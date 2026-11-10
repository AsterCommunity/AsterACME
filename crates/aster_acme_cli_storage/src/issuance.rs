//! Private issuance generations, fixed key/CSR, and atomic current-generation selection.
use super::{
    StorageError, store_error,
    toml_file::{self, FileLease, atomic_write, ensure_real_dir, private_dir, read_private},
};
use aster_acme::{
    account::AccountRecord,
    crypto::{AccountKey, AccountSigner},
    issuance::{
        CertificateName, IssueError, IssueRecord, IssueRequest, IssueSession, IssueStore,
        certificate,
    },
};
use aster_acme_core::workflow::{IssuancePhase, SubmissionState};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub mod removal;

const MAX_JOURNAL: u64 = 1024 * 1024;

/// Local certificate catalog. Names and operation IDs are validated before joining paths.
#[derive(Clone)]
pub struct CliIssueStore {
    root: PathBuf,
    timeout: Duration,
}
impl CliIssueStore {
    /// Open a catalog without writing files; execution creates private directories under lease.
    #[must_use]
    pub fn new(root: PathBuf, timeout: Duration) -> Self {
        Self { root, timeout }
    }

    fn slot(&self, name: &CertificateName) -> PathBuf {
        self.root.join("certs").join(name.as_str())
    }

    async fn lease(&self, name: &CertificateName) -> Result<Arc<FileLease>, IssueError> {
        let path = self.slot(name).join("cert.lock");
        let timeout = self.timeout;
        let lease = tokio::task::spawn_blocking(move || toml_file::lock(&path, timeout))
            .await
            .map_err(|_| failure("certificate lock worker failed"))?
            .map_err(|_| failure("certificate lock failed or timed out"))?;
        Ok(Arc::new(lease))
    }
}

#[derive(Serialize, Deserialize)]
struct Journal {
    version: u32,
    operation: IssueRecord,
}

#[derive(Serialize, Deserialize)]
struct CertificateConfig {
    version: u32,
    cert: CertificateSelection,
}
#[derive(Serialize, Deserialize)]
struct CertificateSelection {
    name: CertificateName,
    identifiers: Vec<aster_acme::identifier::DnsIdentifier>,
    key_algorithm: aster_acme::issuance::key_algorithm::CertificateKeyAlgorithm,
    account_name: String,
    account_id: String,
    directory: aster_acme_protocol::url::AcmeUrl,
    solver_id: String,
    current: Option<String>,
}

struct Session {
    slot: PathBuf,
    generation: PathBuf,
    lease: Arc<FileLease>,
    initial: IssueRecord,
    io: Arc<tokio::sync::Mutex<()>>,
}

impl Session {
    fn verify_identity(&self, record: &IssueRecord) -> Result<(), IssueError> {
        if record.operation_id != self.initial.operation_id
            || record.name != self.initial.name
            || record.account_name != self.initial.account_name
            || record.account_id != self.initial.account_id
            || record.created_at != self.initial.created_at
            || record.directory != self.initial.directory
            || record.account_url != self.initial.account_url
            || record.account_thumbprint != self.initial.account_thumbprint
            || record.solver_id != self.initial.solver_id
            || record.identifiers != self.initial.identifiers
            || record.key_algorithm != self.initial.key_algorithm
        {
            return Err(failure("immutable issuance identity changed"));
        }
        Ok(())
    }
}

fn failure(message: &str) -> IssueError {
    IssueError::Store(store_error(message))
}

/// IDs are opaque base64url thumbprints generated locally, never paths from the CA.
#[must_use]
pub fn valid_operation_id(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

// Only our marker names establish ownership; sibling files/directories are unrelated.
// symlink_metadata observes a broken managed symlink too, so readers reject it explicitly.
fn managed_file_present(path: &Path) -> Result<bool, IssueError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(failure("cannot inspect managed issuance file")),
    }
}

fn read_journal(path: &Path) -> Result<IssueRecord, IssueError> {
    let bytes = read_private(path, MAX_JOURNAL)
        .map_err(|_| failure("issuance journal missing, oversized or unsafe"))?;
    let stored: Journal = toml::from_str(
        std::str::from_utf8(&bytes).map_err(|_| failure("invalid journal encoding"))?,
    )
    .map_err(|_| failure("issuance journal is corrupt"))?;
    if stored.version != 1
        || !valid_operation_id(&stored.operation.operation_id)
        || stored.operation.identifiers.is_empty()
        || stored.operation.identifiers.len() > 100
        || stored.operation.authorizations.len() > 100
    {
        return Err(failure("unsupported or invalid issuance journal"));
    }
    Ok(stored.operation)
}

fn write_journal(path: &Path, record: &IssueRecord) -> Result<(), IssueError> {
    let text = toml::to_string_pretty(&Journal {
        version: 1,
        operation: record.clone(),
    })
    .map_err(|_| failure("cannot encode issuance journal"))?;
    toml_file::write_text(
        path,
        &format!("# Managed by aster-acme. DO NOT EDIT this file.\n{text}"),
        1024 * 1024,
    )
    .map_err(|_| failure("cannot persist issuance journal"))
}

fn selection(slot: &Path) -> Result<CertificateConfig, IssueError> {
    let bytes = read_private(&slot.join("cert.toml"), 64 * 1024)
        .map_err(|_| failure("certificate configuration missing or unsafe"))?;
    let config: CertificateConfig = toml::from_str(
        std::str::from_utf8(&bytes).map_err(|_| failure("invalid certificate configuration"))?,
    )
    .map_err(|_| failure("corrupt certificate configuration"))?;
    if config.version != 1
        || config
            .cert
            .current
            .as_deref()
            .is_some_and(|id| !valid_operation_id(id))
    {
        return Err(failure("unsupported certificate configuration"));
    }
    Ok(config)
}

fn write_selection(slot: &Path, config: &CertificateConfig) -> Result<(), IssueError> {
    let text = toml::to_string_pretty(config)
        .map_err(|_| failure("cannot encode certificate selection"))?;
    toml_file::write_text(
        &slot.join("cert.toml"),
        &format!("# Managed by aster-acme. DO NOT EDIT this file.\n{text}"),
        64 * 1024,
    )
    .map_err(|_| failure("cannot persist current certificate selection"))
}

fn check_material(generation: &Path, record: &IssueRecord) -> Result<(), IssueError> {
    let key = zeroize::Zeroizing::new(
        read_private(&generation.join("private-key.pk8"), 64 * 1024)
            .map_err(|_| failure("certificate key missing or unsafe"))?,
    );
    record.key_algorithm.validate_key(&key)?;
    let csr = read_private(&generation.join("request.der"), 64 * 1024)
        .map_err(|_| failure("fixed CSR missing or unsafe"))?;
    // Hash manifest binds the exact immutable key and CSR bytes across restart.
    let manifest = read_private(&generation.join("material.sha256"), 256)
        .map_err(|_| failure("certificate material manifest missing"))?;
    if manifest != material_digest(&key, &csr).as_bytes() || record.identifiers.is_empty() {
        return Err(failure(
            "certificate key or CSR changed; refusing replacement",
        ));
    }
    Ok(())
}

fn material_digest(key: &[u8], csr: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest as _, Sha256};
    let mut digest = Sha256::new();
    digest.update(key);
    digest.update(csr);
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn read_generations(slot: &Path, name: &CertificateName) -> Result<Vec<IssueRecord>, IssueError> {
    ensure_real_dir(slot)?;
    let mut records = Vec::new();
    for (index, entry) in fs::read_dir(slot)
        .map_err(|_| failure("cannot enumerate certificate requests"))?
        .enumerate()
    {
        if index >= 4096 {
            return Err(failure("certificate directory exceeds scan limit"));
        }
        let entry = entry.map_err(|_| failure("invalid certificate generation entry"))?;
        if !entry
            .file_type()
            .map_err(|_| failure("cannot inspect generation type"))?
            .is_dir()
        {
            continue;
        }
        let journal = entry.path().join("operation.toml");
        if !managed_file_present(&journal)? {
            continue;
        }
        let record = read_journal(&journal)?;
        if record.name != *name
            || entry.file_name().to_str() != Some(record.generation_name().as_str())
        {
            return Err(failure("managed certificate generation identity mismatch"));
        }
        if records
            .iter()
            .any(|saved: &IssueRecord| saved.operation_id == record.operation_id)
        {
            return Err(failure("duplicate managed operation ID"));
        }
        records.push(record);
    }
    Ok(records)
}

#[cfg(unix)]
fn promote_current(slot: &Path, record: &IssueRecord) -> Result<(), IssueError> {
    use std::os::unix::fs::symlink;
    let current = slot.join("current");
    match fs::symlink_metadata(&current) {
        Ok(metadata) if !metadata.file_type().is_symlink() => {
            return Err(failure("current is not a managed certificate symlink"));
        }
        Ok(_) => {
            let target = fs::read_link(&current)
                .map_err(|_| failure("cannot inspect current certificate link"))?;
            if target.components().count() != 1 || target.is_absolute() {
                return Err(failure(
                    "current certificate link points outside its managed directory",
                ));
            }
            let previous = read_journal(&slot.join(&target).join("operation.toml"))?;
            if target != Path::new(&previous.generation_name()) || previous.name != record.name {
                return Err(failure("current certificate link identity mismatch"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(failure("cannot inspect current certificate link")),
    }
    let temporary = slot.join(format!(".current-{}", record.operation_id));
    // A crash may leave our exact pending link. Resume it without touching unrelated
    // colliding files or links, which the user may own.
    match fs::symlink_metadata(&temporary) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                && fs::read_link(&temporary).ok().as_deref()
                    == Some(Path::new(&record.generation_name())) =>
        {
            fs::remove_file(&temporary)
                .map_err(|_| failure("cannot reconcile pending current link"))?;
        }
        Ok(_) => {
            return Err(failure(
                "current link temporary path belongs to an unrelated entry",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(failure("cannot inspect pending current link")),
    }
    symlink(record.generation_name(), &temporary)
        .map_err(|_| failure("cannot create atomic current link"))?;
    if fs::rename(&temporary, &current).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(failure("cannot promote current certificate link"));
    }
    fs::File::open(slot)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| failure("cannot sync current certificate link"))
}

#[cfg(not(unix))]
fn promote_current(_slot: &Path, _record: &IssueRecord) -> Result<(), IssueError> {
    Err(failure("current certificate links require Unix"))
}

impl CliIssueStore {
    async fn initialize(
        &self,
        input: Initialization,
        account: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        match &input {
            Initialization::New(request) => validate_request(request, account)?,
            Initialization::Renewal(_) if !account.is_usable() => {
                return Err(failure("renewal requires an active account"));
            }
            Initialization::Renewal(_) => {}
        }
        let name = match &input {
            Initialization::New(request) => &request.name,
            Initialization::Renewal(name) => name,
        };
        let lease = self.lease(name).await?;
        let slot = self.slot(name);
        let account = account.clone();
        tokio::task::spawn_blocking(move || {
            removal::ensure_idle(&slot)?;
            let request = initialize_definition(&slot, input, &account)?;
            if read_generations(&slot, &request.name)?.len() >= 1024 {
                return Err(failure("certificate generation limit reached"));
            }
            let operation_id = AccountKey::generate()?.jwk()?.thumbprint()?;
            let material = certificate::generate(&request.identifiers, request.key_algorithm)?;
            let record = IssueRecord {
                is_current: false,
                solver_id: "manual_dns".into(),
                operation_id,
                name: request.name,
                created_at: time::OffsetDateTime::now_utc(),
                account_name: request.account_name,
                account_id: account.account_id,
                directory: account.directory_url,
                account_url: account
                    .account_url
                    .ok_or_else(|| failure("missing account URL"))?,
                account_thumbprint: account.key_thumbprint,
                key_algorithm: request.key_algorithm,
                identifiers: request.identifiers,
                phase: IssuancePhase::CreatingOrder,
                creation_submitted: false,
                order_url: None,
                order: None,
                authorizations: Vec::new(),
                finalize_submitted: SubmissionState::NotSubmitted,
                finalize_rejection: None,
                next_poll_at: None,
                certificate_not_after: None,
                renewal: None,
                revocation: aster_acme::revocation::RevocationRecord::default(),
            };
            let generation = slot.join(record.generation_name());
            fs::create_dir(&generation)
                .map_err(|_| failure("cannot create unique issuance generation"))?;
            private_dir(&generation)?;
            // Make the generation visible before writing private material. An interrupted
            // initialization is listed and fails closed on resume, never generates a new key.
            write_journal(&generation.join("operation.toml"), &record)?;
            atomic_write(&generation.join("private-key.pk8"), &material.key)
                .map_err(|_| failure("cannot persist certificate key"))?;
            atomic_write(&generation.join("request.der"), &material.csr)
                .map_err(|_| failure("cannot persist fixed CSR"))?;
            atomic_write(
                &generation.join("material.sha256"),
                material_digest(&material.key, &material.csr).as_bytes(),
            )
            .map_err(|_| failure("cannot persist key/CSR manifest"))?;
            write_journal(&generation.join("operation.toml"), &record)?;
            Ok(Box::new(Session {
                slot,
                generation,
                lease,
                initial: record,
                io: Arc::new(tokio::sync::Mutex::new(())),
            }) as Box<dyn IssueSession>)
        })
        .await
        .map_err(|_| failure("issuance initialization worker failed"))?
    }
}

enum Initialization {
    New(IssueRequest),
    Renewal(CertificateName),
}

fn validate_request(request: &IssueRequest, account: &AccountRecord) -> Result<(), IssueError> {
    if request.identifiers.is_empty()
        || request.identifiers.len() > 100
        || request
            .identifiers
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != request.identifiers.len()
        || !account.is_usable()
    {
        return Err(failure(
            "issuance requires unique domains and an active account",
        ));
    }
    Ok(())
}

// The certificate lease covers definition lookup, name claiming and generation writes.
fn initialize_definition(
    slot: &Path,
    input: Initialization,
    account: &AccountRecord,
) -> Result<IssueRequest, IssueError> {
    match input {
        Initialization::New(request) => {
            match read_private(&slot.join("cert.toml"), 64 * 1024) {
                Ok(_) => {
                    selection(slot)?;
                    return Err(IssueError::NameAlreadyExists(request.name));
                }
                Err(StorageError::NotFound) => {}
                Err(_) => return Err(failure("unsafe certificate configuration")),
            }
            if !read_generations(slot, &request.name)?.is_empty() {
                return Err(IssueError::NameAlreadyExists(request.name));
            }
            write_selection(
                slot,
                &CertificateConfig {
                    version: 1,
                    cert: CertificateSelection {
                        name: request.name.clone(),
                        identifiers: request.identifiers.clone(),
                        key_algorithm: request.key_algorithm,
                        account_name: request.account_name.clone(),
                        account_id: account.account_id.clone(),
                        directory: account.directory_url.clone(),
                        solver_id: "manual_dns".into(),
                        current: None,
                    },
                },
            )?;
            Ok(request)
        }
        Initialization::Renewal(name) => {
            let config = selection(slot)?;
            if config.cert.name != name
                || config.cert.account_id != account.account_id
                || config.cert.directory != account.directory_url
                || config.cert.solver_id != "manual_dns"
            {
                return Err(failure(
                    "renewal definition does not match the selected account",
                ));
            }
            if read_generations(slot, &name)?.iter().any(|record| {
                record.identifiers != config.cert.identifiers
                    || record.key_algorithm != config.cert.key_algorithm
                    || record.account_id != config.cert.account_id
                    || record.directory != config.cert.directory
                    || record.account_name != config.cert.account_name
                    || record.solver_id != config.cert.solver_id
            }) {
                return Err(failure(
                    "saved generations do not match the managed certificate definition",
                ));
            }
            let request = IssueRequest {
                name,
                identifiers: config.cert.identifiers,
                key_algorithm: config.cert.key_algorithm,
                account_name: config.cert.account_name,
            };
            validate_request(&request, account)?;
            Ok(request)
        }
    }
}

#[async_trait]
impl IssueStore for CliIssueStore {
    async fn create(
        &self,
        request: &IssueRequest,
        account: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        self.initialize(Initialization::New(request.clone()), account)
            .await
    }

    async fn renew(
        &self,
        name: &CertificateName,
        account: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        self.initialize(Initialization::Renewal(name.clone()), account)
            .await
    }

    async fn open(
        &self,
        name: &CertificateName,
        operation_id: &str,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        if !valid_operation_id(operation_id) {
            return Err(failure("invalid operation ID"));
        }
        let lease = self.lease(name).await?;
        let slot = self.slot(name);
        let name = name.clone();
        let operation_id = operation_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let record = read_generations(&slot, &name)?
                .into_iter()
                .find(|record| record.operation_id == operation_id)
                .ok_or_else(|| failure("saved certificate request not found"))?;
            let generation = slot.join(record.generation_name());
            ensure_real_dir(&generation)?;
            if record.name != name
                || record.operation_id != operation_id
                || selection(&slot)?.cert.name != name
            {
                return Err(failure("issuance path and identity mismatch"));
            }
            check_material(&generation, &record)?;
            if matches!(record.phase, IssuancePhase::Completed) {
                let chain = read_private(&generation.join("fullchain.pem"), 1024 * 1024)
                    .map_err(|_| failure("completed certificate artifact is missing or unsafe"))?;
                let key = zeroize::Zeroizing::new(
                    read_private(&generation.join("private-key.pk8"), 64 * 1024)
                        .map_err(|_| failure("completed certificate key is missing or unsafe"))?,
                );
                certificate::validate(&chain, &key, &record.identifiers)?;
            }
            Ok(Box::new(Session {
                slot,
                generation,
                lease,
                initial: record,
                io: Arc::new(tokio::sync::Mutex::new(())),
            }) as Box<dyn IssueSession>)
        })
        .await
        .map_err(|_| failure("issuance open worker failed"))?
    }

    async fn list(&self) -> Result<Vec<IssueRecord>, IssueError> {
        let root = self.root.join("certs");
        tokio::task::spawn_blocking(move || {
            if !root
                .try_exists()
                .map_err(|_| failure("cannot inspect certificate catalog"))?
            {
                return Ok(Vec::new());
            }
            ensure_real_dir(&root)?;
            let mut records = Vec::new();
            for (index, entry) in fs::read_dir(&root)
                .map_err(|_| failure("cannot enumerate certificates"))?
                .enumerate()
            {
                if index >= 1024 {
                    return Err(failure("certificate catalog exceeds 1024 names"));
                }
                let entry = entry.map_err(|_| failure("invalid certificate entry"))?;
                let kind = entry
                    .file_type()
                    .map_err(|_| failure("cannot inspect certificate entry type"))?;
                if !kind.is_dir() {
                    continue;
                }
                let slot = entry.path();
                if !managed_file_present(&slot.join("cert.toml"))? {
                    continue;
                }
                let name = CertificateName::new(&entry.file_name().to_string_lossy())?;
                let config = selection(&slot)?;
                if config.cert.name != name {
                    return Err(failure("certificate catalog name mismatch"));
                }
                ensure_real_dir(&slot)?;
                records.extend(
                    read_generations(&slot, &name)?
                        .into_iter()
                        .map(|mut record| {
                            record.is_current = config.cert.current.as_deref()
                                == Some(record.operation_id.as_str());
                            record
                        }),
                );
                if records.len() > 4096 {
                    return Err(failure("issuance listing exceeds 4096 records"));
                }
            }

            records.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then(a.operation_id.cmp(&b.operation_id))
            });
            Ok(records)
        })
        .await
        .map_err(|_| failure("issuance listing worker failed"))?
    }
}

#[async_trait]
impl IssueSession for Session {
    async fn record(&self) -> Result<IssueRecord, IssueError> {
        let permit = self.io.clone().lock_owned().await;
        let generation = self.generation.clone();
        let slot = self.slot.clone();
        let lease = self.lease.clone();
        let record = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lease = lease;
            let mut record = read_journal(&generation.join("operation.toml"))?;
            record.is_current =
                selection(&slot)?.cert.current.as_deref() == Some(record.operation_id.as_str());
            Ok::<_, IssueError>(record)
        })
        .await
        .map_err(|_| failure("issuance snapshot worker failed"))??;
        self.verify_identity(&record)?;
        Ok(record)
    }

    async fn save(&self, record: &IssueRecord) -> Result<(), IssueError> {
        self.verify_identity(record)?;
        let record = record.clone();
        let generation = self.generation.clone();
        let lease = self.lease.clone();
        let permit = self.io.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lease = lease;
            write_journal(&generation.join("operation.toml"), &record)
        })
        .await
        .map_err(|_| failure("issuance journal worker failed"))?
    }

    async fn csr(&self) -> Result<Vec<u8>, IssueError> {
        let generation = self.generation.clone();
        let record = self.initial.clone();
        let lease = self.lease.clone();
        let permit = self.io.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lease = lease;
            check_material(&generation, &record)?;
            read_private(&generation.join("request.der"), 64 * 1024)
                .map_err(|_| failure("fixed CSR missing or unsafe"))
        })
        .await
        .map_err(|_| failure("CSR worker failed"))?
    }

    async fn certificate_der(&self) -> Result<Vec<u8>, IssueError> {
        let generation = self.generation.clone();
        let lease = self.lease.clone();
        let permit = self.io.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lease = lease;
            let chain = read_private(&generation.join("fullchain.pem"), 1024 * 1024)
                .map_err(|_| failure("issued certificate missing or unsafe"))?;
            certificate::leaf_der(&chain)
        })
        .await
        .map_err(|_| failure("certificate read worker failed"))?
    }

    async fn complete(
        &self,
        record: &IssueRecord,
        chain: &[u8],
    ) -> Result<IssueRecord, IssueError> {
        let mut record = record.clone();
        let chain = chain.to_vec();
        let generation = self.generation.clone();
        let slot = self.slot.clone();
        let lease = self.lease.clone();
        self.verify_identity(&record)?;
        let permit = self.io.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lease = lease;
            check_material(&generation, &record)?;
            let key = zeroize::Zeroizing::new(
                read_private(&generation.join("private-key.pk8"), 64 * 1024)
                    .map_err(|_| failure("missing certificate key"))?,
            );
            record.certificate_not_after =
                Some(certificate::validate(&chain, &key, &record.identifiers)?);
            // Establish a durable fallback before promotion; ARI network failures cannot
            // invalidate a successfully issued certificate or erase its renewal plan.
            if record.renewal.is_none() {
                record.renewal = Some(aster_acme::renewal::RenewalPlan::from_certificate(&chain)?);
            }
            if !matches!(record.phase, IssuancePhase::Completed) {
                return Err(failure("cannot promote incomplete issuance"));
            }
            let artifacts = certificate::artifacts(&chain, &key)?;
            for (name, bytes) in [
                ("fullchain.pem", chain.as_slice()),
                ("cert.pem", artifacts.certificate.as_bytes()),
                ("ca.pem", artifacts.ca_chain.as_bytes()),
                ("private-key.pem", artifacts.private_key.as_bytes()),
            ] {
                atomic_write(&generation.join(name), bytes)
                    .map_err(|_| failure("cannot persist certificate artifact set"))?;
            }
            // Keep the operation resumable until selection is durable. A crash after
            // selection only causes a safe re-download of the same issued artifact.
            record.phase = IssuancePhase::Downloading;
            write_journal(&generation.join("operation.toml"), &record)?;
            promote_current(&slot, &record)?;
            let mut config = selection(&slot)?;
            config.cert.current = Some(record.operation_id.clone());
            write_selection(&slot, &config)?;
            record.phase = IssuancePhase::Completed;
            record.is_current = true;
            write_journal(&generation.join("operation.toml"), &record)?;
            Ok(record)
        })
        .await
        .map_err(|_| failure("certificate completion worker failed"))?
    }
}

#[cfg(test)]
mod tests;
