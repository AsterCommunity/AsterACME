//! Private issuance generations, fixed key/CSR, and atomic `in_use`-generation selection.
use super::{
    StorageError, store_error,
    toml_file::{self, FileLease, atomic_write, ensure_real_dir, private_dir, read_private},
};
use aster_acme::{
    account::AccountRecord,
    crypto::{AccountSigner, key::AccountKey},
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

mod publication;
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
        let path = toml_file::object_lock(
            &self.root,
            toml_file::ObjectKind::Certificate,
            name.as_str(),
        )?;
        let timeout = self.timeout;
        let slot = self.slot(name);
        let lease = tokio::task::spawn_blocking(move || {
            let lease = toml_file::lock(&path, timeout)?;
            if slot.join("cert.toml").is_file() {
                removal::ensure_idle(&slot).map_err(std::io::Error::other)?;
                let config = selection(&slot).map_err(std::io::Error::other)?;
                let expected = match config.cert.in_use.as_ref() {
                    Some(id) => read_generations(&slot, &config.cert.name)
                        .map_err(std::io::Error::other)?
                        .into_iter()
                        .find(|record| &record.operation_id == id)
                        .map(|record| record.generation_name())
                        .ok_or_else(|| {
                            std::io::Error::other("selected certificate generation missing")
                        })
                        .map(Some)?,
                    None => None,
                };
                publication::NATIVE
                    .recover(&slot, expected.as_deref())
                    .map_err(std::io::Error::other)?;
            }
            Ok::<_, std::io::Error>(lease)
        })
        .await
        .map_err(|_| failure("certificate lock worker failed"))?
        .map_err(|_| failure("certificate lock, view recovery or timeout failed"))?;
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
    key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm,
    account_name: String,
    account_id: String,
    directory: aster_acme_protocol::url::AcmeUrl,
    solver_id: String,
    in_use: Option<String>,
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
            || record.renewal_of != self.initial.renewal_of
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
            .in_use
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
    .map_err(|_| failure("cannot persist in_use certificate selection"))
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

/// A renewal check can legitimately finish without a new generation.
pub enum RenewalPreparation {
    /// Existing `in_use` is not due; no request/key artifacts were created.
    NotDue(Box<IssueRecord>),
    /// New or recovered generation with its exclusive lease.
    Ready(Box<dyn IssueSession>),
}

impl CliIssueStore {
    async fn initialize(
        &self,
        input: Initialization,
        account: &AccountRecord,
    ) -> Result<RenewalPreparation, IssueError> {
        match &input {
            Initialization::New(request) => validate_request(request, account)?,
            Initialization::Renewal(_) | Initialization::Scheduled { .. }
                if !account.is_usable() =>
            {
                return Err(failure("renewal requires an active account"));
            }
            Initialization::Renewal(_) | Initialization::Scheduled { .. } => {}
        }
        let name = match &input {
            Initialization::New(request) => &request.name,
            Initialization::Renewal(name) | Initialization::Scheduled { name, .. } => name,
        };
        let lease = self.lease(name).await?;
        let slot = self.slot(name);
        let account = account.clone();
        tokio::task::spawn_blocking(move || {
            if let Initialization::Scheduled {
                expected_in_use,
                immediate,
                ..
            } = &input
                && let Some(in_use) = check_renewal_schedule(&slot, expected_in_use, *immediate)?
            {
                return Ok(RenewalPreparation::NotDue(Box::new(in_use)));
            }
            let renewal_of = prepare_initialization(&slot, &input)?;
            let request = initialize_definition(&slot, input, &account)?;
            if let Some(record) = existing_renewal(&slot, &request.name, renewal_of.as_ref())? {
                let generation = slot.join(record.generation_name());
                check_material(&generation, &record)?;
                return Ok(RenewalPreparation::Ready(Box::new(Session {
                    slot,
                    generation,
                    lease,
                    initial: record,
                    io: Arc::new(tokio::sync::Mutex::new(())),
                })));
            }
            if read_generations(&slot, &request.name)?.len() >= 1024 {
                return Err(failure("certificate generation limit reached"));
            }
            let operation_id =
                AccountKey::generate(aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256)?
                    .jwk()?
                    .thumbprint()?;
            let material = certificate::generate(&request.identifiers, request.key_algorithm)?;
            let record = IssueRecord {
                is_in_use: false,
                renewal_of,
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
                submitted_replaces: None,
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
            write_material(&generation, &material)?;
            write_journal(&generation.join("operation.toml"), &record)?;
            Ok(RenewalPreparation::Ready(Box::new(Session {
                slot,
                generation,
                lease,
                initial: record,
                io: Arc::new(tokio::sync::Mutex::new(())),
            })))
        })
        .await
        .map_err(|_| failure("issuance initialization worker failed"))?
    }
}

impl CliIssueStore {
    /// Prepare or resume a renewal under its certificate lease, applying the `in_use`
    /// version and due-time checks before creating keys or any remote side effects.
    ///
    /// # Errors
    /// Returns `RenewalPreparation::NotDue` without artifact writes; rejects stale `in_use` or uncertain revocation.
    pub async fn prepare_renewal(
        &self,
        name: &CertificateName,
        expected_in_use: &str,
        immediate: bool,
        account: &AccountRecord,
    ) -> Result<RenewalPreparation, IssueError> {
        self.initialize(
            Initialization::Scheduled {
                name: name.clone(),
                expected_in_use: expected_in_use.into(),
                immediate,
            },
            account,
        )
        .await
    }
}

fn check_renewal_schedule(
    slot: &Path,
    expected_in_use: &str,
    immediate: bool,
) -> Result<Option<IssueRecord>, IssueError> {
    use aster_acme_core::renewal::{RenewalDecision, renewal_decision};
    removal::ensure_idle(slot)?;
    let config = selection(slot)?;
    if config.cert.in_use.as_deref() != Some(expected_in_use) {
        return Err(failure(
            "in_use changed while selecting renewal; inspect cert show before retrying",
        ));
    }
    let records = read_generations(slot, &config.cert.name)?;
    let mut in_use = records
        .iter()
        .find(|record| record.operation_id == expected_in_use)
        .cloned()
        .ok_or_else(|| failure("in_use certificate is missing"))?;
    if in_use.unfinished() || !publication::NATIVE.matches(slot, &in_use)? {
        return Err(failure(
            "in_use certificate selection is inconsistent; refusing renewal",
        ));
    }
    in_use.is_in_use = true;
    let pending = records.iter().any(|record| {
        record.unfinished()
            && record
                .renewal_of
                .as_ref()
                .is_some_and(|previous| previous.operation_id == expected_in_use)
    });
    let due = in_use
        .renewal
        .as_ref()
        .map(|plan| plan.renew_at)
        .ok_or_else(|| failure("in_use certificate has no renewal plan"))?;
    match renewal_decision(
        pending,
        in_use.revocation.state,
        due.unix_timestamp(),
        time::OffsetDateTime::now_utc().unix_timestamp(),
        immediate,
    ) {
        RenewalDecision::NotDue => Ok(Some(in_use)),
        RenewalDecision::Start | RenewalDecision::Resume => Ok(None),
        RenewalDecision::RevocationUncertain => Err(failure(
            "certificate revocation is unconfirmed; resolve it before renewing",
        )),
    }
}

// Validate the live selection under the object lease before key generation.
fn prepare_initialization(
    slot: &Path,
    input: &Initialization,
) -> Result<Option<aster_acme::issuance::RenewalPredecessor>, IssueError> {
    match input {
        Initialization::New(_) => {
            fs::create_dir_all(slot).map_err(|_| failure("cannot create certificate directory"))?;
        }
        Initialization::Renewal(_) | Initialization::Scheduled { .. } => {}
    }
    ensure_real_dir(slot)?;
    private_dir(slot)?;
    removal::ensure_idle(slot)?;
    let renewal_of = match input {
        Initialization::New(_) => None,
        Initialization::Renewal(_) | Initialization::Scheduled { .. } => predecessor(slot)?,
    };
    Ok(renewal_of)
}

// Persist the immutable key/CSR pair and digest together while the caller holds
// the certificate lease; a partially written set remains non-resumable.
fn write_material(
    generation: &Path,
    material: &certificate::CertificateMaterial,
) -> Result<(), IssueError> {
    atomic_write(&generation.join("private-key.pk8"), &material.key)
        .map_err(|_| failure("cannot persist certificate key"))?;
    atomic_write(&generation.join("request.der"), &material.csr)
        .map_err(|_| failure("cannot persist fixed CSR"))?;
    atomic_write(
        &generation.join("material.sha256"),
        material_digest(&material.key, &material.csr).as_bytes(),
    )
    .map_err(|_| failure("cannot persist key/CSR manifest"))?;
    Ok(())
}

fn existing_renewal(
    slot: &Path,
    name: &CertificateName,
    previous: Option<&aster_acme::issuance::RenewalPredecessor>,
) -> Result<Option<IssueRecord>, IssueError> {
    let Some(previous) = previous else {
        return Ok(None);
    };
    let pending = read_generations(slot, name)?
        .into_iter()
        .filter(|record| record.unfinished() && record.renewal_of.as_ref() == Some(previous))
        .collect::<Vec<_>>();
    match pending.as_slice() {
        [] => Ok(None),
        [record] => Ok(Some(record.clone())),
        _ => Err(failure(
            "several unfinished renewals match in_use; select an exact operation",
        )),
    }
}

fn predecessor(
    slot: &Path,
) -> Result<Option<aster_acme::issuance::RenewalPredecessor>, IssueError> {
    let config = selection(slot)?;
    let Some(in_use) = config.cert.in_use else {
        return Ok(None);
    };
    let record = read_generations(slot, &config.cert.name)?
        .into_iter()
        .find(|record| record.operation_id == in_use)
        .ok_or_else(|| failure("in_use generation is missing"))?;
    let chain = read_private(
        &slot.join(record.generation_name()).join("fullchain.pem"),
        1024 * 1024,
    )
    .map_err(|_| failure("in_use certificate is missing or unsafe"))?;
    let plan = aster_acme::renewal::RenewalPlan::from_certificate(&chain)?;
    Ok(Some(aster_acme::issuance::RenewalPredecessor {
        operation_id: in_use,
        certificate_id: plan.certificate_id,
    }))
}

enum Initialization {
    New(IssueRequest),
    Renewal(CertificateName),
    Scheduled {
        name: CertificateName,
        expected_in_use: String,
        immediate: bool,
    },
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
                        in_use: None,
                    },
                },
            )?;
            Ok(request)
        }
        Initialization::Renewal(name) | Initialization::Scheduled { name, .. } => {
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
        match self
            .initialize(Initialization::New(request.clone()), account)
            .await?
        {
            RenewalPreparation::Ready(session) => Ok(session),
            RenewalPreparation::NotDue(_) => {
                Err(failure("new issuance unexpectedly returned renewal timing"))
            }
        }
    }

    async fn renew(
        &self,
        name: &CertificateName,
        account: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        match self
            .initialize(Initialization::Renewal(name.clone()), account)
            .await?
        {
            RenewalPreparation::Ready(session) => Ok(session),
            RenewalPreparation::NotDue(_) => Err(failure(
                "unconditional renewal unexpectedly returned timing",
            )),
        }
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
                            record.is_in_use =
                                config.cert.in_use.as_deref() == Some(record.operation_id.as_str());
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
            record.is_in_use =
                selection(&slot)?.cert.in_use.as_deref() == Some(record.operation_id.as_str());
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
            let config = selection(&slot)?;
            if let Some(previous) = &record.renewal_of
                && config.cert.in_use.as_deref() != Some(previous.operation_id.as_str())
                && config.cert.in_use.as_deref() != Some(record.operation_id.as_str())
            {
                return Err(failure(
                    "renewal predecessor is no longer in_use; refusing stale promotion",
                ));
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
            publication::NATIVE.publish(&slot, &record)?;
            let mut config = selection(&slot)?;
            config.cert.in_use = Some(record.operation_id.clone());
            write_selection(&slot, &config)?;
            publication::NATIVE.recover(&slot, Some(&record.generation_name()))?;
            record.phase = IssuancePhase::Completed;
            record.is_in_use = true;
            write_journal(&generation.join("operation.toml"), &record)?;
            Ok(record)
        })
        .await
        .map_err(|_| failure("certificate completion worker failed"))?
    }
}

#[cfg(test)]
mod tests;
