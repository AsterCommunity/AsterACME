//! Private issuance generations, fixed key/CSR, and atomic `in_use`-generation selection.
use crate::{
    account::store_error,
    toml_file::{self, FileLease, atomic_write, ensure_real_dir, private_dir, read_private},
};
use aster_acme::storage::issuance::{IssueSession, IssueStore};
use aster_acme::storage::query::IssueQuery;
use aster_acme::{
    account::AccountRecord,
    issuance::{CertificateName, IssueError, IssueRecord, IssueRequest, certificate},
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

mod deployment;
mod generation;
mod publication;
mod query;
mod retry;
pub mod revocation;
mod session;
use crate::issuance::generation::Initialization;
pub use deployment::{
    DeploymentArtifacts, DeploymentBinding, DeploymentDefinition, DeploymentPatch,
    DeploymentPermissions, DeploymentSession, DeploymentTarget,
    validate_id as validate_deployment_id,
};
pub mod removal;

const MAX_JOURNAL: u64 = 1024 * 1024;
const JOURNAL_VERSION: u32 = 1;

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
            let lease = toml_file::lock(&path, timeout).map_err(|error| {
                if error.kind() == std::io::ErrorKind::TimedOut {
                    IssueError::LeaseUnavailable("certificate", error.to_string())
                } else {
                    failure(&format!("certificate lock failed: {error}"))
                }
            })?;
            if slot.join("cert.toml").is_file() {
                removal::ensure_idle(&slot)?;
                publication::recover_selection(&slot)?;
            }
            Ok::<_, IssueError>(lease)
        })
        .await
        .map_err(|_| failure("certificate lock worker failed"))??;
        Ok(Arc::new(lease))
    }
}

#[derive(Serialize, Deserialize)]
struct Journal<T = IssueRecord> {
    version: u32,
    operation: T,
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
    challenge: aster_acme::challenge::ChallengeKind,
    solver_config: serde_json::Value,
    solver_id: String,
    in_use: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deployments: Vec<deployment::DeploymentBinding>,
}

impl CertificateSelection {
    fn matches_record(&self, record: &IssueRecord) -> bool {
        self.name == record.name
            && self.identifiers == record.identifiers
            && self.key_algorithm == record.key_algorithm
            && self.account_name == record.account_name
            && self.account_id == record.account_id
            && self.directory == record.directory
            && self.challenge == record.challenge
            && self.solver_id == record.solver_id
            && self.solver_config == record.solver_config
    }
}

#[derive(Clone)]
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
            || record.challenge != self.initial.challenge
            || record.solver_config != self.initial.solver_config
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

fn new_operation_id() -> Result<String, IssueError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut random = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut random).map_err(|_| aster_acme::crypto::CryptoError::Randomness)?;
    Ok(URL_SAFE_NO_PAD.encode(random))
}

/// IDs are opaque 32-byte base64url random values generated locally, never CA paths.
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
    if stored.version != JOURNAL_VERSION
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
        version: JOURNAL_VERSION,
        operation: record,
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
    let mut seen = std::collections::HashSet::new();
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
        if !seen.insert(record.operation_id.clone()) {
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
        Ok(Box::new(
            self.open_session(name, operation_id, OpenMode::Execution)
                .await?,
        ))
    }

    async fn open_observation(
        &self,
        name: &CertificateName,
        operation_id: &str,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        Ok(Box::new(
            self.open_session(name, operation_id, OpenMode::Observation)
                .await?,
        ))
    }

    async fn query(&self, query: IssueQuery) -> Result<Vec<IssueRecord>, IssueError> {
        let root = self.root.join("certs");
        tokio::task::spawn_blocking(move || query::read(&root, &query))
            .await
            .map_err(|_| failure("issuance query worker failed"))?
    }
}

#[derive(Clone, Copy)]
enum OpenMode {
    Execution,
    Observation,
}
impl CliIssueStore {
    async fn open_session(
        &self,
        name: &CertificateName,
        operation_id: &str,
        mode: OpenMode,
    ) -> Result<Session, IssueError> {
        if !valid_operation_id(operation_id) {
            return Err(failure("invalid operation ID"));
        }
        let lease = self.lease(name).await?;
        let slot = self.slot(name);
        let name = name.clone();
        let operation_id = operation_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let record = query::read(
                slot.parent()
                    .ok_or_else(|| failure("missing catalog parent"))?,
                &IssueQuery {
                    name: Some(name.clone()),
                    operation_id: Some(operation_id.clone()),
                    ..IssueQuery::default()
                },
            )?
            .into_iter()
            .next()
            .ok_or_else(|| failure("saved certificate request not found"))?;
            let generation = slot.join(record.generation_name());
            ensure_real_dir(&generation)?;
            if record.name != name
                || record.operation_id != operation_id
                || !selection(&slot)?.cert.matches_record(&record)
            {
                return Err(failure("issuance path and identity mismatch"));
            }
            if matches!(mode, OpenMode::Execution) {
                check_material(&generation, &record)?;
            }
            if matches!(mode, OpenMode::Execution)
                && matches!(record.phase, IssuancePhase::Completed)
            {
                let chain = read_private(&generation.join("fullchain.pem"), 1024 * 1024)
                    .map_err(|_| failure("completed certificate artifact is missing or unsafe"))?;
                let key = zeroize::Zeroizing::new(
                    read_private(&generation.join("private-key.pk8"), 64 * 1024)
                        .map_err(|_| failure("completed certificate key is missing or unsafe"))?,
                );
                certificate::validate(&chain, &key, &record.identifiers)?;
            }
            Ok(Session {
                slot,
                generation,
                lease,
                initial: record,
                io: Arc::new(tokio::sync::Mutex::new(())),
            })
        })
        .await
        .map_err(|_| failure("issuance open worker failed"))?
    }
}

#[cfg(test)]
mod tests;

/// Inspect immutable certificate definitions while the provider registry is exclusively locked.
///
/// # Errors
/// Returns an error when the inventory is unsafe, unreadable or malformed.
pub fn provider_referenced(root: &Path, provider: &str) -> std::io::Result<bool> {
    let directory = root.join("certs");
    if !directory.exists() {
        return Ok(false);
    }
    crate::state_file::ensure_directory(&directory)?;
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if CertificateName::new(name).is_err() {
            continue;
        }
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let slot = entry.path();
        let path = slot.join("cert.toml");
        if !path.try_exists()? {
            continue;
        }
        let config = selection(&slot)
            .map_err(|_| std::io::Error::other("cannot verify certificate provider references"))?;
        if config.cert.solver_id == "dns_external"
            && config
                .cert
                .solver_config
                .get("provider_instance_id")
                .and_then(serde_json::Value::as_str)
                == Some(provider)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
