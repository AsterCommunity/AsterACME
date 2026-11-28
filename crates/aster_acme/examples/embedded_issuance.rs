//! End-to-end embedded issuance: the library services, an in-memory store, and an
//! embedder-owned HTTP-01 solver in one runnable binary.
//!
//! The chain mirrors what an embedding application owns: discover the CA
//! directory, register or reuse an account through `AccountService`, inject a
//! `ChallengeSolver`, create an issuance via `IssueStore`, and
//! read the promoted artifacts. Protocol state and retries stay inside
//! `aster_acme`; this file shows a minimal volatile adapter, not durable recovery.
//!
//! Defaults are deliberately safe for a first run: Let's Encrypt **staging**
//! and a temporary data directory that is removed on exit. `--directory`
//! accepts another ACME CA; plain `http://` loopback URLs are allowed through
//! the transport options for non-TLS test CAs. TLS-only test CAs such as
//! Pebble additionally require trusting their test root in the platform trust
//! store, which this example does not set up. An embedding application must
//! replace the in-memory stores with durable, concurrency-safe adapters for
//! restart recovery.
//!
//! ```sh
//! cargo run -p aster_acme --example embedded_issuance -- \
//!     --domain example.com --webroot /srv/www \
//!     --contact admin@example.com
//! ```
//!
//! The web server serving `--webroot` must expose
//! `<webroot>/.well-known/acme-challenge/` on public port 80. The solver below
//! is a teaching implementation: it writes plain files and only ever removes
//! files it published unchanged. The CLI ships the production webroot solver
//! with hard-link ownership checks; embedders needing those guarantees should
//! adapt it rather than this example.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use aster_acme::{
    account::{AccountRecord, AccountService, AccountTimes, RegistrationOptions},
    challenge::ChallengeKind,
    crypto::{JwsSigner, key::SoftwareSigningKey, key_algorithm::KeyAlgorithm},
    identifier::Identifier,
    issuance::{
        CertificateName, IssueError, IssueExecution, IssueIdentity, IssueOutcome, IssueRecord,
        IssueRequest, RenewalRetryState, ValidationRequirement, certificate,
        progress::{IssueEvent, IssueObserver},
        workflow::{Workflow, WorkflowObserver},
    },
    renewal::RenewalPlan,
    solver::{ChallengePublication, ChallengeSolver, CleanupResult, ExecutionContext, ReadyResult},
    storage::{
        account::{AccountKeyStore, AccountLease, AccountStore, AccountStoreError, KeyAccess},
        issuance::{IssueSession, IssueStore},
        query::IssueQuery,
    },
    transport::{HttpPool, TransportOptions},
};
use aster_acme_core::{
    account::{AccountRecordState, DeactivationState},
    workflow::{IssuancePhase, SubmissionState},
};
use aster_acme_protocol::{directory::Directory, url::AcmeUrl};
use async_trait::async_trait;
use clap::Parser;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const LETSENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
const DEFAULT_CERTIFICATE_NAME: &str = "embedded-example";
const ACCOUNT_NAME: &str = "embedded";
const TOTAL_BUDGET: Duration = Duration::from_mins(15);
const MAX_POLLS: u32 = 30;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
static NEXT_OPERATION_ID: AtomicU64 = AtomicU64::new(1);

/// Volatile account adapter for this one-flow example; it has no durable state or leases.
#[derive(Default)]
struct EmbeddedAccountStore {
    signer: Mutex<Option<Arc<SoftwareSigningKey>>>,
    record: Mutex<Option<AccountRecord>>,
}

fn account_store_error(message: &'static str) -> AccountStoreError {
    AccountStoreError {
        message: message.to_owned(),
        kind: aster_acme::storage::account::AccountStoreErrorKind::Other,
    }
}

#[async_trait]
impl AccountStore for EmbeddedAccountStore {
    async fn lock_account(
        &self,
        _directory: &AcmeUrl,
        _thumbprint: &str,
    ) -> Result<Arc<dyn AccountLease>, AccountStoreError> {
        // The example runs one account operation; real adapters must serialize contenders.
        Ok(Arc::new(()))
    }

    async fn load(
        &self,
        directory: &AcmeUrl,
        thumbprint: &str,
    ) -> Result<Option<AccountRecord>, AccountStoreError> {
        // Never expose an account record under a different CA or key identity.
        let record = self
            .record
            .lock()
            .map_err(|_| account_store_error("account state unavailable"))?;
        Ok(record
            .as_ref()
            .filter(|record| {
                record.directory_url == *directory && record.key_thumbprint == thumbprint
            })
            .cloned())
    }

    async fn save(
        &self,
        record: &AccountRecord,
        _lease: &Arc<dyn AccountLease>,
    ) -> Result<(), AccountStoreError> {
        // A record update may refresh CA observations, but it cannot replace the key identity.
        let signer = self
            .signer
            .lock()
            .map_err(|_| account_store_error("account key unavailable"))?;
        let signer = signer
            .as_ref()
            .ok_or_else(|| account_store_error("account key is missing"))?;
        let thumbprint = signer
            .jwk()
            .and_then(|jwk| jwk.thumbprint())
            .map_err(|_| account_store_error("account key identity is unavailable"))?;
        if record.key_thumbprint != thumbprint || record.key_algorithm != signer.algorithm() {
            return Err(account_store_error("account record does not match its key"));
        }
        let mut saved = self
            .record
            .lock()
            .map_err(|_| account_store_error("account state unavailable"))?;
        if saved.as_ref().is_none_or(|saved| {
            saved.directory_url != record.directory_url || saved.account_id != record.account_id
        }) {
            return Err(account_store_error(
                "account directory or stable identity changed",
            ));
        }
        *saved = Some(record.clone());
        Ok(())
    }
}

#[async_trait]
impl AccountKeyStore for EmbeddedAccountStore {
    async fn signer(
        &self,
        directory: &AcmeUrl,
        name: &str,
        access: KeyAccess,
    ) -> Result<Arc<dyn JwsSigner>, AccountStoreError> {
        // This adapter intentionally models one named account only.
        if name != ACCOUNT_NAME {
            return Err(account_store_error(
                "this example owns only its embedded account",
            ));
        }
        let mut signer_slot = self
            .signer
            .lock()
            .map_err(|_| account_store_error("account key unavailable"))?;
        if signer_slot.is_none() {
            let KeyAccess::Create(algorithm) = access else {
                return Err(account_store_error("account key does not exist"));
            };
            let signer = Arc::new(
                SoftwareSigningKey::generate(algorithm.unwrap_or_default())
                    .map_err(|_| account_store_error("account key generation failed"))?,
            );
            let thumbprint = signer
                .jwk()
                .and_then(|jwk| jwk.thumbprint())
                .map_err(|_| account_store_error("account key identity is unavailable"))?;
            let record = AccountRecord {
                key_algorithm: signer.algorithm(),
                user_agent: None,
                times: AccountTimes::default(),
                account_id: AccountRecord::stable_id(directory, &thumbprint),
                directory_url: directory.clone(),
                key_thumbprint: thumbprint,
                account_url: None,
                contacts: Vec::new(),
                server_contacts: None,
                last_status: None,
                deactivation: DeactivationState::NotRequested,
                key_rotation: None,
                accepted_terms_url: None,
                preferred_profile: None,
                auto_accept_terms_updates: false,
                state: AccountRecordState::RegistrationPending,
            };
            *self
                .record
                .lock()
                .map_err(|_| account_store_error("account state unavailable"))? = Some(record);
            *signer_slot = Some(signer);
        }
        let signer = signer_slot
            .as_ref()
            .ok_or_else(|| account_store_error("account key is missing"))?;
        if let KeyAccess::Create(Some(algorithm)) = access
            && algorithm != signer.algorithm()
        {
            return Err(account_store_error(
                "requested algorithm differs from the saved account key",
            ));
        }
        let record = self
            .record
            .lock()
            .map_err(|_| account_store_error("account state unavailable"))?;
        if record
            .as_ref()
            .is_none_or(|record| record.directory_url != *directory)
        {
            return Err(account_store_error(
                "account key belongs to a different directory",
            ));
        }
        Ok(signer.clone())
    }
}

struct EmbeddedGeneration {
    record: IssueRecord,
    key: Zeroizing<Vec<u8>>,
    csr: Vec<u8>,
}

/// In-memory issuance state with validated output files; unsuitable for restart or concurrent execution.
struct EmbeddedIssueStore {
    generations: Arc<Mutex<Vec<EmbeddedGeneration>>>,
    artifact_root: PathBuf,
}

impl EmbeddedIssueStore {
    fn new(artifact_root: PathBuf) -> Self {
        Self {
            generations: Arc::new(Mutex::new(Vec::new())),
            artifact_root,
        }
    }
}

struct EmbeddedIssueSession {
    generations: Arc<Mutex<Vec<EmbeddedGeneration>>>,
    artifact_root: PathBuf,
    name: CertificateName,
    operation_id: String,
}

impl EmbeddedIssueSession {
    // Resolve every operation by both managed name and operation ID so stale sessions
    // cannot mutate a later request that happens to reuse the same certificate name.
    fn with_generation<T>(
        &self,
        f: impl FnOnce(&mut EmbeddedGeneration) -> Result<T, IssueError>,
    ) -> Result<T, IssueError> {
        let mut generations = self
            .generations
            .lock()
            .map_err(|_| IssueError::InvalidInput("example issuance state unavailable"))?;
        let generation = generations
            .iter_mut()
            .find(|generation| {
                generation.record.name == self.name
                    && generation.record.operation_id == self.operation_id
            })
            .ok_or(IssueError::InvalidInput(
                "example issuance generation not found",
            ))?;
        f(generation)
    }
}

// These fields define the immutable request and signer binding for a generation;
// workflow checkpoints may advance, but the request material may not be rewritten.
fn same_generation_identity(saved: &IssueRecord, candidate: &IssueRecord) -> bool {
    saved.name == candidate.name
        && saved.operation_id == candidate.operation_id
        && saved.created_at == candidate.created_at
        && saved.account_name == candidate.account_name
        && saved.account_id == candidate.account_id
        && saved.directory == candidate.directory
        && saved.account_url == candidate.account_url
        && saved.account_thumbprint == candidate.account_thumbprint
        && saved.challenge == candidate.challenge
        && saved.solver_id == candidate.solver_id
        && saved.solver_config == candidate.solver_config
        && saved.key_algorithm == candidate.key_algorithm
        && saved.profile == candidate.profile
        && saved.identifiers == candidate.identifiers
}

#[async_trait]
impl IssueSession for EmbeddedIssueSession {
    async fn record(&self) -> Result<IssueRecord, IssueError> {
        self.with_generation(|generation| Ok(generation.record.clone()))
    }

    async fn save(&self, record: &IssueRecord) -> Result<(), IssueError> {
        self.with_generation(|generation| {
            if !same_generation_identity(&generation.record, record) {
                return Err(IssueError::InvalidInput(
                    "example issuance identity or definition changed",
                ));
            }
            generation.record = record.clone();
            Ok(())
        })
    }

    async fn certificate_key(&self) -> Result<Vec<u8>, IssueError> {
        self.with_generation(|generation| Ok(generation.key.to_vec()))
    }

    async fn csr(&self) -> Result<Vec<u8>, IssueError> {
        self.with_generation(|generation| Ok(generation.csr.clone()))
    }

    async fn complete(
        &self,
        record: &IssueRecord,
        chain: &[u8],
    ) -> Result<IssueRecord, IssueError> {
        self.with_generation(|generation| {
            // Only the downloading checkpoint may promote the exact generation and fixed CSR key.
            if !same_generation_identity(&generation.record, record)
                || generation.record.phase != IssuancePhase::Downloading
                || record.phase != IssuancePhase::Completed
            {
                return Err(IssueError::InvalidInput(
                    "example issuance cannot promote this generation",
                ));
            }
            certificate::validate(chain, &generation.key, &record.identifiers)?;
            let renewal = RenewalPlan::from_certificate(chain)?;
            let artifacts = certificate::artifacts(chain, &generation.key)?;
            let output = self
                .artifact_root
                .join("certs")
                .join(self.name.as_str())
                .join("in_use");
            let staging = output.with_extension(format!("tmp-{}", self.operation_id));
            // Build the complete artifact set off to the side; expose it only after every write succeeds.
            std::fs::create_dir_all(&staging).map_err(|_| {
                IssueError::InvalidInput("cannot create example artifact directory")
            })?;
            let fullchain = format!("{}{}", artifacts.certificate, artifacts.ca_chain);
            for (file, contents) in [
                ("fullchain.pem", fullchain.as_str()),
                ("cert.pem", artifacts.certificate.as_str()),
                ("ca.pem", artifacts.ca_chain.as_str()),
                ("private-key.pem", artifacts.private_key.as_str()),
            ] {
                if let Err(error) = std::fs::write(staging.join(file), contents) {
                    let _ = std::fs::remove_dir_all(&staging);
                    return Err(IssueError::Publication(error.to_string()));
                }
            }
            if output.exists() {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(IssueError::InvalidInput(
                    "example in_use artifacts already exist",
                ));
            }
            if let Err(error) = std::fs::rename(&staging, &output) {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(IssueError::Publication(error.to_string()));
            }
            let mut completed = record.clone();
            completed.is_in_use = true;
            completed.renewal = Some(renewal);
            generation.record = completed.clone();
            Ok(completed)
        })
    }

    async fn record_renewal_failure(
        &self,
        _failure: aster_acme::renewal::admission::RenewalFailure,
    ) -> Result<RenewalRetryState, IssueError> {
        Err(IssueError::InvalidInput(
            "renewal is outside this example store's scope",
        ))
    }
}

#[async_trait]
impl IssueStore for EmbeddedIssueStore {
    async fn create(
        &self,
        request: &IssueRequest,
        account: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        request.validate()?;
        let account_url = account.account_url.clone().ok_or(IssueError::InvalidInput(
            "registered account URL is missing",
        ))?;
        // Key and CSR are generated once per operation and retained with its journal.
        let material = certificate::generate(&request.identifiers, request.key_algorithm)?;
        let sequence = NEXT_OPERATION_ID.fetch_add(1, Ordering::Relaxed);
        let operation_id = format!(
            "{}-{sequence}",
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let record = IssueRecord {
            chain_selection: request.chain_selection.clone(),
            selected_chain: None,
            challenge: request.challenge,
            solver_config: request.solver_config.clone(),
            is_in_use: false,
            deployment_count: None,
            renewal_of: None,
            solver_id: request.solver_id.clone(),
            operation_id: operation_id.clone(),
            name: request.name.clone(),
            created_at: time::OffsetDateTime::now_utc(),
            account_name: request.account_name.clone(),
            account_id: account.account_id.clone(),
            directory: account.directory_url.clone(),
            account_url,
            account_thumbprint: account.key_thumbprint.clone(),
            key_algorithm: request.key_algorithm,
            profile: request.profile.clone(),
            identifiers: request.identifiers.clone(),
            phase: IssuancePhase::CreatingOrder,
            new_order_intent_saved: false,
            creation_failure: None,
            submitted_replaces: None,
            order_url: None,
            order: None,
            authorizations: Vec::new(),
            finalize_submitted: SubmissionState::NotSubmitted,
            finalize_rejection: None,
            next_poll_at: None,
            poll_wait_source: None,
            revocation: aster_acme::revocation::RevocationRecord::default(),
            renewal: None,
            renewal_retry: None,
        };
        let mut generations = self
            .generations
            .lock()
            .map_err(|_| IssueError::InvalidInput("example issuance state unavailable"))?;
        if generations
            .iter()
            .any(|generation| generation.record.name == request.name)
        {
            return Err(IssueError::NameAlreadyExists(request.name.clone()));
        }
        generations.push(EmbeddedGeneration {
            record,
            key: material.key,
            csr: material.csr,
        });
        drop(generations);
        Ok(Box::new(EmbeddedIssueSession {
            generations: self.generations.clone(),
            artifact_root: self.artifact_root.clone(),
            name: request.name.clone(),
            operation_id,
        }))
    }

    async fn renew(
        &self,
        _name: &CertificateName,
        _account: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        Err(IssueError::InvalidInput(
            "renewal is outside this example store's scope",
        ))
    }

    async fn open(
        &self,
        name: &CertificateName,
        operation_id: &str,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        self.session(name, operation_id)
    }

    async fn open_observation(
        &self,
        _name: &CertificateName,
        _operation_id: &str,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        Err(IssueError::InvalidInput(
            "observation sessions are outside this example store's scope",
        ))
    }

    async fn query(&self, query: IssueQuery) -> Result<Vec<IssueRecord>, IssueError> {
        let generations = self
            .generations
            .lock()
            .map_err(|_| IssueError::InvalidInput("example issuance state unavailable"))?;
        query
            .view
            .project(
                generations
                    .iter()
                    .map(|generation| generation.record.clone())
                    .collect(),
            )
            .map(|records| {
                records
                    .into_iter()
                    .filter(|record| query.matches(record))
                    .collect()
            })
    }
}

impl EmbeddedIssueStore {
    fn session(
        &self,
        name: &CertificateName,
        operation_id: &str,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        let generations = self
            .generations
            .lock()
            .map_err(|_| IssueError::InvalidInput("example issuance state unavailable"))?;
        if !generations.iter().any(|generation| {
            generation.record.name == *name && generation.record.operation_id == operation_id
        }) {
            return Err(IssueError::InvalidInput(
                "example issuance generation not found",
            ));
        }
        Ok(Box::new(EmbeddedIssueSession {
            generations: self.generations.clone(),
            artifact_root: self.artifact_root.clone(),
            name: name.clone(),
            operation_id: operation_id.to_owned(),
        }))
    }
}

/// Arguments accepted by the example binary.
#[derive(Debug, Parser)]
struct Args {
    /// DNS name or bare IP literal ([RFC 8738](https://datatracker.ietf.org/doc/html/rfc8738)) to issue; wildcards are rejected
    /// because HTTP-01 cannot validate them.
    #[arg(short, long)]
    domain: String,
    /// Webroot of an already running HTTP server; challenge files are written below it.
    #[arg(short, long)]
    webroot: PathBuf,
    /// Optional contact mailbox, for example admin@example.com (mailto: is also accepted).
    #[arg(short, long)]
    contact: Vec<String>,
    /// CA directory URL; staging by default, override for another ACME CA.
    #[arg(long, default_value = LETSENCRYPT_STAGING_DIRECTORY)]
    directory: String,
    /// Managed certificate name for this run.
    #[arg(short, long, default_value = DEFAULT_CERTIFICATE_NAME)]
    name: String,
}

/// Embedder-owned HTTP-01 publication. ACME derives the material; this type
/// owns files, ownership and cleanup. Locks never span an await point.
struct EmbeddedWebroot {
    root: PathBuf,
    published: Mutex<Vec<(PathBuf, String)>>,
}

impl EmbeddedWebroot {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            published: Mutex::new(Vec::new()),
        }
    }

    fn target(&self, requirement: &ValidationRequirement) -> Option<(PathBuf, String)> {
        // Accept only the library-derived HTTP-01 path; other challenge material is out of scope.
        let ValidationRequirement::Http01 { path, content, .. } = requirement else {
            return None;
        };
        let token = path.strip_prefix("/.well-known/acme-challenge/")?;
        Some((
            self.root
                .join(".well-known")
                .join("acme-challenge")
                .join(token),
            content.clone(),
        ))
    }
}

#[async_trait]
impl ChallengeSolver for EmbeddedWebroot {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::Http01
    }

    async fn ready(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<ReadyResult, IssueError> {
        // Track only files this solver wrote so cleanup never claims unrelated paths.
        let mut newly = Vec::new();
        for publication in publications {
            execution.check().map_err(IssueError::from)?;
            let Some((target, content)) = self.target(&publication.requirement) else {
                return Err(IssueError::InvalidInput(
                    "webroot solver received non-HTTP-01 material",
                ));
            };
            let directory = target.parent().ok_or_else(|| {
                IssueError::InvalidInput("challenge target has no parent directory")
            })?;
            tokio::fs::create_dir_all(directory)
                .await
                .map_err(|error| IssueError::Publication(error.to_string()))?;
            tokio::fs::write(&target, content.as_bytes())
                .await
                .map_err(|error| IssueError::Publication(error.to_string()))?;
            println!("published challenge file: {}", target.display());
            newly.push((target, content));
        }
        self.published
            .lock()
            .map(|mut published| published.extend(newly))
            .map_err(|_| IssueError::Cancelled)?;
        Ok(ReadyResult {
            ready: true,
            ..ReadyResult::default()
        })
    }

    async fn cleanup(
        &self,
        publications: &[ChallengePublication],
        _execution: &ExecutionContext,
    ) -> Result<CleanupResult, IssueError> {
        let mut completed = Vec::new();
        for publication in publications {
            let Some((target, content)) = self.target(&publication.requirement) else {
                continue;
            };
            // Claim and drop ownership under one short lock; IO happens without it.
            let claimed = {
                let mut published = self.published.lock().map_err(|_| IssueError::Cancelled)?;
                published
                    .iter()
                    .position(|(path, saved)| path == &target && saved == &content)
                    .map(|index| published.remove(index))
            };
            if claimed.is_none() {
                continue;
            }
            match tokio::fs::read(&target).await {
                Ok(bytes) if bytes == content.as_bytes() => {
                    if let Err(error) = tokio::fs::remove_file(&target).await {
                        return Err(IssueError::Publication(error.to_string()));
                    }
                    println!("removed owned challenge file: {}", target.display());
                }
                Ok(_) => println!("retained changed challenge file: {}", target.display()),
                Err(_) => {}
            }
            completed.push(publication.publication_id.clone());
        }
        Ok(CleanupResult {
            completed,
            failure: None,
            retry_at: None,
        })
    }
}

/// Prints typed protocol events; an embedding application renders its own UI here.
struct ProgressPrinter;

impl IssueObserver for ProgressPrinter {
    fn observe(&self, event: &IssueEvent) {
        let message = match event {
            IssueEvent::CreatingOrder { method, .. } => {
                format!("creating {} order", method.name())
            }
            IssueEvent::OrderCreated { .. } => "order created".to_owned(),
            IssueEvent::OrderObserved { status } => format!("order status: {status:?}"),
            IssueEvent::AuthorizationObserved { identifier, status } => {
                format!("authorization {identifier}: {status:?}")
            }
            IssueEvent::PublicationRequired { count, .. } => {
                format!("{count} publication(s) required")
            }
            IssueEvent::PublicationReady { method } => {
                format!("{} publication ready", method.name())
            }
            IssueEvent::CleanupPending => "cleanup pending".to_owned(),
            IssueEvent::ValidationSubmitted { identifier } => {
                format!("validation submitted for {identifier}")
            }
            IssueEvent::Polling { attempt, limit } => {
                format!("polling ({attempt}/{limit})")
            }
            IssueEvent::Waiting { delay, .. } => {
                format!("waiting {delay:?}")
            }
            IssueEvent::Finalizing => "finalizing".to_owned(),
            IssueEvent::ChainCandidatesObserved { available } => {
                format!("{} candidate chain(s)", available.len())
            }
            IssueEvent::ChainSelectionUnavailable { requested, using } => {
                format!("chain {requested} unavailable; using CA default {using}")
            }
            IssueEvent::ChainSelected { chain } => format!("chain: {chain}"),
            IssueEvent::Downloading => "downloading certificate".to_owned(),
            IssueEvent::CertificateSaved { name } => {
                format!("certificate saved: {}", name.as_str())
            }
        };
        println!("{message}");
    }
}

impl WorkflowObserver for ProgressPrinter {
    fn discovering(&self) {
        println!("discovering CA directory");
    }

    fn discovered(&self, directory: &Directory, _record: &IssueRecord) {
        let terms = directory.meta.terms_of_service.as_ref().map_or_else(
            || "none advertised".to_owned(),
            |terms| display_terms(terms),
        );
        println!("directory ready; terms: {terms}");
    }
}

fn normalize_contact(contact: &str) -> String {
    if contact.starts_with("mailto:") {
        contact.to_owned()
    } else {
        format!("mailto:{contact}")
    }
}

/// CA-controlled term identifiers are untrusted terminal text. Escape control
/// and bidirectional-format characters at this display boundary only; the
/// directory value and the recorded acceptance stay verbatim. Embedders should
/// apply the same policy wherever server text reaches a terminal.
fn display_terms(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control()
                || matches!(
                    c,
                    '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
            {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn artifact_paths(data_dir: &Path, name: &CertificateName) -> PathBuf {
    data_dir.join("certs").join(name.as_str()).join("in_use")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run(args))
}

/// Discover the CA, then register once or reuse the persisted identity. The
/// example accepts the advertised terms itself; a product must collect real
/// user consent before this call.
async fn ensure_registered_account(
    pool: &HttpPool,
    directory: &AcmeUrl,
    transport: TransportOptions,
    store: &Arc<EmbeddedAccountStore>,
    signer: &Arc<dyn JwsSigner>,
    contacts: Vec<String>,
) -> Result<AccountRecord, Box<dyn std::error::Error>> {
    // The service owns registration/recovery protocol decisions; this adapter owns only state.
    let client = Arc::new(pool.discover(directory.clone(), transport).await?);
    let service = AccountService::new(client, store.clone());
    let account = service
        .register_or_recover(
            signer.as_ref(),
            RegistrationOptions {
                contacts,
                terms_accepted: true,
                ..RegistrationOptions::default()
            },
        )
        .await?;
    println!(
        "account {} at {}",
        if account.recovered {
            "reused"
        } else {
            "registered"
        },
        account.account_url.as_str()
    );
    let thumbprint = signer.jwk()?.thumbprint()?;
    store
        .load(directory, &thumbprint)
        .await?
        .ok_or_else(|| "registered account record is missing".into())
}

/// Load or create the account signing key, then register once or reuse the
/// persisted identity.
async fn ensure_account(
    directory: &AcmeUrl,
    transport: TransportOptions,
    account_store: &Arc<EmbeddedAccountStore>,
    contacts: Vec<String>,
) -> Result<(AccountRecord, Arc<dyn JwsSigner>, HttpPool), Box<dyn std::error::Error>> {
    // Account signing key: load the persisted one or generate and store a new key.
    let signer = AccountKeyStore::signer(
        account_store.as_ref(),
        directory,
        ACCOUNT_NAME,
        KeyAccess::Create(Some(KeyAlgorithm::default())),
    )
    .await?;
    let pool = HttpPool::default();
    let account = ensure_registered_account(
        &pool,
        directory,
        transport,
        account_store,
        &signer,
        contacts,
    )
    .await?;
    Ok((account, signer, pool))
}

/// Reuse an unfinished request in this process, otherwise create one.
async fn open_or_create(
    store: &EmbeddedIssueStore,
    request: &IssueRequest,
    account_record: &AccountRecord,
    name: &CertificateName,
) -> Result<Box<dyn IssueSession>, Box<dyn std::error::Error>> {
    // Resume the existing operation instead of creating a second order for the same name.
    let saved = store
        .query(IssueQuery {
            unfinished: Some(true),
            name: Some(name.clone()),
            ..IssueQuery::default()
        })
        .await?;
    match saved.into_iter().next() {
        Some(saved) => {
            println!("resuming saved request {}", saved.operation_id);
            Ok(store.open(&saved.name, &saved.operation_id).await?)
        }
        None => Ok(store.create(request, account_record).await?),
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let directory = AcmeUrl::new(&args.directory)?;
    let identifier = Identifier::new(&args.domain)?;
    if identifier.is_wildcard() {
        return Err("HTTP-01 cannot validate wildcard identifiers".into());
    }
    let name = CertificateName::new(&args.name)?;
    let contacts = args
        .contact
        .iter()
        .map(|contact| normalize_contact(contact))
        .collect::<Vec<_>>();

    // The whole managed state lives here and disappears with the process; an
    // embedding application supplies durable adapters instead.
    let data_dir = TempDir::new()?;
    let account_store = Arc::new(EmbeddedAccountStore::default());
    let issue_store = EmbeddedIssueStore::new(data_dir.path().to_path_buf());
    let transport = TransportOptions {
        allow_loopback_http: directory.as_str().starts_with("http://"),
        ..TransportOptions::default()
    };
    let (account_record, signer, pool) =
        ensure_account(&directory, transport.clone(), &account_store, contacts).await?;

    let request = IssueRequest {
        chain_selection: None,
        challenge: ChallengeKind::Http01,
        solver_id: "embedded-webroot".to_owned(),
        solver_config: serde_json::json!({ "root": args.webroot.display().to_string() }),
        name: name.clone(),
        identifiers: vec![identifier],
        profile: None,
        key_algorithm: KeyAlgorithm::default(),
        account_name: ACCOUNT_NAME.to_owned(),
    };
    request.validate()?;
    let mut session = open_or_create(&issue_store, &request, &account_record, &name).await?;

    let solver = EmbeddedWebroot::new(args.webroot.clone());
    let workflow =
        Workflow::new(pool, directory, transport)?.with_observer(Arc::new(ProgressPrinter));
    let execution = IssueExecution {
        max_polls: MAX_POLLS,
        context: ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + TOTAL_BUDGET,
        },
        poll_interval: POLL_INTERVAL,
    };
    let outcome = workflow
        .run(
            IssueIdentity {
                account: account_record,
                signer,
            },
            session.as_mut(),
            &solver,
            &execution,
        )
        .await?;

    match outcome {
        IssueOutcome::Completed { record, cleanup } => {
            let generation = artifact_paths(data_dir.path(), &record.name);
            println!("issued certificate {}", record.name.as_str());
            println!("artifacts: {}", generation.display());
            for file in ["fullchain.pem", "cert.pem", "ca.pem", "private-key.pem"] {
                println!("  {}", generation.join(file).display());
            }
            for requirement in &cleanup {
                println!("retain manual validation material: {requirement:?}");
            }
            println!(
                "note: this run used a temporary data directory; the files above are removed on exit"
            );
        }
        IssueOutcome::ActionRequired { record, records } => {
            for requirement in &records {
                println!("pending validation material: {requirement:?}");
            }
            println!(
                "serve the material above; this in-memory example cannot resume after process exit ({})",
                record.operation_id
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "embedded_issuance/tests.rs"]
mod tests;
