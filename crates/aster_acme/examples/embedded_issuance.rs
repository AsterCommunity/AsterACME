//! End-to-end embedded issuance: the library services, a file store, and an
//! embedder-owned HTTP-01 solver in one runnable binary.
//!
//! The chain mirrors what an embedding application owns: discover the CA
//! directory, register or reuse an account through `AccountService`, inject a
//! `ChallengeSolver`, create or resume a saved issuance via `IssueStore`, and
//! read the promoted artifacts. Protocol state, retries and recovery stay
//! inside `aster_acme`; this file only shows the adapter surface.
//!
//! Defaults are deliberately safe for a first run: Let's Encrypt **staging**
//! and a temporary data directory that is removed on exit. Passing
//! `--directory http://localhost:14000/dir` targets a local Pebble or other
//! test CA listening without TLS; plain loopback HTTP is then allowed
//! explicitly through the transport options. The resume path activates when
//! an embedding application substitutes its own persistent data directory:
//! rerunning the same command picks up the unfinished saved request.
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
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use aster_acme::{
    account::{AccountRecord, AccountService, RegistrationOptions},
    challenge::ChallengeKind,
    crypto::{JwsSigner, key_algorithm::KeyAlgorithm},
    identifier::DnsIdentifier,
    issuance::{
        CertificateName, IssueError, IssueExecution, IssueIdentity, IssueOutcome, IssueRecord,
        IssueRequest, ValidationRequirement,
        progress::{IssueEvent, IssueObserver},
        workflow::{Workflow, WorkflowObserver},
    },
    solver::{ChallengePublication, ChallengeSolver, CleanupResult, ExecutionContext, ReadyResult},
    storage::{
        account::{AccountKeyStore, KeyAccess},
        issuance::{IssueSession, IssueStore},
        query::IssueQuery,
    },
    transport::{HttpPool, TransportOptions},
};
use aster_acme_cli_storage::{account::CliAccountStore, issuance::CliIssueStore};
use aster_acme_protocol::{directory::Directory, url::AcmeUrl};
use async_trait::async_trait;
use clap::Parser;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const LETSENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
const DEFAULT_CERTIFICATE_NAME: &str = "embedded-example";
const ACCOUNT_NAME: &str = "embedded";
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_BUDGET: Duration = Duration::from_mins(15);
const MAX_POLLS: u32 = 30;
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Arguments accepted by the example binary.
#[derive(Debug, Parser)]
struct Args {
    /// DNS name to issue; wildcards are rejected because HTTP-01 cannot validate them.
    #[arg(short, long)]
    domain: String,
    /// Webroot of an already running HTTP server; challenge files are written below it.
    #[arg(short, long)]
    webroot: PathBuf,
    /// Optional contact mailbox, for example admin@example.com (mailto: is also accepted).
    #[arg(short, long)]
    contact: Vec<String>,
    /// CA directory URL; staging by default, override for Pebble or another test CA.
    #[arg(long, default_value = LETSENCRYPT_STAGING_DIRECTORY)]
    directory: String,
    /// Managed certificate name; an unfinished request under this name is resumed.
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
            |url| url.as_str().to_owned(),
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
async fn ensure_account(
    pool: &HttpPool,
    directory: &AcmeUrl,
    transport: TransportOptions,
    store: &Arc<CliAccountStore>,
    signer: &Arc<dyn JwsSigner>,
    contacts: Vec<String>,
) -> Result<AccountRecord, Box<dyn std::error::Error>> {
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
    Ok(store
        .metadata()
        .await?
        .ok_or("registered account record is missing")?)
}

/// Resume an unfinished saved request under this name, otherwise create one.
async fn open_or_create(
    store: &CliIssueStore,
    request: &IssueRequest,
    account_record: &AccountRecord,
    name: &CertificateName,
) -> Result<Box<dyn IssueSession>, Box<dyn std::error::Error>> {
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
    let identifier = DnsIdentifier::new(&args.domain)?;
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
    // embedding application passes its own persistent directory instead.
    let data_dir = TempDir::new()?;
    let account_store = Arc::new(CliAccountStore::open(
        data_dir.path(),
        ACCOUNT_NAME,
        LOCK_TIMEOUT,
    )?);
    let issue_store = CliIssueStore::new(data_dir.path().to_path_buf(), LOCK_TIMEOUT);

    // Account signing key: load the persisted one or generate and store a new key.
    let signer = AccountKeyStore::signer(
        account_store.as_ref(),
        &directory,
        ACCOUNT_NAME,
        KeyAccess::Create(Some(KeyAlgorithm::default())),
    )
    .await?;

    // Loopback HTTP stays opt-in for numeric-IP test CAs such as Pebble.
    let transport = TransportOptions {
        allow_loopback_http: directory.as_str().starts_with("http://"),
        ..TransportOptions::default()
    };
    let pool = HttpPool::default();
    let account_record = ensure_account(
        &pool,
        &directory,
        transport.clone(),
        &account_store,
        &signer,
        contacts,
    )
    .await?;

    let request = IssueRequest {
        challenge: ChallengeKind::Http01,
        solver_id: "embedded-webroot".to_owned(),
        solver_config: serde_json::json!({ "root": args.webroot.display().to_string() }),
        name: name.clone(),
        identifiers: vec![identifier],
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
                "serve the material above, then rerun this command to resume {}",
                record.operation_id
            );
        }
    }
    Ok(())
}
