//! CLI execution wires account leases, generation sessions, and manual DNS UI into the library.
use super::progress::Progress;
use super::{
    args::{CertCommand, IssueArgs},
    render, selection,
};
use crate::common::args::{HttpArgs, LocalArgs};
use crate::common::log::Level;
use crate::{
    commands::account::args::AccountArgs,
    common::{
        context::{CliContext, CliSettings},
        error::CliResult,
        terminal,
    },
};
use aster_acme::issuance::service::IssueService;
use aster_acme::{
    account::{AccountKeyStore, AccountStore},
    identifier::DnsIdentifier,
    issuance::{
        CertificateName, DnsReadiness, DnsRequirement, IssueError, IssueExecution, IssueIdentity,
        IssueOutcome, IssueRecord, IssueRequest, IssueSession, IssueStore,
    },
    solver::ExecutionContext,
    transport::AcmeClient,
};
use aster_acme_cli_storage::issuance::CliIssueStore;
use async_trait::async_trait;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

fn options(local: &LocalArgs, http: &HttpArgs, account: Option<String>) -> AccountArgs {
    AccountArgs {
        data_dir: local.data_dir.clone(),
        json: local.json,
        name: account,
        user_agent: http.user_agent.clone(),
        timeout: http.timeout,
        ..AccountArgs::default()
    }
}

async fn issue(mut args: IssueArgs) -> CliResult<()> {
    let progress = Arc::new(Progress::new(args.local.json));
    let interactive = terminal::interactive(args.local.json);
    super::interaction::complete(
        &mut args,
        interactive,
        &mut super::interaction::TerminalDomains,
    )?;
    let mut options = options(&args.local, &args.http, args.account.clone());
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    let selected = match &args.resume {
        Some(name) => Some(selection::choose(
            store.list().await?,
            &CertificateName::new(name)?,
            args.operation.as_deref(),
            true,
            options.json,
        )?),
        None => None,
    };
    if let Some(record) = &selected {
        options.name = Some(record.account_name.clone());
    }
    let context = settings.account(&options).await?;
    progress.log.line(
        Level::Info,
        &format!(
            "Using CA: {} (account {})",
            context.directory.as_str(),
            context.name
        ),
    );
    let signer = context
        .store
        .signer(&context.directory, &context.name, false)
        .await?;
    let thumbprint = signer.jwk()?.thumbprint()?;
    // Lock order is account, then certificate. Rotation/deactivation/removal cannot
    // change the account identity during challenge material derivation or signing.
    let _account_lease = context
        .store
        .lock_account(&context.directory, &thumbprint)
        .await?;
    let account = context
        .store
        .load(&context.directory, &thumbprint)
        .await?
        .ok_or("No registered account exists.")?;
    if !account.is_usable() {
        return Err("Issuance requires a registered active account.".into());
    }
    let mut session =
        prepare_session(&store, selected, &args, &context.name, &account, &progress).await?;
    let record = session.record().await?;
    let root = context
        .config_path
        .parent()
        .ok_or("Missing data directory.")?;
    let generation = root
        .join("certs")
        .join(record.name.as_str())
        .join(record.generation_name());
    progress.log.line(
        Level::Info,
        &format!(
            "Certificate key: {}",
            generation.join("private-key.pk8").display()
        ),
    );
    let foreground = Foreground {
        context: &context,
        options: &options,
        args: &args,
        progress: progress.clone(),
    };
    let outcome = match foreground
        .run(IssueIdentity { account, signer }, session.as_mut())
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            progress.log.line(Level::Info,&format!("Request retained. Resume with: aster-acme cert issue --resume '{}' --operation {}",record.name.as_str(),record.operation_id));
            return Err(error);
        }
    };
    println!(
        "{}",
        render::outcome(
            &outcome,
            options.json,
            context
                .config_path
                .parent()
                .ok_or("Missing data directory.")?
        )?
    );
    Ok(())
}

struct Foreground<'a> {
    context: &'a CliContext,
    options: &'a AccountArgs,
    args: &'a IssueArgs,
    progress: Arc<Progress>,
}
impl Foreground<'_> {
    async fn run(
        &self,
        identity: IssueIdentity,
        session: &mut dyn IssueSession,
    ) -> CliResult<IssueOutcome> {
        self.progress
            .log
            .line(Level::Info, "Discovering ACME endpoints over verified TLS");
        tracing::debug!("Discovering certificate issuance endpoints");
        let client = Arc::new(
            AcmeClient::discover(
                self.context.directory.clone(),
                self.context.transport_options(self.options)?,
            )
            .await?,
        );
        let service = IssueService::new(client, identity)?.with_observer(self.progress.clone());
        let cancellation = CancellationToken::new();
        let signal = tokio::spawn({
            let cancellation = cancellation.clone();
            async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    cancellation.cancel();
                }
            }
        });
        let execution = IssueExecution {
            context: ExecutionContext {
                cancellation,
                deadline: Instant::now() + Duration::from_secs(self.args.wait_timeout),
            },
            force: self.args.force,
            poll_interval: Duration::from_secs(2),
        };
        let dns = match self.args.challenge {
            super::args::Challenge::ManualDns => ManualDns {
                interactive: terminal::interactive(self.options.json),
                resuming: self.args.resume.is_some(),
                yes: self.args.yes,
                checker: Arc::new(aster_acme_validation::dns01::visibility::DnsVisibility),
                progress: self.progress.clone(),
            },
        };
        let result = service.run(session, &dns, &execution).await;
        signal.abort();
        Ok(result?)
    }
}

struct ManualDns {
    interactive: bool,
    resuming: bool,
    yes: bool,
    checker: Arc<dyn DnsReadiness>,
    progress: Arc<Progress>,
}
#[async_trait]
impl DnsReadiness for ManualDns {
    async fn ready(
        &self,
        records: &[DnsRequirement],
        force: bool,
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        // A new scripted invocation must expose its fresh TXT values before any
        // acknowledgement. --yes only removes human confirmation, not publication.
        if !self.resuming && (self.yes || !self.interactive) {
            return Ok(false);
        }
        if self.interactive && !self.yes {
            let records = records.to_vec();
            let progress = self.progress.clone();
            let (sender, receiver) = tokio::sync::oneshot::channel();
            // A blocked terminal read must not keep Tokio's blocking pool alive after
            // the overall issuance deadline. This CLI-only thread owns no storage lease.
            std::thread::Builder::new()
                .name("manual-dns-confirmation".into())
                .spawn(move || {
                    let details=records.iter().map(|record|format!("{}  TXT  {}",record.name,record.value)).collect::<Vec<_>>();
                    progress.log.details(Level::Warning,"Action required: add every TXT value below; keep existing unrelated values",&details);
                    let result = inquire::Confirm::new("Have you published these TXT values?").with_render_config(crate::common::terminal::prompt_style(false))
                        .with_default(false)
                        .prompt();
                    let _ = sender.send(result);
                })
                .map_err(|_| IssueError::Interrupted)?;
            let confirmed = receiver
                .await
                .map_err(|_| IssueError::Interrupted)?
                .map_err(|_| IssueError::Interrupted)?;
            if !confirmed {
                return Ok(false);
            }
        }
        self.progress.log.line(
            if force { Level::Warning } else { Level::Info },
            if force {
                "Skipping local DNS lookup (--force); proceeding to CA validation"
            } else {
                "Checking all required DNS TXT values"
            },
        );
        let ready = self.checker.ready(records, force, execution).await?;
        if !ready {
            self.progress.log.line(
                Level::Warning,
                "Required DNS TXT values are not visible yet; the request is retained for resume",
            );
        }
        Ok(ready)
    }
}

pub(crate) async fn execute(command: CertCommand) -> CliResult<()> {
    match command {
        CertCommand::Issue(args) => issue(args).await,
        CertCommand::List { name, local } => {
            let options = AccountArgs {
                data_dir: local.data_dir.clone(),
                json: local.json,
                ..AccountArgs::default()
            };
            let settings = CliSettings::load(&options).await?;
            let store = CliIssueStore::new(settings.data_dir, Duration::from_secs(5));
            let filter = name.as_deref().map(CertificateName::new).transpose()?;
            let records = store
                .list()
                .await?
                .into_iter()
                .filter(|record| filter.as_ref().is_none_or(|name| record.name == *name))
                .collect::<Vec<_>>();
            println!("{}", render::list(&records, local.json)?);
            Ok(())
        }
        CertCommand::Show {
            name,
            named_name,
            operation,
            verify,
            http,
            local,
        } => {
            let options = options(&local, &http, None);
            let settings = CliSettings::load(&options).await?;
            let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
            let records = store.list().await?;
            let name = selection::certificate_name(
                &records,
                name.as_deref().or(named_name.as_deref()),
                operation.as_deref(),
                local.json,
            )?;
            let mut record =
                selection::choose(records, &name, operation.as_deref(), false, local.json)?;
            if verify {
                let context = settings
                    .account(&AccountArgs {
                        name: Some(record.account_name.clone()),
                        ..options
                    })
                    .await?;
                record = verify_order(context, &http, &record, &store).await?;
            }
            println!("{}", render::show(&[record], local.json, verify)?);
            Ok(())
        }
    }
}

async fn verify_order(
    context: CliContext,
    http: &HttpArgs,
    record: &IssueRecord,
    store: &CliIssueStore,
) -> CliResult<IssueRecord> {
    let signer = context
        .store
        .signer(&context.directory, &context.name, false)
        .await?;
    let thumbprint = signer.jwk()?.thumbprint()?;
    let _lease = context
        .store
        .lock_account(&context.directory, &thumbprint)
        .await?;
    let account = context
        .store
        .load(&context.directory, &thumbprint)
        .await?
        .ok_or("Account metadata missing.")?;
    let mut session = store.open(&record.name, &record.operation_id).await?;
    let transport = context.transport_options(&AccountArgs {
        user_agent: http.user_agent.clone(),
        timeout: http.timeout,
        ..AccountArgs::default()
    })?;
    let client = Arc::new(AcmeClient::discover(context.directory, transport).await?);
    Ok(
        IssueService::new(client, IssueIdentity { account, signer })?
            .inspect(session.as_mut())
            .await?,
    )
}

fn request(args: &IssueArgs, account: &str) -> CliResult<IssueRequest> {
    let identifiers = args.domain.clone();
    let primary = identifiers
        .first()
        .ok_or("At least one domain is required.")?
        .value();
    Ok(IssueRequest {
        name: CertificateName::new(args.name.as_deref().unwrap_or(&primary))?,
        identifiers,
        account_name: account.into(),
    })
}

// Resolve recovery and new-generation creation together with their user-visible intent.
async fn prepare_session(
    store: &CliIssueStore,
    selected: Option<IssueRecord>,
    args: &IssueArgs,
    account_name: &str,
    account: &aster_acme::account::AccountRecord,
    progress: &Progress,
) -> CliResult<Box<dyn IssueSession>> {
    let session = if let Some(record) = selected {
        progress.log.line(
            Level::Info,
            &format!(
                "Resuming {} requested at {}",
                record.name.as_str(),
                crate::common::time::timestamp(Some(record.created_at))
            ),
        );
        store.open(&record.name, &record.operation_id).await?
    } else {
        let request = request(args, account_name)?;
        progress.log.line(
            Level::Info,
            &format!(
                "Domains: {}",
                request
                    .identifiers
                    .iter()
                    .map(DnsIdentifier::value)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
        progress
            .log
            .line(Level::Info, "Creating certificate key and fixed CSR");
        store.create(&request, account).await?
    };
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct Check {
        calls: AtomicUsize,
        forced: AtomicBool,
    }
    #[async_trait]
    impl DnsReadiness for Check {
        async fn ready(
            &self,
            _records: &[DnsRequirement],
            force: bool,
            execution: &ExecutionContext,
        ) -> Result<bool, IssueError> {
            execution.check().map_err(|_| IssueError::Interrupted)?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.forced.store(force, Ordering::SeqCst);
            // Represent a TXT value which has not propagated: --yes must preserve it.
            Ok(force)
        }
    }

    #[tokio::test]
    async fn yes_bypasses_terminal_confirmation_but_not_dns_readiness() {
        for interactive in [false, true] {
            for force in [false, true] {
                let check = Arc::new(Check::default());
                let manual = ManualDns {
                    interactive,
                    resuming: true,
                    yes: true,
                    checker: check.clone(),
                    progress: Arc::new(Progress::new(true)),
                };
                let execution = ExecutionContext {
                    cancellation: CancellationToken::new(),
                    deadline: Instant::now() + Duration::from_secs(2),
                };
                let records = [DnsRequirement {
                    name: "_acme-challenge.example.invalid".into(),
                    value: "not-propagated".into(),
                }];
                let result = tokio::time::timeout(
                    Duration::from_secs(1),
                    manual.ready(&records, force, &execution),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(result, force);
                assert_eq!(check.calls.load(Ordering::SeqCst), 1);
                assert_eq!(check.forced.load(Ordering::SeqCst), force);
                execution.cancellation.cancel();
                assert!(matches!(
                    manual.ready(&records, force, &execution).await,
                    Err(IssueError::Interrupted)
                ));
            }
        }
    }

    #[tokio::test]
    async fn new_automated_requests_yield_txt_instructions_even_with_yes_and_force() {
        for (interactive, yes) in [(false, false), (false, true), (true, true)] {
            let check = Arc::new(Check::default());
            let manual = ManualDns {
                interactive,
                resuming: false,
                yes,
                checker: check.clone(),
                progress: Arc::new(Progress::new(true)),
            };
            let execution = ExecutionContext {
                cancellation: CancellationToken::new(),
                deadline: Instant::now() + Duration::from_secs(1),
            };
            assert!(!manual.ready(&[], true, &execution).await.unwrap());
            assert_eq!(check.calls.load(Ordering::SeqCst), 0);
        }
    }
}
