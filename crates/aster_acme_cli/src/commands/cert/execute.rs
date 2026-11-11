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

pub(super) fn options(local: &LocalArgs, http: &HttpArgs, account: Option<String>) -> AccountArgs {
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
    let progress = Arc::new(Progress::new(args.run.local.json));
    let interactive = terminal::interactive(args.run.local.json);
    super::interaction::complete(
        &mut args,
        interactive,
        &mut super::interaction::TerminalDomains,
    )?;
    let mut options = options(&args.run.local, &args.run.http, args.account.clone());
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    let selected = match &args.resume {
        Some(explicit) => {
            let records = store
                .list()
                .await?
                .into_iter()
                .filter(IssueRecord::unfinished)
                .collect::<Vec<_>>();
            let name = selection::certificate_name(
                &records,
                match explicit {
                    super::args::ResumeTarget::Choose => None,
                    super::args::ResumeTarget::Named(name) => Some(name.as_str()),
                },
                args.operation.as_deref(),
                options.json,
            )?;
            Some(selection::choose(
                records,
                &name,
                args.operation.as_deref(),
                selection::RequestSelection::Unfinished,
                options.json,
            )?)
        }
        None => None,
    };
    if let Some(record) = &selected {
        options.name = Some(record.account_name.clone());
    }
    let run = args.run.clone();
    let root = settings.data_dir.clone();
    let result = transact(
        settings,
        options,
        &store,
        Start::Issue {
            selected: selected.map(Box::new),
            args,
        },
        &run,
        RunMode::Single,
        progress,
    )
    .await?;
    crate::common::output::print_result(
        &render::result(&result, run.local.json, &root)?,
        run.local.json,
        crate::common::output::ResultPreceding::Progress,
    );
    Ok(())
}

pub(super) enum Start {
    Issue {
        selected: Option<Box<IssueRecord>>,
        args: IssueArgs,
    },
    Renew {
        name: CertificateName,
        expected_in_use: String,
        now: bool,
    },
}

pub(super) async fn transact(
    settings: CliSettings,
    options: AccountArgs,
    store: &CliIssueStore,
    start: Start,
    run: &super::args::RunArgs,
    mode: RunMode,
    progress: Arc<Progress>,
) -> CliResult<super::report::CertificateResult> {
    let context = settings.account(&options).await?;
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
    let mut session = match start {
        Start::Issue { selected, args } => {
            prepare_session(
                store,
                selected.map(|record| *record),
                &args,
                &context.name,
                &account,
                &progress,
            )
            .await?
        }
        Start::Renew {
            name,
            expected_in_use,
            now,
        } => {
            match store
                .prepare_renewal(&name, &expected_in_use, now, &account)
                .await
            {
                Ok(aster_acme_cli_storage::issuance::RenewalPreparation::Ready(session)) => session,
                Ok(aster_acme_cli_storage::issuance::RenewalPreparation::NotDue(record)) => {
                    return Ok(super::report::CertificateResult::NotDue(record));
                }
                Err(error) => return Err(error.into()),
            }
        }
    };
    progress.log.line(
        Level::Info,
        &format!(
            "Using CA: {} (account {})",
            context.directory.as_str(),
            context.name
        ),
    );
    let record = session.record().await?;
    let publication = PublicationState::from_record(&record);
    report_material(&context, &record, &progress)?;
    let foreground = Foreground {
        context: &context,
        options: &options,
        args: run,
        publication,
        mode,
        progress: progress.clone(),
    };
    let outcome = match foreground
        .run(IssueIdentity { account, signer }, session.as_mut())
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            match session.record().await {
                Ok(saved) if saved.finalize_rejection.is_some() => progress.log.line(Level::Warning, "The CA rejected this fixed CSR. Start a new cert issue with a supported --key-type; resume will retain this rejection."),
                _ => progress.log.line(Level::Info,&format!("Request retained. Resume with: aster-acme cert issue --resume '{}' --operation {}",record.name.as_str(),record.operation_id)),
            }
            return Err(error);
        }
    };
    Ok(super::report::CertificateResult::Issuance(outcome))
}

fn report_material(
    context: &CliContext,
    record: &IssueRecord,
    progress: &Progress,
) -> CliResult<()> {
    if record.renewal_of.is_some() {
        progress.log.line(
            Level::Info,
            &format!(
                "Renewing {} with {}",
                record.name.as_str(),
                record.key_algorithm.name()
            ),
        );
    }
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
    Ok(())
}

/// Batch cancellation and prompt policy are explicit, never inferred from JSON styling.
pub(super) enum RunMode {
    Single,
    Batch(CancellationToken),
}

struct Foreground<'a> {
    context: &'a CliContext,
    options: &'a AccountArgs,
    args: &'a super::args::RunArgs,
    publication: PublicationState,
    mode: RunMode,
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
        self.progress
            .protocol(client.directory(), &session.record().await?);
        let service = IssueService::new(client, identity)?.with_observer(self.progress.clone());
        let (cancellation, signal) = match &self.mode {
            RunMode::Single => {
                let cancellation = CancellationToken::new();
                let signal = tokio::spawn({
                    let cancellation = cancellation.clone();
                    async move {
                        if tokio::signal::ctrl_c().await.is_ok() {
                            cancellation.cancel();
                        }
                    }
                });
                (cancellation, Some(signal))
            }
            RunMode::Batch(cancellation) => (cancellation.clone(), None),
        };
        let execution = IssueExecution {
            context: ExecutionContext {
                cancellation,
                deadline: Instant::now() + Duration::from_secs(self.args.wait_timeout),
            },
            skip_dns_check: self.args.skip_dns_check,
            poll_interval: Duration::from_secs(2),
        };
        let dns = match session.record().await?.solver_id.as_str() {
            "manual_dns" => ManualDns {
                interactive: matches!(self.mode, RunMode::Single)
                    && terminal::interactive(self.options.json),
                publication: self.publication,
                yes: self.args.yes,
                checker: Arc::new(aster_acme_validation::dns01::visibility::DnsVisibility),
                progress: self.progress.clone(),
            },
            _ => return Err("The saved validation implementation is not supported.".into()),
        };
        let result = service.run(session, &dns, &execution).await;
        if let Some(signal) = signal {
            signal.abort();
        }
        Ok(result?)
    }
}

/// Existing CLI flags do not prove that manual validation material was ever saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationState {
    Fresh,
    SavedRequirements,
}

impl PublicationState {
    fn from_record(record: &IssueRecord) -> Self {
        match record
            .authorizations
            .iter()
            .find_map(|authorization| authorization.dns.as_ref())
        {
            Some(_) => Self::SavedRequirements,
            None => Self::Fresh,
        }
    }
}

struct ManualDns {
    interactive: bool,
    publication: PublicationState,
    yes: bool,
    checker: Arc<dyn DnsReadiness>,
    progress: Arc<Progress>,
}
#[async_trait]
impl DnsReadiness for ManualDns {
    async fn ready(
        &self,
        records: &[DnsRequirement],
        skip_dns_check: bool,
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        // A new scripted invocation must expose its fresh TXT values before any
        // acknowledgement. --yes only removes human confirmation, not publication.
        if matches!(self.publication, PublicationState::Fresh) && (self.yes || !self.interactive) {
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
            if skip_dns_check {
                Level::Warning
            } else {
                Level::Info
            },
            if skip_dns_check {
                "Skipping local DNS lookup (--skip-dns-check); proceeding to CA validation"
            } else {
                "Checking all required DNS TXT values"
            },
        );
        let ready = self
            .checker
            .ready(records, skip_dns_check, execution)
            .await?;
        if !ready {
            self.progress.log.line(
                Level::Warning,
                "Required DNS TXT values are not visible yet; the request is retained for resume",
            );
            self.progress.log.line(Level::Info, "You can use --skip-dns-check when resuming to skip local DNS visibility checks; the CA will still validate domain ownership.");
        }
        Ok(ready)
    }
}

pub(crate) async fn execute(command: CertCommand) -> CliResult<()> {
    match command {
        CertCommand::Issue(args) => issue(args).await,
        CertCommand::Renew(args) => super::renewal::execute(args).await,
        CertCommand::Remove {
            target,
            all,
            history,
            revoked,
            yes,
            local,
        } => {
            use super::removal::RemovalFilter;
            let filter = match (all, history, revoked) {
                (false, false, false) => RemovalFilter::Request,
                (true, false, false) => RemovalFilter::All,
                (false, true, false) => RemovalFilter::History,
                (false, false, true) => RemovalFilter::Revoked,
                _ => return Err("--all, --history and --revoked are mutually exclusive.".into()),
            };
            super::removal::execute(target, filter, yes, local).await
        }
        CertCommand::List {
            name,
            history,
            local,
        } => {
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
            let records = if history {
                records
            } else {
                selection::managed_records(records)?
            };
            println!("{}", render::list(&records, local.json)?);
            Ok(())
        }
        CertCommand::Show {
            target,
            history,
            verify,
            http,
            local,
        } => show(target, history, verify, http, local).await,
        CertCommand::Revoke {
            target,
            reason,
            yes,
            http,
            local,
        } => revoke(target, reason, yes, http, local).await,
    }
}

async fn show(
    target: super::args::SavedTargetArgs,
    history: bool,
    verify: bool,
    http: HttpArgs,
    local: LocalArgs,
) -> CliResult<()> {
    let options = options(&local, &http, None);
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    let mut record = selected_record(
        &store,
        &target,
        local.json,
        if history {
            selection::RequestSelection::Any
        } else {
            selection::RequestSelection::InUse
        },
    )
    .await?;
    if verify {
        let context = settings
            .account(&AccountArgs {
                name: Some(record.account_name.clone()),
                ..options
            })
            .await?;
        record =
            remote_operation(context, &http, &record, &store, RemoteOperation::Inspect).await?;
    }
    let view = if history || target.operation.is_some() {
        render::DetailView::Version
    } else {
        render::DetailView::InUse
    };
    println!("{}", render::show(&[record], local.json, verify, view)?);
    Ok(())
}

async fn revoke(
    target: super::args::SavedTargetArgs,
    reason: Option<aster_acme_protocol::revocation::RevocationReason>,
    yes: bool,
    http: HttpArgs,
    local: LocalArgs,
) -> CliResult<()> {
    let options = options(&local, &http, None);
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    let record = selected_record(
        &store,
        &target,
        local.json,
        selection::RequestSelection::Any,
    )
    .await?;
    // A confirmed local outcome needs neither an account key nor HTTP.
    let record = match record.revocation.state {
        aster_acme_core::revocation::RevocationState::Confirmed => record,
        aster_acme_core::revocation::RevocationState::NotRequested
        | aster_acme_core::revocation::RevocationState::Pending => {
            let context = settings
                .account(&AccountArgs {
                    name: Some(record.account_name.clone()),
                    ..options
                })
                .await?;
            remote_operation(
                context,
                &http,
                &record,
                &store,
                RemoteOperation::Revoke {
                    reason,
                    yes,
                    json: local.json,
                },
            )
            .await?
        }
    };
    println!("{}", render::revoked(&record, local.json)?);
    Ok(())
}

async fn selected_record(
    store: &CliIssueStore,
    target: &super::args::SavedTargetArgs,
    json: bool,
    mode: selection::RequestSelection,
) -> CliResult<IssueRecord> {
    let records = store.list().await?;
    let name = selection::certificate_name(
        &records,
        target
            .identity
            .name
            .as_deref()
            .or(target.identity.named_name.as_deref()),
        target.operation.as_deref(),
        json,
    )?;
    selection::choose(records, &name, target.operation.as_deref(), mode, json)
}

enum RemoteOperation {
    Inspect,
    Revoke {
        reason: Option<aster_acme_protocol::revocation::RevocationReason>,
        yes: bool,
        json: bool,
    },
}

async fn remote_operation(
    context: CliContext,
    http: &HttpArgs,
    record: &IssueRecord,
    store: &CliIssueStore,
    operation: RemoteOperation,
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
    match &operation {
        RemoteOperation::Inspect => {}
        RemoteOperation::Revoke { reason, yes, json } => {
            use aster_acme_core::revocation::{RevocationAction, revocation_action};
            let in_use = session.record().await?;
            match revocation_action(
                matches!(
                    in_use.phase,
                    aster_acme_core::workflow::IssuancePhase::Completed
                ),
                in_use.revocation.state,
                in_use.revocation.reason == reason.or(in_use.revocation.reason),
            ) {
                RevocationAction::NotIssued => {
                    return Err("Only an issued certificate can be revoked.".into());
                }
                RevocationAction::ReasonConflict => {
                    return Err("An unconfirmed revocation must retain its original reason.".into());
                }
                RevocationAction::AlreadyConfirmed => return Ok(in_use),
                RevocationAction::Submit => {}
            }
            let reason = reason
                .or(in_use.revocation.reason)
                .map_or_else(|| "not specified".into(), |reason| reason.to_string());
            terminal::confirm_action(
                &format!(
                    "Permanently revoke certificate\n  Name: {}\n  Request: {}\n  Domains: {}\n  CA: {}\n  Reason: {}\n\nThis cannot be undone. Local certificate files will be retained.\nA deployed copy must be replaced separately.",
                    in_use.name.as_str(),
                    in_use.operation_id,
                    in_use
                        .identifiers
                        .iter()
                        .map(DnsIdentifier::value)
                        .collect::<Vec<_>>()
                        .join(", "),
                    in_use.directory.as_str(),
                    reason
                ),
                "Revoke this certificate?",
                *yes,
                *json,
            )?;
        }
    }
    let transport = context.transport_options(&AccountArgs {
        user_agent: http.user_agent.clone(),
        timeout: http.timeout,
        ..AccountArgs::default()
    })?;
    let client = Arc::new(AcmeClient::discover(context.directory, transport).await?);
    let identity = IssueIdentity { account, signer };
    match operation {
        RemoteOperation::Inspect => Ok(IssueService::new(client, identity)?
            .inspect(session.as_mut())
            .await?),
        RemoteOperation::Revoke { reason, .. } => Ok(
            aster_acme::revocation::RevocationService::new(client, identity)
                .revoke(session.as_mut(), reason)
                .await?,
        ),
    }
}

fn request(args: &IssueArgs, account: &str) -> CliResult<IssueRequest> {
    match args.challenge {
        Some(super::args::Challenge::ManualDns) => {}
        None => return Err("Specify -c/--challenge for a new certificate.".into()),
    }
    let identifiers = args.domain.clone();
    let primary = identifiers
        .first()
        .ok_or("At least one domain is required.")?;
    Ok(IssueRequest {
        key_algorithm: args.key_algorithm,
        name: match args.name.as_deref() {
            Some(name) => CertificateName::new(name)?,
            None => CertificateName::generated(primary)?,
        },
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
        progress.log.line(
            Level::Info,
            &format!(
                "Certificate key type: {} (saved)",
                record.key_algorithm.name()
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
        progress.log.line(
            Level::Info,
            &format!("Certificate key type: {}", request.key_algorithm.name()),
        );
        progress
            .log
            .line(Level::Info, "Creating certificate key and fixed CSR");
        allocate_certificate(
            store,
            request,
            account,
            if args.name.is_some() {
                Naming::Explicit
            } else {
                Naming::Automatic
            },
        )
        .await?
    };
    Ok(session)
}

/// Only automatic naming retries a typed allocation collision; other failures propagate.
#[derive(Clone, Copy)]
enum Naming {
    Explicit,
    Automatic,
}

async fn allocate_certificate(
    store: &dyn IssueStore,
    mut request: IssueRequest,
    account: &aster_acme::account::AccountRecord,
    naming: Naming,
) -> Result<Box<dyn IssueSession>, IssueError> {
    for _ in 0..16 {
        match store.create(&request, account).await {
            Err(IssueError::NameAlreadyExists(_)) if matches!(naming, Naming::Automatic) => {
                request.name = CertificateName::generated(
                    request
                        .identifiers
                        .first()
                        .ok_or(IssueError::InvalidInput("missing primary domain"))?,
                )?;
            }
            result => return result,
        }
    }
    Err(IssueError::InvalidInput(
        "automatic certificate name allocation exceeded its collision budget",
    ))
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
            skip_dns_check: bool,
            execution: &ExecutionContext,
        ) -> Result<bool, IssueError> {
            execution.check().map_err(|_| IssueError::Interrupted)?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.forced.store(skip_dns_check, Ordering::SeqCst);
            // Represent a TXT value which has not propagated: --yes must preserve it.
            Ok(skip_dns_check)
        }
    }

    #[tokio::test]
    async fn yes_bypasses_terminal_confirmation_but_not_dns_readiness() {
        for interactive in [false, true] {
            for skip_dns_check in [false, true] {
                let check = Arc::new(Check::default());
                let manual = ManualDns {
                    interactive,
                    publication: PublicationState::SavedRequirements,
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
                    manual.ready(&records, skip_dns_check, &execution),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(result, skip_dns_check);
                assert_eq!(check.calls.load(Ordering::SeqCst), 1);
                assert_eq!(check.forced.load(Ordering::SeqCst), skip_dns_check);
                execution.cancellation.cancel();
                assert!(matches!(
                    manual.ready(&records, skip_dns_check, &execution).await,
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
                publication: PublicationState::Fresh,
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
    fn allocation_account() -> aster_acme::account::AccountRecord {
        serde_json::from_value(serde_json::json!({
            "account_id":"test-account","directory_url":"https://ca.example/directory","account_url":"https://ca.example/account",
            "key_thumbprint":"test-key","contacts":[],"server_contacts":null,"last_status":"valid","deactivation":"not_requested",
            "key_rotation":null,"accepted_terms_url":null,"state":"registered"
        })).unwrap()
    }

    #[tokio::test]
    async fn automatic_allocation_retries_only_name_collisions_while_explicit_names_refuse_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
        let account = allocation_account();
        let request = IssueRequest {
            key_algorithm: aster_acme::issuance::key_algorithm::CertificateKeyAlgorithm::EcdsaP256,
            name: CertificateName::new("example.com-collision").unwrap(),
            identifiers: vec![DnsIdentifier::new("example.com").unwrap()],
            account_name: "default".into(),
        };
        let initial = store.create(&request, &account).await.unwrap();
        let initial_record = initial.record().await.unwrap();
        let mut observation = initial_record.clone();
        observation.creation_submitted = true;
        assert_eq!(
            PublicationState::from_record(&observation),
            PublicationState::Fresh
        );
        observation.authorizations.push(serde_json::from_value(serde_json::json!({
            "url":"https://ca.example/authz","resource":{"identifier":{"type":"dns","value":"example.com"},"status":"pending","challenges":[]},
            "challenge_url":"https://ca.example/challenge","dns":{"name":"_acme-challenge.example.com","value":"saved"},"cleanup_pending":true,"acknowledgement":"not_submitted"
        })).unwrap());
        assert_eq!(
            PublicationState::from_record(&observation),
            PublicationState::SavedRequirements
        );
        drop(initial);
        assert!(matches!(
            allocate_certificate(&store, request.clone(), &account, Naming::Explicit).await,
            Err(IssueError::NameAlreadyExists(_))
        ));
        let generated = allocate_certificate(&store, request, &account, Naming::Automatic)
            .await
            .unwrap();
        let actual = generated.record().await.unwrap();
        assert_ne!(actual.name, initial_record.name);
        assert!(actual.name.as_str().starts_with("example.com-"));
        assert_eq!(actual.name.as_str().len(), "example.com-".len() + 8);
        assert_eq!(store.list().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn allocation_propagates_unsafe_storage_errors_without_creating_another_random_name() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
        let account = allocation_account();
        let request = IssueRequest {
            key_algorithm: aster_acme::issuance::key_algorithm::CertificateKeyAlgorithm::EcdsaP256,
            name: CertificateName::new("example.com-existing").unwrap(),
            identifiers: vec![DnsIdentifier::new("example.com").unwrap()],
            account_name: "default".into(),
        };
        drop(store.create(&request, &account).await.unwrap());
        let config = temp.path().join("certs/example.com-existing/cert.toml");
        let before = std::fs::read(&config).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            allocate_certificate(&store, request, &account, Naming::Automatic).await,
            Err(IssueError::Store(_))
        ));
        assert_eq!(
            std::fs::read_dir(temp.path().join("certs"))
                .unwrap()
                .count(),
            1
        );
        assert_eq!(std::fs::read(config).unwrap(), before);
    }
    #[tokio::test]
    async fn renew_not_due_uses_saved_definition_and_never_contacts_ca_or_creates_a_generation() {
        use rcgen::{CertificateParams, Issuer, KeyPair};
        let temp = tempfile::tempdir().unwrap();
        let ca = aster_acme_protocol::url::AcmeUrl::new("https://127.0.0.1:1/directory").unwrap();
        let accounts = aster_acme_cli_storage::CliAccountStore::open(
            temp.path(),
            "default",
            Duration::from_secs(1),
        )
        .unwrap();
        let signer = accounts.signer(&ca, "default", true).await.unwrap();
        let thumb = signer.jwk().unwrap().thumbprint().unwrap();
        let mut account = accounts.load(&ca, &thumb).await.unwrap().unwrap();
        account.state = aster_acme_core::account::AccountRecordState::Registered;
        account.last_status = Some(aster_acme_core::protocol::AccountStatus::Valid);
        account.account_url =
            Some(aster_acme_protocol::url::AcmeUrl::new("https://127.0.0.1:1/account").unwrap());
        accounts.save(&account).await.unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
        let request = IssueRequest {
            name: CertificateName::new("web").unwrap(),
            identifiers: vec![DnsIdentifier::new("example.com").unwrap()],
            key_algorithm: aster_acme::issuance::key_algorithm::CertificateKeyAlgorithm::EcdsaP384,
            account_name: "default".into(),
        };
        let session = store.create(&request, &account).await.unwrap();
        let mut record = session.record().await.unwrap();
        let generation = temp.path().join("certs/web").join(record.generation_name());
        let key_bytes = std::fs::read(generation.join("private-key.pk8")).unwrap();
        let key = KeyPair::try_from(key_bytes.as_slice()).unwrap();
        let issuer = Issuer::new(
            CertificateParams::new(Vec::<String>::new()).unwrap(),
            KeyPair::generate().unwrap(),
        );
        let mut params = CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(89);
        record.phase = aster_acme_core::workflow::IssuancePhase::Completed;
        let chain = params.signed_by(&key, &issuer).unwrap().pem();
        session.complete(&record, chain.as_bytes()).await.unwrap();
        drop(session);
        let journal = std::fs::read(generation.join("operation.toml")).unwrap();
        let definition = std::fs::read(temp.path().join("certs/web/cert.toml")).unwrap();
        let args = super::super::args::RenewArgs {
            target: super::super::args::CertificateNameArgs {
                name: Some("web".into()),
                named_name: None,
            },
            now: false,
            all: false,
            run: super::super::args::RunArgs {
                yes: false,
                skip_dns_check: false,
                wait_timeout: 2,
                http: HttpArgs::default(),
                local: LocalArgs {
                    data_dir: Some(temp.path().into()),
                    json: true,
                },
            },
        };
        super::super::renewal::execute(args).await.unwrap();
        assert_eq!(store.list().await.unwrap().len(), 1);
        assert_eq!(
            std::fs::read(generation.join("operation.toml")).unwrap(),
            journal
        );
        assert_eq!(
            std::fs::read(temp.path().join("certs/web/cert.toml")).unwrap(),
            definition
        );
        assert_eq!(
            std::fs::read(generation.join("private-key.pk8")).unwrap(),
            key_bytes
        );
    }
}
