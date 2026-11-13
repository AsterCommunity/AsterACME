//! CLI execution wires account leases, generation sessions, and manual DNS UI into the library.
use crate::commands::cert::progress::Progress;
use crate::commands::cert::{
    args::{CertCommand, IssueArgs},
    render, selection,
};
use crate::common::args::{HttpArgs, LocalArgs};
use crate::common::output::MessageKind;
use crate::{
    commands::account::args::AccountArgs,
    common::{
        context::{CliContext, CliSettings},
        error::CliResult,
        terminal,
    },
};
use aster_acme::issuance::service::IssueService;
use aster_acme::storage::account::{AccountKeyStore, AccountStore};
use aster_acme::storage::issuance::{IssueSession, IssueStore};
use aster_acme::storage::query::{IssueQuery, IssueView, SimilarIssue};
use aster_acme::{
    identifier::DnsIdentifier,
    issuance::{
        CertificateName, IssueError, IssueExecution, IssueIdentity, IssueOutcome, IssueRecord,
        IssueRequest,
    },
    solver::ExecutionContext,
};
use aster_acme_cli_storage::issuance::CliIssueStore;
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
        request_timeout: http.request_timeout,
        ..AccountArgs::default()
    }
}

async fn issue(
    mut args: IssueArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<super::report::CertificateReport> {
    let interactive = terminal::interactive(args.run.local.json);
    super::interaction::complete(
        &mut args,
        interactive,
        &mut super::interaction::TerminalPrompts(&cli.output),
    )?;
    let mut options = options(&args.run.local, &args.run.http, args.account.clone());
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    let mut proposed = if args.resume.is_none() {
        let context = settings.clone().account(&options).await?;
        context.require_account().await?;
        let account = context
            .store
            .metadata()
            .await?
            .ok_or("No registered account exists.")?;
        Some((request(&args, &context.name)?, account))
    } else {
        None
    };

    let selected = select_saved_issue(&args, &store, proposed.as_ref(), cli).await?;
    if let Some(record) = &selected {
        options.name = Some(record.account_name.clone());
    }
    let run = args.run.clone();
    let root = settings.data_dir.clone();
    let input = if let Some(record) = selected {
        IssueInput::Resume(Box::new(record))
    } else {
        IssueInput::New {
            request: proposed.take().ok_or("Missing new request definition.")?.0,
            naming: if args.name.is_some() {
                Naming::Explicit
            } else {
                Naming::Automatic
            },
        }
    };
    let result = transact(
        settings,
        options,
        &store,
        Start::Issue(input),
        &run,
        RunMode::Single(CancellationToken::new()),
        cli,
    )
    .await?;
    Ok(super::report::CertificateReport::Result {
        result,
        data_dir: root,
    })
}

async fn select_saved_issue(
    args: &IssueArgs,
    store: &CliIssueStore,
    proposed: Option<&(IssueRequest, aster_acme::account::AccountRecord)>,
    cli: &crate::common::context::CommandContext,
) -> CliResult<Option<IssueRecord>> {
    Ok(match &args.resume {
        Some(explicit) => {
            let query = IssueQuery {
                name: match explicit {
                    super::args::ResumeTarget::Choose => None,
                    super::args::ResumeTarget::Named(name) => Some(CertificateName::new(name)?),
                },
                unfinished: Some(true),
                operation_id: args.operation.clone(),
                resumable: Some(true),
                ..IssueQuery::default()
            };
            let records = store.query(query.clone()).await?;
            if records.is_empty() && query.name.is_some() {
                let inventory = store
                    .query(IssueQuery {
                        resumable: None,
                        ..query
                    })
                    .await?;
                selection::check_explicit_resume(&inventory, explicit, args.operation.as_deref())?;
            }
            let name = selection::certificate_name(
                &records,
                match explicit {
                    super::args::ResumeTarget::Choose => None,
                    super::args::ResumeTarget::Named(name) => Some(name.as_str()),
                },
                args.operation.as_deref(),
                selection::CertificateLabel::Standard,
                &cli.output,
            )?;
            Some(selection::choose(
                records,
                &name,
                args.operation.as_deref(),
                &cli.output,
            )?)
        }
        None => {
            if args.name.is_some() {
                None
            } else {
                let (request, account) = proposed.ok_or("Missing new request definition.")?;
                let now = time::OffsetDateTime::now_utc();
                let candidates = store
                    .query(IssueQuery {
                        unfinished: Some(true),
                        similar: Some(SimilarIssue {
                            request: request.clone(),
                            account: account.clone(),
                            now,
                        }),
                        ..IssueQuery::default()
                    })
                    .await?
                    .into_iter()
                    .collect();
                super::similar::choose(candidates, args.if_similar_order, &cli.output)?
            }
        }
    })
}

pub(super) enum IssueInput {
    // A saved journal is large; keep it off the transaction frame. New input holds
    // only the desired definition, not the entire parsed CLI/output/HTTP args.
    Resume(Box<IssueRecord>),
    New {
        request: IssueRequest,
        naming: Naming,
    },
}

pub(super) enum Start {
    Issue(IssueInput),
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
    cli: &crate::common::context::CommandContext,
) -> CliResult<super::report::CertificateResult> {
    let progress = Arc::new(Progress::new(cli.output.clone()));
    let context = settings.account(&options).await?;
    let (operation_timeout, _, _) = run.limits(&context.config);
    let cancellation = match &mode {
        RunMode::Single(token) | RunMode::Batch(token) => token.clone(),
    };
    let _signal = matches!(mode, RunMode::Single(_))
        .then(|| crate::common::signal::InterruptGuard::new(cancellation.clone()));
    let execution = ExecutionContext {
        cancellation,
        deadline: Instant::now() + Duration::from_secs(operation_timeout),
    };
    let signer = context
        .store
        .signer(
            &context.directory,
            &context.name,
            aster_acme::storage::account::KeyAccess::Existing,
        )
        .await?;
    let thumbprint = signer.jwk()?.thumbprint()?;
    // Lock order is account, then certificate. Rotation/deactivation/removal cannot
    // change the account identity during challenge material derivation or signing.
    let _account_lease = context
        .store
        .lock_account(&context.directory, &thumbprint)
        .await
        .map_err(|error| match error.kind {
            aster_acme::storage::account::AccountStoreErrorKind::LockUnavailable => {
                IssueError::LeaseUnavailable("account", error.to_string())
            }
            aster_acme::storage::account::AccountStoreErrorKind::Other => IssueError::Store(error),
        })?;
    let account = context
        .store
        .load(&context.directory, &thumbprint)
        .await?
        .ok_or("No registered account exists.")?;
    let mut session = match start {
        Start::Issue(input) => prepare_session(store, input, &account, &progress).await?,
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
    let record = session.record().await?;
    report_material(&context, &record, &progress)?;
    let foreground = Foreground {
        context: &context,
        options: &options,
        args: run,
        mode,
        cli,
        progress: progress.clone(),
        execution: execution.clone(),
    };
    let outcome = match foreground
        .run(IssueIdentity { account, signer }, session.as_mut())
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            return report_issue_failure(session.as_mut(), &record, &progress, &execution, error)
                .await;
        }
    };
    drop(session);
    Ok(attach_deployment_results(outcome, store, &execution).await)
}

async fn report_issue_failure(
    session: &mut dyn IssueSession,
    record: &IssueRecord,
    progress: &Progress,
    execution: &ExecutionContext,
    error: Box<dyn std::error::Error>,
) -> CliResult<super::report::CertificateResult> {
    let saved = session.record().await?;
    if saved.renewal_of.is_some() && saved.unfinished() && !execution.cancellation.is_cancelled() {
        let blocked_reason = if saved.new_order_intent_saved
            && saved.order_url.is_none()
            && saved.creation_failure.is_none()
        {
            Some("newOrder may have been accepted but no Location was saved".into())
        } else if saved
            .creation_failure
            .as_ref()
            .is_some_and(|failure| failure.status == 408 || failure.status >= 500)
        {
            Some("newOrder response does not establish whether the CA accepted the order".into())
        } else {
            None
        };
        let ca_retry_at = saved
            .creation_failure
            .as_ref()
            .and_then(|failure| failure.retry_at)
            .or_else(|| {
                (saved.poll_wait_source == Some(aster_acme::issuance::PollWaitSource::RetryAfter))
                    .then_some(saved.next_poll_at)
                    .flatten()
            });
        let retry = session
            .record_renewal_failure(time::OffsetDateTime::now_utc(), ca_retry_at, blocked_reason)
            .await?;
        report_renewal_retry(progress, &saved, &retry);
    }
    if matches!(
        error.downcast_ref::<IssueError>(),
        Some(IssueError::InvalidOrder { .. })
    ) {
        progress.output.progress(MessageKind::Warning, "Invalid order retained for inspection. Correct validation and start a new cert issue; this order cannot be resumed.");
    } else if matches!(
        error.downcast_ref::<IssueError>(),
        Some(IssueError::CreationUncertain)
    ) {
        progress.output.progress(MessageKind::Warning, "Order creation was interrupted before its URL was saved. Inspect the retained request before explicitly starting an independent one; repeating resume cannot recover a missing URL.");
    } else if saved.creation_failure.is_some() {
        progress.output.progress(MessageKind::Warning, "newOrder error response retained for inspection; no order status was observed. Inspect cert show and the CA problem before explicitly starting a new request; this response cannot be resumed as an order.");
    } else if saved.authorization_failure().is_some() {
        progress.output.progress(MessageKind::Warning, "Failed authorization retained for inspection. Correct validation and start a new cert issue; this authorization cannot be resumed.");
    } else if saved.finalize_rejection.is_some() {
        progress.output.progress(MessageKind::Warning, "The CA rejected this fixed CSR. Start a new cert issue with a supported --key-type; resume will retain this rejection.");
    } else {
        progress.output.progress(
            MessageKind::Info,
            &format!(
                "Request retained. Resume with: aster-acme cert issue --resume '{}' --operation {}",
                record.name.as_str(),
                record.operation_id
            ),
        );
    }
    Err(error)
}

pub(super) fn report_renewal_retry(
    progress: &Progress,
    record: &IssueRecord,
    retry: &aster_acme::issuance::RenewalRetryState,
) {
    match (&retry.blocked_reason, retry.retry_at) {
        (Some(reason), _) => progress.output.progress(
            MessageKind::Warning,
            &format!("Automatic renewal blocked for {}: {reason}", record.name),
        ),
        (None, Some(at)) => progress.output.progress(
            MessageKind::Info,
            &format!(
                "Automatic renewal retry after failure {} for {} scheduled at {}",
                retry.failures,
                record.name,
                crate::common::time::timestamp(Some(
                    retry.ca_retry_at.map_or(at, |ca_at| at.max(ca_at))
                ))
            ),
        ),
        (None, None) => progress.output.progress(
            MessageKind::Warning,
            &format!(
                "Automatic renewal for {} has no safe retry deadline",
                record.name
            ),
        ),
    }
}

async fn attach_deployment_results(
    outcome: IssueOutcome,
    store: &CliIssueStore,
    execution: &ExecutionContext,
) -> super::report::CertificateResult {
    let deployment_results = match &outcome {
        IssueOutcome::Completed { record, .. } => {
            let name = record.name.clone();
            let generation = record.generation_name();
            super::deployment::after_issuance(store, &name, &generation, execution).await
        }
        IssueOutcome::ActionRequired { .. } => (Vec::new(), Vec::new()),
    };
    let (deployments, deployment_events) = deployment_results;
    if deployments.is_empty() && deployment_events.is_empty() {
        super::report::CertificateResult::Issuance(outcome)
    } else {
        super::report::CertificateResult::Issued {
            outcome,
            deployments,
            deployment_events,
        }
    }
}

fn report_material(
    context: &CliContext,
    record: &IssueRecord,
    progress: &Progress,
) -> CliResult<()> {
    if record.renewal_of.is_some() {
        progress.output.progress(
            MessageKind::Info,
            &format!(
                "Renewing {} with {}",
                record.name.as_str(),
                record.key_algorithm.name()
            ),
        );
    }
    progress.output.progress(
        MessageKind::Info,
        &format!(
            "Using CA: {} (account {})",
            context.directory.as_str(),
            context.name
        ),
    );
    let root = context
        .config_path
        .parent()
        .ok_or("Missing data directory.")?;
    let generation = root
        .join("certs")
        .join(record.name.as_str())
        .join(record.generation_name());
    progress.output.progress(
        MessageKind::Info,
        &format!(
            "Certificate key: {}",
            generation.join("private-key.pk8").display()
        ),
    );
    Ok(())
}

/// Batch cancellation and prompt policy are explicit, never inferred from JSON styling.
pub(super) enum RunMode {
    Single(CancellationToken),
    Batch(CancellationToken),
}

struct Foreground<'a> {
    context: &'a CliContext,
    options: &'a AccountArgs,
    args: &'a super::args::RunArgs,
    mode: RunMode,
    cli: &'a crate::common::context::CommandContext,
    progress: Arc<Progress>,
    execution: ExecutionContext,
}

impl Foreground<'_> {
    async fn run(
        &self,
        identity: IssueIdentity,
        session: &mut dyn IssueSession,
    ) -> CliResult<IssueOutcome> {
        let saved = session.record().await?;
        let solver = super::validation::adapter(
            &saved,
            matches!(self.mode, RunMode::Single(_)) && terminal::interactive(self.options.json),
            self.args.yes,
            self.progress.clone(),
        )?;
        #[cfg(feature = "precheck")]
        let solver = crate::commands::cert::precheck::with_validation(
            solver,
            self.cli.http.clone(),
            self.progress.clone(),
        );
        let workflow = aster_acme::issuance::workflow::Workflow::new(
            self.cli.http.clone(),
            self.context.directory.clone(),
            self.context.transport_options(self.options)?,
        )?
        .with_observer(self.progress.clone());
        let (_, max_polls, poll_interval) = self.args.limits(&self.context.config);
        let execution = IssueExecution {
            max_polls,
            context: self.execution.clone(),
            poll_interval: Duration::from_secs(poll_interval),
        };
        #[cfg(feature = "precheck")]
        let result = {
            let check = aster_acme_validation::caa::order::OrderCaa::default();
            let observer =
                crate::commands::cert::precheck::caa::Display::new(&saved, &self.progress);
            let stage = aster_acme::precheck::order::Stage::new(&check).with_observer(&observer);
            workflow
                .run_with_precheck(identity, session, solver.as_ref(), &execution, &stage)
                .await
        };
        #[cfg(not(feature = "precheck"))]
        let result = workflow
            .run(identity, session, solver.as_ref(), &execution)
            .await;
        if matches!(result, Err(IssueError::Interrupted))
            && self.execution.cancellation.is_cancelled()
        {
            return Err(Box::new(terminal::Canceled));
        }
        Ok(result?)
    }
}

pub(crate) async fn execute(
    command: CertCommand,
    cli: &crate::common::context::CommandContext,
) -> CliResult<super::report::CertificateReport> {
    match command {
        CertCommand::Issue(args) => issue(args, cli).await,
        CertCommand::Renew(args) => super::renewal::execute(args, cli).await,
        CertCommand::Deploy(args) => {
            super::deployment::execute(args, cli, CancellationToken::new()).await
        }
        CertCommand::Remove {
            target,
            all,
            history,
            revoked,
            failed,
            yes,
            local,
        } => {
            use crate::commands::cert::removal::RemovalFilter;
            let filter = match (all, history, revoked, failed) {
                (false, false, false, false) => RemovalFilter::Request,
                (true, false, false, false) => RemovalFilter::All,
                (false, true, false, false) => RemovalFilter::History,
                (false, false, true, false) => RemovalFilter::Revoked,
                (false, false, false, true) => RemovalFilter::Failed,
                _ => {
                    return Err(
                        "--all, --history, --revoked and --failed are mutually exclusive.".into(),
                    );
                }
            };
            super::removal::execute(target, filter, yes, local, cli).await
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
                .query(IssueQuery {
                    name: filter,
                    view: if history {
                        IssueView::All
                    } else {
                        IssueView::Managed
                    },
                    ..IssueQuery::default()
                })
                .await?;
            Ok(super::report::CertificateReport::List(records))
        }
        CertCommand::Show {
            target,
            history,
            verify,
            http,
            local,
        } => show(target, history, verify, http, local, cli).await,
        CertCommand::Revoke(args) => crate::commands::cert::revocation::execute(args, cli).await,
    }
}

async fn show(
    target: super::args::SavedTargetArgs,
    history: bool,
    verify: bool,
    http: HttpArgs,
    local: LocalArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<super::report::CertificateReport> {
    let options = options(&local, &http, None);
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    let mut record = selected_record(
        &store,
        &target,
        cli,
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
        record = inspect_remote(context, &http, &record, &store, cli).await?;
    }
    let view = if history || target.operation.is_some() {
        render::DetailView::Version
    } else {
        render::DetailView::InUse
    };
    Ok(super::report::CertificateReport::Show {
        record: Box::new(record),
        verified: verify,
        view,
    })
}

pub(super) async fn selected_record(
    store: &CliIssueStore,
    target: &super::args::SavedTargetArgs,
    cli: &crate::common::context::CommandContext,
    mode: selection::RequestSelection,
) -> CliResult<IssueRecord> {
    let query = IssueQuery {
        name: target
            .identity
            .name
            .as_deref()
            .or(target.identity.named_name.as_deref())
            .map(CertificateName::new)
            .transpose()?,
        operation_id: target.operation.clone(),
        unfinished: if matches!(mode, selection::RequestSelection::Completed) {
            Some(false)
        } else {
            None
        },
        view: if matches!(mode, selection::RequestSelection::InUse) && target.operation.is_none() {
            IssueView::CurrentOrUnfinished
        } else {
            IssueView::All
        },
        ..IssueQuery::default()
    };
    let records = store.query(query).await?;
    let name = selection::certificate_name(
        &records,
        target
            .identity
            .name
            .as_deref()
            .or(target.identity.named_name.as_deref()),
        target.operation.as_deref(),
        selection::CertificateLabel::Standard,
        &cli.output,
    )?;
    selection::choose(records, &name, target.operation.as_deref(), &cli.output)
}

async fn inspect_remote(
    context: CliContext,
    http: &HttpArgs,
    record: &IssueRecord,
    store: &CliIssueStore,
    cli: &crate::common::context::CommandContext,
) -> CliResult<IssueRecord> {
    let signer = context
        .store
        .signer(
            &context.directory,
            &context.name,
            aster_acme::storage::account::KeyAccess::Existing,
        )
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
        request_timeout: http.request_timeout,
        ..AccountArgs::default()
    })?;
    let client = Arc::new(cli.http.discover(context.directory, transport).await?);
    let identity = IssueIdentity { account, signer };
    Ok(IssueService::new(client, identity)?
        .inspect(session.as_mut())
        .await?)
}

fn request(args: &IssueArgs, account: &str) -> CliResult<IssueRequest> {
    let method = args
        .challenge
        .ok_or("Specify -c/--challenge for a new certificate.")?;
    let solver_config =
        super::validation::configuration(method, args.webroot.as_deref(), args.listen_address)?;
    let identifiers = args.domain.clone();
    let primary = identifiers
        .first()
        .ok_or("At least one domain is required.")?;
    let request = IssueRequest {
        challenge: method.kind(),
        solver_id: method.id().into(),
        solver_config,
        key_algorithm: args.key_algorithm,
        name: match args.name.as_deref() {
            Some(name) => CertificateName::new(name)?,
            None => CertificateName::generated(primary)?,
        },
        identifiers,
        account_name: account.into(),
    };
    request.validate()?;
    Ok(request)
}

// Resolve recovery and new-generation creation together with their user-visible intent.
async fn prepare_session(
    store: &CliIssueStore,
    input: IssueInput,
    account: &aster_acme::account::AccountRecord,
    progress: &Progress,
) -> CliResult<Box<dyn IssueSession>> {
    let session = match input {
        IssueInput::Resume(record) => {
            progress.output.progress(
                MessageKind::Info,
                &format!(
                    "Resuming {} requested at {}",
                    record.name.as_str(),
                    crate::common::time::timestamp(Some(record.created_at))
                ),
            );
            progress.output.progress(
                MessageKind::Info,
                &format!(
                    "Certificate key type: {} (saved)",
                    record.key_algorithm.name()
                ),
            );
            store.open(&record.name, &record.operation_id).await?
        }
        IssueInput::New { request, naming } => {
            progress.output.progress(
                MessageKind::Info,
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
            progress.output.progress(
                MessageKind::Info,
                &format!("Certificate key type: {}", request.key_algorithm.name()),
            );
            progress.output.progress(
                MessageKind::Info,
                &format!(
                    "Creating certificate key and fixed CSR for {}",
                    request.name.as_str()
                ),
            );
            allocate_certificate(store, request, account, naming).await?
        }
    };
    Ok(session)
}

/// Only automatic naming retries a typed allocation collision; other failures propagate.
#[derive(Clone, Copy)]
pub(super) enum Naming {
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
    use crate::commands::cert::execute::*;

    #[tokio::test]
    async fn renewal_deadline_enters_backoff_but_user_cancellation_does_not() {
        use rcgen::{CertificateParams, Issuer, KeyPair};
        for cancelled in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
            let account = allocation_account();
            let request = IssueRequest {
                name: CertificateName::new("deadline").unwrap(),
                identifiers: vec![DnsIdentifier::new("example.com").unwrap()],
                account_name: "default".into(),
                key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
                challenge: aster_acme::challenge::ChallengeKind::Dns01,
                solver_id: "manual_dns".into(),
                solver_config: serde_json::json!({}),
            };
            let session = store.create(&request, &account).await.unwrap();
            let mut current = session.record().await.unwrap();
            let key = zeroize::Zeroizing::new(
                std::fs::read(
                    temp.path()
                        .join("certs/deadline")
                        .join(current.generation_name())
                        .join("private-key.pk8"),
                )
                .unwrap(),
            );
            let key = KeyPair::try_from(key.as_slice()).unwrap();
            let issuer = Issuer::new(
                CertificateParams::new(Vec::<String>::new()).unwrap(),
                KeyPair::generate().unwrap(),
            );
            let chain = CertificateParams::new(vec!["example.com".to_owned()])
                .unwrap()
                .signed_by(&key, &issuer)
                .unwrap()
                .pem();
            current.phase = aster_acme_core::workflow::IssuancePhase::Completed;
            let current = session.complete(&current, chain.as_bytes()).await.unwrap();
            drop(session);
            let mut attempt = store.renew(&current.name, &account).await.unwrap();
            let record = attempt.record().await.unwrap();
            let execution = ExecutionContext {
                cancellation: CancellationToken::new(),
                deadline: Instant::now(),
            };
            if cancelled {
                execution.cancellation.cancel();
            }
            let progress = Progress::new(crate::common::session::OutputSession::new(true));
            let error = report_issue_failure(
                attempt.as_mut(),
                &record,
                &progress,
                &execution,
                Box::new(IssueError::Interrupted),
            )
            .await
            .err()
            .unwrap();
            assert!(error.is::<IssueError>());
            drop(attempt);
            let saved = store
                .open_observation(&current.name, &current.operation_id)
                .await
                .unwrap()
                .record()
                .await
                .unwrap();
            assert_eq!(saved.renewal_retry.is_some(), !cancelled);
            if let Some(retry) = saved.renewal_retry {
                assert_eq!(retry.failures, 1);
            }
        }
    }
    fn allocation_account() -> aster_acme::account::AccountRecord {
        serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p256","account_id":"test-account","directory_url":"https://ca.example/directory","account_url":"https://ca.example/account",
            "key_thumbprint":"test-key","contacts":[],"server_contacts":null,"last_status":"valid","deactivation":"not_requested",
            "key_rotation":null,"accepted_terms_url":null,"state":"registered"
        })).unwrap()
    }

    #[tokio::test]
    async fn renewal_material_logs_name_before_ca_for_each_batch_item() {
        use aster_acme::issuance::progress::{IssueEvent, IssueObserver};
        let temp = tempfile::tempdir().unwrap();
        let options = AccountArgs {
            data_dir: Some(temp.path().into()),
            ca_directory: Some("https://ca.example/directory".into()),
            ..AccountArgs::default()
        };
        let context = CliSettings::load(&options)
            .await
            .unwrap()
            .account(&options)
            .await
            .unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
        for json in [false, true] {
            let (output, stdout, stderr) = crate::common::session::tests::session(json);
            let progress = Progress::new(output);
            for suffix in ["first", "second"] {
                let name = format!("cdn.example.com-{suffix}-{json}");
                let request = IssueRequest {
                    name: CertificateName::new(&name).unwrap(),
                    identifiers: vec![DnsIdentifier::new("cdn.example.com").unwrap()],
                    account_name: "default".into(),
                    key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
                    challenge: aster_acme::challenge::ChallengeKind::Dns01,
                    solver_id: "manual_dns".into(),
                    solver_config: serde_json::json!({}),
                };
                let session = store.create(&request, &allocation_account()).await.unwrap();
                let mut record = session.record().await.unwrap();
                record.renewal_of = Some(aster_acme::issuance::RenewalPredecessor {
                    retained_validation: Vec::new(),
                    operation_id: "p".repeat(43),
                    certificate_id: None,
                });
                report_material(&context, &record, &progress).unwrap();
                progress.observe(&IssueEvent::CertificateSaved { name: record.name });
            }
            assert_eq!(stdout.text(), "");
            let text = stderr.text();
            if json {
                assert_eq!(text, "");
                continue;
            }
            let lines = text.lines().collect::<Vec<_>>();
            assert_eq!(lines.len(), 8);
            for (item, suffix) in ["first", "second"].into_iter().enumerate() {
                let name = format!("cdn.example.com-{suffix}-{json}");
                assert!(lines[item * 4].contains(&format!("Renewing {name} with ecdsa-p256")));
                assert!(
                    lines[item * 4 + 1]
                        .contains("Using CA: https://ca.example/directory (account default)")
                );
                assert!(lines[item * 4 + 2].contains("Certificate key:"));
                assert!(
                    lines[item * 4 + 3].contains(&format!("Certificate {name} verified and saved"))
                );
            }
        }
    }

    #[tokio::test]
    async fn automatic_allocation_retries_only_name_collisions_while_explicit_names_refuse_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
        let account = allocation_account();
        let request = IssueRequest {
            challenge: aster_acme::challenge::ChallengeKind::Dns01,
            solver_id: "manual_dns".into(),
            solver_config: serde_json::Value::Object(serde_json::Map::default()),
            key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
            name: CertificateName::new("example.com-collision").unwrap(),
            identifiers: vec![DnsIdentifier::new("example.com").unwrap()],
            account_name: "default".into(),
        };
        let initial = store.create(&request, &account).await.unwrap();
        let initial_record = initial.record().await.unwrap();
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
        assert_eq!(store.query(IssueQuery::default()).await.unwrap().len(), 2);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn allocation_propagates_unsafe_storage_errors_without_creating_another_random_name() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
        let account = allocation_account();
        let request = IssueRequest {
            challenge: aster_acme::challenge::ChallengeKind::Dns01,
            solver_id: "manual_dns".into(),
            solver_config: serde_json::Value::Object(serde_json::Map::default()),
            key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
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
        let accounts = aster_acme_cli_storage::account::CliAccountStore::open(
            temp.path(),
            "default",
            Duration::from_secs(1),
        )
        .unwrap();
        let signer = accounts
            .signer(
                &ca,
                "default",
                aster_acme::storage::account::KeyAccess::Create(None),
            )
            .await
            .unwrap();
        let thumb = signer.jwk().unwrap().thumbprint().unwrap();
        let mut account = accounts.load(&ca, &thumb).await.unwrap().unwrap();
        account.state = aster_acme_core::account::AccountRecordState::Registered;
        account.last_status = Some(aster_acme_core::protocol::AccountStatus::Valid);
        account.account_url =
            Some(aster_acme_protocol::url::AcmeUrl::new("https://127.0.0.1:1/account").unwrap());
        accounts.save(&account).await.unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
        let request = IssueRequest {
            challenge: aster_acme::challenge::ChallengeKind::Dns01,
            solver_id: "manual_dns".into(),
            solver_config: serde_json::Value::Object(serde_json::Map::default()),
            name: CertificateName::new("web").unwrap(),
            identifiers: vec![DnsIdentifier::new("example.com").unwrap()],
            key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP384,
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
                max_polls: Some(30),
                poll_interval: None,
                yes: false,

                operation_timeout: Some(2),
                http: HttpArgs::default(),
                local: LocalArgs {
                    data_dir: Some(temp.path().into()),
                    json: true,
                },
            },
        };
        super::super::renewal::execute(args, &crate::common::context::CommandContext::new(true))
            .await
            .unwrap();
        assert_eq!(store.query(IssueQuery::default()).await.unwrap().len(), 1);
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
