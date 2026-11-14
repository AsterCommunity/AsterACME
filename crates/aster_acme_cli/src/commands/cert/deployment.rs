//! CLI-managed file deployment and bounded service reload execution.
use crate::commands::account::args::AccountArgs;
use crate::commands::cert::{
    args::deployment::{DeployAddArgs, DeployArgs, DeployCommand},
    progress::Progress,
    report::{DeploymentEvent, DeploymentExecution, DeploymentReport},
};
use crate::common::{context::CliSettings, error::CliResult, output::MessageKind};
use aster_acme::storage::issuance::IssueStore as _;
use aster_acme::storage::query::{IssueQuery, IssueView};
use aster_acme::{
    deployment::{DeploymentIntent, DeploymentPhase},
    issuance::CertificateName,
};
use aster_acme_cli_storage::issuance::{
    CliIssueStore, DeploymentBinding, DeploymentDefinition, DeploymentPatch, DeploymentPermissions,
    DeploymentTarget,
};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_RETRIES: u8 = 3;
const MAX_BACKOFF: Duration = Duration::from_secs(4);

mod execution;
mod interaction;
mod reload;

use crate::commands::cert::deployment::execution::Execution;

pub(super) async fn execute(
    args: DeployArgs,
    cli: &crate::common::context::CommandContext,
    cancellation: tokio_util::sync::CancellationToken,
) -> CliResult<super::report::CertificateReport> {
    let _signal = crate::common::signal::InterruptGuard::new(cancellation.clone());
    // Never drop the command future while publication owns a blocking task.
    // Cancellation is propagated to the shared execution boundaries instead.
    let execution = Execution {
        cancellation,
        deadline: None,
    };
    execute_inner(args, cli, &execution).await
}

async fn execute_inner(
    args: DeployArgs,
    cli: &crate::common::context::CommandContext,
    execution: &Execution,
) -> CliResult<super::report::CertificateReport> {
    let options: AccountArgs = args.local().clone().into();
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir, Duration::from_secs(5));
    let managing = matches!(
        args.command,
        DeployCommand::List(_)
            | DeployCommand::Show(_)
            | DeployCommand::Remove(_)
            | DeployCommand::Update(_)
    );
    let name = select_certificate(&store, args.name(), managing, &cli.output).await?;
    execution.check()?;
    let progress = Progress::new(cli.output.clone());
    let mut execution_events = Vec::new();
    let (entries, attempted) = match args.command {
        DeployCommand::List(_) => (store.deployments(&name).await?, false),
        DeployCommand::Show(args) => {
            let id = if let Some(id) = args.deployment {
                id
            } else {
                let bindings = store.deployments(&name).await?;
                binding_id(&bindings, "inspect", &cli.output)?
            };
            let binding = store.deployment(&name, &id).await?;
            return Ok(super::report::CertificateReport::DeploymentDetails {
                name: name.as_str().into(),
                binding: Box::new(binding),
            });
        }
        DeployCommand::Remove(args) => {
            let definitions = store.deployments(&name).await?;
            let id = remove_id(args.id, &definitions, &cli.output)?;
            store.remove_deployment(&name, &id).await?;
            return Ok(super::report::CertificateReport::DeploymentRemoved {
                name: name.as_str().into(),
                id,
            });
        }
        DeployCommand::Update(args) => {
            let binding = update(&store, &name, args, &cli.output).await?;
            return Ok(super::report::CertificateReport::DeploymentUpdated {
                name: name.as_str().into(),
                binding: Box::new(binding),
            });
        }
        DeployCommand::Add(mut args) => {
            complete_add(&store, &name, &mut args, &cli.output).await?;
            let definition = definition(args)?;
            execution.check()?;
            let configured = store.add_deployment(&name, definition).await?;
            let execution = run_target(
                &store,
                &name,
                &configured,
                DeploymentIntent::Explicit,
                Some(&progress),
                Some(execution),
            )
            .await;
            execution_events.extend(execution.events);
            (vec![execution.binding], true)
        }
        DeployCommand::Run(args) => {
            let definitions = store.deployments(&name).await?;
            let selected = select_targets(definitions, args.id.as_deref())?;
            if selected.is_empty() {
                return Err(
                    "No deployment targets are configured. Use cert deploy add to configure one."
                        .into(),
                );
            }
            let entries = run_selected(
                &store,
                &name,
                selected,
                &progress,
                execution,
                &mut execution_events,
                None,
            )
            .await;
            (entries, true)
        }
    };
    Ok(super::report::CertificateReport::Deployment(
        DeploymentReport {
            name: name.as_str().into(),
            entries,
            events: execution_events,
            attempted,
        },
    ))
}

/// Retry only durable, known deployment failures for the current certificate generation.
/// Uncertain reloads stay behind the existing explicit-inspection barrier.
pub(crate) async fn retry_due(
    store: &CliIssueStore,
    timeout: Duration,
    cancellation: &tokio_util::sync::CancellationToken,
    cli: &crate::common::context::CommandContext,
    records: Vec<aster_acme::issuance::IssueRecord>,
) -> Vec<DeploymentReport> {
    let now = time::OffsetDateTime::now_utc();
    let progress = Progress::new(cli.output.clone());
    let mut reports = Vec::new();
    for record in records {
        if cancellation.is_cancelled() {
            break;
        }
        let definitions = match store.deployments(&record.name).await {
            Ok(definitions) => definitions,
            Err(error) => {
                reports.push(DeploymentReport {
                    name: record.name.as_str().to_owned(),
                    entries: Vec::new(),
                    events: vec![event(
                        MessageKind::Error,
                        format!("Deployment retry state could not be read: {error}"),
                    )],
                    attempted: true,
                });
                continue;
            }
        };
        let generation = record.generation_name();
        let selected = definitions
            .into_iter()
            .filter(|binding| binding.retry_due(&generation, now))
            .collect::<Vec<_>>();
        if selected.is_empty() {
            continue;
        }
        let execution = Execution {
            cancellation: cancellation.clone(),
            deadline: std::time::Instant::now().checked_add(timeout),
        };
        let mut events = Vec::new();
        let entries = run_selected(
            store,
            &record.name,
            selected,
            &progress,
            &execution,
            &mut events,
            Some(&generation),
        )
        .await;
        if entries.is_empty() && events.is_empty() {
            continue;
        }
        reports.push(DeploymentReport {
            name: record.name.as_str().to_owned(),
            entries,
            events,
            attempted: true,
        });
    }
    reports
}

async fn run_selected(
    store: &CliIssueStore,
    name: &CertificateName,
    selected: Vec<DeploymentBinding>,
    progress: &Progress,
    execution: &Execution,
    execution_events: &mut Vec<DeploymentEvent>,
    retry_generation: Option<&str>,
) -> Vec<DeploymentBinding> {
    let mut entries = Vec::with_capacity(selected.len());
    let mut selected = selected.into_iter();
    while let Some(definition) = selected.next() {
        if execution.check().is_err() {
            execution_events.push(event(
                MessageKind::Error,
                "Deployment cancelled before next target; completed results retained.",
            ));
            entries.push(definition);
            entries.extend(selected);
            break;
        }
        let intent = match retry_generation {
            Some(generation) => DeploymentIntent::Retry {
                generation,
                snapshot: &definition,
            },
            None => DeploymentIntent::Explicit,
        };
        let execution = run_target(
            store,
            name,
            &definition,
            intent,
            Some(progress),
            Some(execution),
        )
        .await;
        if execution.attempted {
            entries.push(execution.binding);
        }
        execution_events.extend(execution.events);
    }

    entries
}

async fn complete_add(
    store: &CliIssueStore,
    name: &CertificateName,
    args: &mut DeployAddArgs,
    output: &crate::common::session::OutputSession,
) -> CliResult<()> {
    let definitions = store.deployments(name).await?;
    interaction::complete(
        args,
        &definitions,
        crate::common::terminal::interactive(output.is_json()),
        &mut interaction::TerminalPrompts { output },
    )
}

async fn update(
    store: &CliIssueStore,
    name: &CertificateName,
    args: crate::commands::cert::args::deployment::DeployUpdateArgs,
    output: &crate::common::session::OutputSession,
) -> CliResult<DeploymentBinding> {
    let id = if let Some(id) = args.identity.id {
        id
    } else {
        let definitions = store.deployments(name).await?;
        binding_id(&definitions, "update", output)?
    };
    let target = if args.target.is_some()
        || args.cert_path.is_some()
        || args.fullchain_path.is_some()
        || args.ca_path.is_some()
        || args.key_path.is_some()
    {
        Some(destination(
            args.target,
            args.cert_path,
            args.fullchain_path,
            args.ca_path,
            args.key_path,
        )?)
    } else {
        None
    };
    let patch = DeploymentPatch {
        target,
        reload_command: if args.clear_reload {
            Some(Vec::new())
        } else {
            args.reload_cmd.as_deref().map(parse_command).transpose()?
        },
        timeout_seconds: args.reload_timeout,
        max_retries: args.max_retries,
        permissions: DeploymentPermissions {
            file_mode: args.file_mode,
            key_mode: args.key_mode,
        },
    };
    let binding = store.update_deployment(name, &id, patch).await?;
    Ok(binding)
}

fn definition(args: DeployAddArgs) -> CliResult<DeploymentDefinition> {
    Ok(DeploymentDefinition {
        permissions: DeploymentPermissions {
            file_mode: args.file_mode,
            key_mode: args.key_mode,
        },
        name: args.id,
        target: destination(
            args.target,
            args.cert_path,
            args.fullchain_path,
            args.ca_path,
            args.key_path,
        )?,
        reload_command: args
            .reload_cmd
            .as_deref()
            .map(parse_command)
            .transpose()?
            .unwrap_or_default(),
        timeout_seconds: args.reload_timeout.unwrap_or(DEFAULT_TIMEOUT_SECONDS),
        max_retries: args.max_retries.unwrap_or(DEFAULT_RETRIES),
    })
}

fn binding_id(
    definitions: &[DeploymentBinding],
    operation: &str,
    output: &crate::common::session::OutputSession,
) -> CliResult<String> {
    if !crate::common::terminal::interactive(output.is_json()) {
        let hint = if operation == "inspect" {
            "cert deploy show CERT_NAME DEPLOY_NAME"
        } else {
            "cert deploy update CERT_NAME -n DEPLOY_NAME"
        };
        return Err(format!("Specify a deployment name: {hint}.").into());
    }
    if definitions.is_empty() {
        return Err(
            "No deployment bindings to inspect. Use cert deploy add to configure one.".into(),
        );
    }
    let labels = definitions
        .iter()
        .map(|binding| binding.id.clone())
        .collect::<Vec<_>>();
    let index = crate::common::terminal::select_index(
        &format!("Choose a deployment to {operation}:"),
        &labels,
        0,
        output,
    )?;
    labels
        .into_iter()
        .nth(index)
        .ok_or_else(|| "Invalid deployment selection.".into())
}

fn remove_id(
    explicit: Option<String>,
    definitions: &[DeploymentBinding],
    output: &crate::common::session::OutputSession,
) -> CliResult<String> {
    if let Some(id) = explicit {
        return Ok(id);
    }
    if definitions.is_empty() {
        return Err("No deployment bindings to remove.".into());
    }
    if !crate::common::terminal::interactive(output.is_json()) {
        return Err(
            "Specify a deployment name: cert deploy remove CERT_NAME -n DEPLOY_NAME.".into(),
        );
    }
    let labels = definitions
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let index = crate::common::terminal::select_index(
        "Choose a deployment to remove:",
        &labels,
        0,
        output,
    )?;
    labels
        .into_iter()
        .nth(index)
        .ok_or_else(|| "Invalid deployment selection.".into())
}

/// Inspecting/removing bindings uses retained inventory; publishing requires an eligible current version.
async fn select_certificate(
    store: &CliIssueStore,
    explicit: Option<&str>,
    managing: bool,
    output: &crate::common::session::OutputSession,
) -> CliResult<CertificateName> {
    let candidates = store
        .query(IssueQuery {
            name: explicit.map(CertificateName::new).transpose()?,
            view: if managing {
                IssueView::Managed
            } else {
                IssueView::All
            },
            in_use: if managing { None } else { Some(true) },
            unfinished: if managing { None } else { Some(false) },
            revocation: if managing {
                None
            } else {
                Some(aster_acme_core::revocation::RevocationState::NotRequested)
            },
            ..IssueQuery::default()
        })
        .await?;
    if managing {
        super::selection::certificate_name(
            &candidates,
            explicit,
            None,
            super::selection::CertificateLabel::Deployment,
            output,
        )
    } else {
        super::selection::deployment_certificate_name(&candidates, explicit, output)
    }
}

/// Called after a completed issuance/renewal. A deployment error never changes
/// the saved CA certificate result; each target retains its own retry checkpoint.
pub(super) async fn after_issuance(
    store: &CliIssueStore,
    name: &CertificateName,
    generation: &str,
    execution: &aster_acme::solver::ExecutionContext,
) -> (Vec<DeploymentBinding>, Vec<DeploymentEvent>) {
    if execution.check().is_err() {
        return (
            Vec::new(),
            vec![event(
                MessageKind::Error,
                "Deployment not started: issuance execution was cancelled or its deadline expired; issued certificate retained. Run cert deploy explicitly.",
            )],
        );
    }
    // Do not drop automatic_inner at the operation deadline: a started blocking
    // publication continues under its lease. The worker records the final publish
    // state, then checks the deadline before starting reload or another target.
    Box::pin(automatic_inner(store, name, generation, execution)).await
}

async fn automatic_inner(
    store: &CliIssueStore,
    name: &CertificateName,
    generation: &str,
    execution: &aster_acme::solver::ExecutionContext,
) -> (Vec<DeploymentBinding>, Vec<DeploymentEvent>) {
    let execution = Execution::from(execution);
    let definitions = match store.deployments(name).await {
        Ok(definitions) => definitions,
        Err(error) => {
            return (
                Vec::new(),
                vec![event(
                    MessageKind::Error,
                    format!("Certificate issued; deployment inventory could not be read: {error}"),
                )],
            );
        }
    };
    let mut result = Vec::with_capacity(definitions.len());
    let mut events = Vec::new();
    let mut definitions = definitions.into_iter();
    while let Some(definition) = definitions.next() {
        if execution.check().is_err() {
            events.push(event(MessageKind::Error, "Automatic deployment stopped before the next target because issuance was cancelled or its deadline expired; committed certificate and deployment checkpoints are retained."));
            result.push(definition);
            result.extend(definitions);
            break;
        }
        let same_generation = definition.generation.as_deref() == Some(generation);
        if same_generation && definition.phase == DeploymentPhase::Deployed {
            result.push(definition);
            continue;
        }
        let target = Box::pin(run_target(
            store,
            name,
            &definition,
            DeploymentIntent::AfterIssuance { generation },
            None,
            Some(&execution),
        ))
        .await;
        events.extend(target.events);
        result.push(target.binding);
    }
    (result, events)
}

async fn run_target(
    store: &CliIssueStore,
    name: &CertificateName,
    definition: &DeploymentBinding,
    intent: DeploymentIntent<'_, DeploymentBinding>,
    progress: Option<&Progress>,
    execution: Option<&Execution>,
) -> DeploymentExecution {
    let id = definition.id.as_str();
    match Box::pin(run_one(store, name, id, intent, progress, execution)).await {
        Ok(mut execution) => {
            if execution.attempted && execution.binding.phase != DeploymentPhase::Deployed {
                record_event(
                    &mut execution.events,
                    MessageKind::Error,
                    &format!(
                        "Deployment '{id}' did not complete: {}",
                        execution
                            .binding
                            .last_error
                            .as_deref()
                            .unwrap_or("saved outcome requires inspection")
                    ),
                    progress,
                );
            }
            for event in &mut execution.events {
                event.deployment = Some(id.to_owned());
            }
            execution
        }
        Err(error) => {
            let mut events = Vec::new();
            record_event(
                &mut events,
                MessageKind::Error,
                &format!("Deployment '{id}' failed before completion: {error}"),
                progress,
            );
            for event in &mut events {
                event.deployment = Some(id.to_owned());
            }
            DeploymentExecution {
                attempted: true,
                binding: definition.clone(),
                events,
            }
        }
    }
}

async fn run_one(
    store: &CliIssueStore,
    name: &CertificateName,
    id: &str,
    intent: DeploymentIntent<'_, DeploymentBinding>,
    progress: Option<&Progress>,
    execution: Option<&Execution>,
) -> CliResult<DeploymentExecution> {
    if execution.is_some_and(|execution| execution.check().is_err()) {
        return Err(
            "issuance was cancelled or its execution deadline expired before deployment".into(),
        );
    }
    let mut session = store.open_deployment(name, id).await?;
    if execution.is_some_and(|execution| execution.check().is_err()) {
        return Err(
            "issuance was cancelled or its execution deadline expired before publication".into(),
        );
    }
    let mut events = Vec::new();
    if !session.admits(intent, time::OffsetDateTime::now_utc()) {
        return Ok(DeploymentExecution {
            attempted: false,
            binding: session.definition().clone(),
            events: events.clone(),
        });
    }
    let current_generation = session.artifacts().generation.clone();
    record_event(
        &mut events,
        MessageKind::Info,
        &format!("Started deployment '{id}' for generation {current_generation}"),
        progress,
    );
    prepare_publication(&mut session, execution).await?;
    Box::pin(publish_and_finish(
        &mut session,
        name,
        &mut events,
        progress,
        execution,
        aster_acme_cli_storage::issuance::DeploymentSession::publish,
    ))
    .await
}

fn uncertain(binding: &DeploymentBinding) -> bool {
    binding.phase.reload_uncertain()
}

async fn prepare_publication(
    session: &mut aster_acme_cli_storage::issuance::DeploymentSession,
    execution: Option<&Execution>,
) -> CliResult<()> {
    // An explicit retry does not itself resolve the previous reload. Keep
    // its durable barrier throughout publication, cancellation and crashes.
    let previous = session.definition().clone();
    if !uncertain(session.definition()) {
        session
            .save_state(DeploymentPhase::Publishing, 0, None)
            .await?;
    }
    if execution.is_some_and(|execution| execution.check().is_err()) {
        if !uncertain(session.definition()) {
            session
                .save_state(
                    previous.phase,
                    previous.attempts,
                    previous
                        .last_error
                        .or_else(|| Some("deployment cancelled before file publication".into())),
                )
                .await?;
        }
        return Err("deployment cancelled before file publication".into());
    }
    Ok(())
}

// Keep publication and its checkpoint in one awaited lifecycle. The injected
// operation lets tests suspend real publication without process-global hooks.
async fn publish_and_finish(
    session: &mut aster_acme_cli_storage::issuance::DeploymentSession,
    name: &CertificateName,
    events: &mut Vec<DeploymentEvent>,
    progress: Option<&Progress>,
    execution: Option<&Execution>,
    publish: impl AsyncFnOnce(
        &aster_acme_cli_storage::issuance::DeploymentSession,
    ) -> Result<(), aster_acme::issuance::IssueError>,
) -> CliResult<DeploymentExecution> {
    if let Err(error) = publish(session).await {
        if !uncertain(session.definition()) {
            let retry = session
                .record_failure(
                    DeploymentPhase::PublishFailed,
                    0,
                    error.to_string(),
                    time::OffsetDateTime::now_utc(),
                )
                .await?;
            record_event(
                events,
                MessageKind::Info,
                &format!(
                    "Automatic deployment retry scheduled at {}",
                    crate::common::time::timestamp(retry.retry_at)
                ),
                progress,
            );
        }
        record_event(
            events,
            MessageKind::Warning,
            &format!(
                "Deployment '{}' file publication failed: {error}",
                session.definition().id
            ),
            progress,
        );
        return Ok(DeploymentExecution {
            attempted: true,
            binding: session.definition().clone(),
            events: events.clone(),
        });
    }
    Box::pin(finish_publication(
        session, name, events, progress, execution,
    ))
    .await
}

async fn finish_publication(
    session: &mut aster_acme_cli_storage::issuance::DeploymentSession,
    name: &CertificateName,
    events: &mut Vec<DeploymentEvent>,
    progress: Option<&Progress>,
    execution: Option<&Execution>,
) -> CliResult<DeploymentExecution> {
    let id = session.definition().id.clone();
    record_event(
        events,
        MessageKind::Info,
        &format!(
            "Deployment '{}' files published for generation {}",
            session.definition().id,
            session.artifacts().generation
        ),
        progress,
    );
    if session.definition().reload_command.is_empty() {
        session
            .save_state(DeploymentPhase::Deployed, 0, None)
            .await?;
        record_event(
            events,
            MessageKind::Success,
            &format!("Deployment '{id}' completed (no reload command configured)"),
            progress,
        );
        return Ok(DeploymentExecution {
            attempted: true,
            binding: session.definition().clone(),
            events: events.clone(),
        });
    }
    // Successful publication is known independently of whether reload starts.
    // A prior unknown reload remains a barrier until a new definite result.
    if !uncertain(session.definition()) {
        session
            .save_state(DeploymentPhase::PublicationComplete, 0, None)
            .await?;
    }
    if execution.is_some_and(|execution| execution.check().is_err()) {
        if session.definition().phase.reload_uncertain() {
            return Err("previous reload outcome remains unconfirmed after cancellation; inspect the service before retry".into());
        }
        let error = "files were published, but reload was not started because the issuance was cancelled or its deadline expired";
        session
            .save_state(DeploymentPhase::PublicationComplete, 0, Some(error.into()))
            .await?;
        session
            .schedule_retry(time::OffsetDateTime::now_utc())
            .await?;
        record_event(events, MessageKind::Error, error, progress);
        return Ok(DeploymentExecution {
            attempted: true,
            binding: session.definition().clone(),
            events: events.clone(),
        });
    }
    let binding = session.definition().clone();
    if let Err(error) = Box::pin(reload_with_retries(
        session, &binding, name, events, progress, execution,
    ))
    .await
    {
        record_event(events, MessageKind::Error, &error.to_string(), progress);
    }
    Ok(DeploymentExecution {
        attempted: true,
        binding: session.definition().clone(),
        events: events.clone(),
    })
}

async fn reload_with_retries(
    session: &mut aster_acme_cli_storage::issuance::DeploymentSession,
    binding: &DeploymentBinding,
    name: &CertificateName,
    events: &mut Vec<DeploymentEvent>,
    progress: Option<&Progress>,
    execution: Option<&Execution>,
) -> CliResult<()> {
    let attempts_allowed = binding.max_retries.saturating_add(1);
    for attempt in 1..=attempts_allowed {
        if execution.is_some_and(|execution| execution.check().is_err()) {
            if attempt > 1 && session.definition().phase == DeploymentPhase::ReloadFailed {
                record_reload_failure(session, events, progress).await?;
            }
            return Err(
                "issuance was cancelled or its execution deadline expired before reload".into(),
            );
        }
        let previous = session.definition().clone();
        session
            .save_state(DeploymentPhase::Reloading, attempt, None)
            .await?;
        let result = Box::pin(reload::run(
            &binding.reload_command,
            Duration::from_secs(binding.timeout_seconds),
            &binding.id,
            attempt,
            events,
            progress,
            execution,
        ))
        .await;
        let failed_to_start = !result.started;
        if settle_reload_attempt(
            session, &previous, attempt, result, events, progress, execution,
        )
        .await?
        {
            return Ok(());
        }
        if attempt < attempts_allowed {
            reload_backoff(attempt, failed_to_start).await;
        }
    }
    record_event(
        events,
        MessageKind::Warning,
        &format!(
            "Deployment '{}' reload failed after {attempts_allowed} attempts; retry with cert deploy run {} -n {}",
            binding.id,
            name.as_str(),
            binding.id
        ),
        progress,
    );
    record_reload_failure(session, events, progress).await?;
    Ok(())
}

async fn record_reload_failure(
    session: &mut aster_acme_cli_storage::issuance::DeploymentSession,
    events: &mut Vec<DeploymentEvent>,
    progress: Option<&Progress>,
) -> CliResult<()> {
    if session.definition().phase == DeploymentPhase::ReloadFailed {
        let previous = session.definition().clone();
        let retry = session
            .record_failure(
                DeploymentPhase::ReloadFailed,
                previous.attempts,
                previous
                    .last_error
                    .unwrap_or_else(|| "reload command exited unsuccessfully".into()),
                time::OffsetDateTime::now_utc(),
            )
            .await?;
        record_event(
            events,
            MessageKind::Info,
            &format!(
                "Automatic deployment retry scheduled at {}",
                crate::common::time::timestamp(retry.retry_at)
            ),
            progress,
        );
    }
    Ok(())
}

// A checkpoint records intent, not proof of spawn. Restore the pre-attempt
// state if cancellation wins before the process owner starts the executable.
async fn settle_reload_attempt(
    session: &mut aster_acme_cli_storage::issuance::DeploymentSession,
    previous: &DeploymentBinding,
    attempt: u8,
    result: reload::ReloadResult,
    events: &mut Vec<DeploymentEvent>,
    progress: Option<&Progress>,
    execution: Option<&Execution>,
) -> CliResult<bool> {
    if !result.started
        && (uncertain(previous) || execution.is_some_and(|execution| execution.check().is_err()))
    {
        session
            .save_state(
                previous.phase,
                previous.attempts,
                previous.last_error.clone(),
            )
            .await?;
        return Err(
            "reload was not started; previous execution state retained; no process was terminated"
                .into(),
        );
    }
    if result.timed_out {
        return Err(reload_interrupted(session, attempt, execution).await?);
    }
    let binding = session.definition().clone();
    finish_reload_attempt(session, &binding, attempt, result, events, progress).await
}

/// Return true only for confirmed success. Errors after spawn are uncertain:
/// a service may have changed even when its exit status cannot be observed.
async fn finish_reload_attempt(
    session: &mut aster_acme_cli_storage::issuance::DeploymentSession,
    binding: &DeploymentBinding,
    attempt: u8,
    result: reload::ReloadResult,
    events: &mut Vec<DeploymentEvent>,
    progress: Option<&Progress>,
) -> CliResult<bool> {
    match result.status {
        Ok(status) if status.success() => {
            session
                .save_state(DeploymentPhase::Deployed, attempt, None)
                .await?;
            record_event(
                events,
                MessageKind::Success,
                &format!("Deployment '{}' reload succeeded", binding.id),
                progress,
            );
            Ok(true)
        }
        Ok(status) => {
            session
                .save_state(
                    DeploymentPhase::ReloadFailed,
                    attempt,
                    Some(format!("reload command exited unsuccessfully: {status}")),
                )
                .await?;
            Ok(false)
        }
        Err(error) if result.started => {
            let detail = format!(
                "reload started but its result could not be observed: {error}; inspect the service before an explicit retry"
            );
            session
                .save_state(
                    DeploymentPhase::ReloadUncertain,
                    attempt,
                    Some(detail.clone()),
                )
                .await?;
            Err(detail.into())
        }
        Err(error) => {
            session
                .save_state(
                    DeploymentPhase::ReloadFailed,
                    attempt,
                    Some(format!("reload command could not start: {error}")),
                )
                .await?;
            Ok(false)
        }
    }
}

// A killed reload may already have affected the service. Keep uncertainty
// durable and require an explicit retry instead of replaying it automatically.
async fn reload_interrupted(
    session: &mut aster_acme_cli_storage::issuance::DeploymentSession,
    attempt: u8,
    execution: Option<&Execution>,
) -> CliResult<Box<dyn std::error::Error>> {
    let overall_deadline = execution.is_some_and(|execution| {
        !execution.cancellation.is_cancelled()
            && execution
                .deadline
                .is_some_and(|deadline| deadline <= std::time::Instant::now())
    });
    let detail = if overall_deadline {
        "overall operation deadline expired during reload; process tree was terminated; inspect the service before retry"
    } else {
        "reload timed out or was cancelled; process tree was terminated; inspect the service before retry"
    };
    session
        .save_state(
            DeploymentPhase::ReloadUncertain,
            attempt,
            Some(detail.into()),
        )
        .await?;
    Ok(if overall_deadline {
        "overall operation deadline expired during reload; inspect the service, then use cert deploy run CERT_NAME -n DEPLOY_NAME"
    } else {
        "reload timed out or was cancelled; inspect the service, then use cert deploy run CERT_NAME -n DEPLOY_NAME"
    }
    .into())
}

async fn reload_backoff(attempt: u8, process_failed_to_start: bool) {
    let delay = if process_failed_to_start {
        Duration::from_millis(250)
    } else {
        let shift = u32::from(attempt.saturating_sub(1)).min(2);
        Duration::from_millis(250_u64 << shift).min(MAX_BACKOFF)
    };
    tokio::time::sleep(delay).await;
}

fn event(kind: MessageKind, message: impl Into<String>) -> DeploymentEvent {
    DeploymentEvent {
        deployment: None,
        kind,
        message: message.into(),
        at: time::OffsetDateTime::now_utc(),
    }
}

fn record_event(
    events: &mut Vec<DeploymentEvent>,
    kind: MessageKind,
    message: &str,
    progress: Option<&Progress>,
) {
    let event = event(kind, message);
    if let Some(progress) = progress {
        progress
            .output
            .context(&crate::commands::cert::render::deployment::event(
                &event,
                progress.output.diagnostic_format().color,
            ));
    }
    events.push(event);
}

fn destination(
    target: Option<PathBuf>,
    certificate: Option<PathBuf>,
    fullchain: Option<PathBuf>,
    ca_chain: Option<PathBuf>,
    key: Option<PathBuf>,
) -> CliResult<DeploymentTarget> {
    match (target, certificate, fullchain, ca_chain, key) {
        (Some(path), None, None, None, None) => {
            Ok(DeploymentTarget::Directory { path: directory(&path)? })
        }
        (None, certificate, fullchain, ca_chain, private_key)
            if certificate.is_some() || fullchain.is_some() || ca_chain.is_some() || private_key.is_some() => Ok(DeploymentTarget::Files {
                certificate: certificate.as_deref().map(canonical_file_path).transpose()?,
                fullchain: fullchain.as_deref().map(canonical_file_path).transpose()?,
                ca_chain: ca_chain.as_deref().map(canonical_file_path).transpose()?,
                private_key: private_key.as_deref().map(canonical_file_path).transpose()?,
            }),
        _ => Err("Use --target DIR or at least one of --cert-path, --key-path, --ca-path, --fullchain-path; these forms are mutually exclusive.".into()),
    }
}

fn directory(path: &Path) -> CliResult<PathBuf> {
    let path = path
        .canonicalize()
        .map_err(|_| "--target must be an existing directory")?;
    if !path.is_dir() {
        return Err("--target must be an existing directory".into());
    }
    Ok(path)
}

fn canonical_file_path(path: &Path) -> CliResult<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let name = path
        .file_name()
        .ok_or("deployment file path must name a file")?;
    if name.to_string_lossy().contains(['/', '\\', ':']) {
        return Err("invalid deployment filename".into());
    }
    Ok(parent.join(name))
}

fn parse_command(command: &str) -> CliResult<Vec<String>> {
    let words = shlex::split(command).ok_or("--reload-cmd has unbalanced quoting")?;
    if words.is_empty()
        || words.len() > 64
        || words
            .iter()
            .any(|word| word.contains('\0') || word.len() > 4096)
    {
        return Err("--reload-cmd must contain a bounded executable and argv".into());
    }
    Ok(words)
}

fn select_targets(
    definitions: Vec<DeploymentBinding>,
    requested: Option<&str>,
) -> CliResult<Vec<DeploymentBinding>> {
    if let Some(id) = requested {
        return definitions
            .into_iter()
            .find(|item| item.id == id)
            .map(|item| vec![item])
            .ok_or_else(|| format!("No deployment named '{id}' is configured.").into());
    }
    Ok(definitions)
}

#[cfg(test)]
pub(crate) mod tests;
