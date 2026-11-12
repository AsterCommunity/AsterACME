//! CLI-managed file deployment and bounded service reload execution.
use crate::commands::account::args::AccountArgs;
use crate::commands::cert::{
    args::deployment::{DeployAddArgs, DeployArgs, DeployCommand},
    progress::Progress,
    report::{DeploymentEvent, DeploymentExecution, DeploymentReport},
};
use crate::common::{context::CliSettings, error::CliResult, output::MessageKind};
use aster_acme::issuance::CertificateName;
use aster_acme::storage::issuance::IssueStore as _;
use aster_acme::storage::query::{IssueQuery, IssueView};
use aster_acme_cli_storage::issuance::{
    CliIssueStore, DeploymentBinding, DeploymentDefinition, DeploymentPatch, DeploymentPermissions,
    DeploymentPhase, DeploymentTarget,
};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_RETRIES: u8 = 3;
const MAX_BACKOFF: Duration = Duration::from_secs(4);

mod interaction;
mod reload;

pub(super) async fn execute(
    args: DeployArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<super::report::CertificateReport> {
    let cancellation = tokio_util::sync::CancellationToken::new();
    let _signal = crate::common::signal::InterruptGuard::new(cancellation.clone());
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(Box::new(crate::common::terminal::Canceled) as Box<dyn std::error::Error>),
        result = execute_inner(args, cli) => result,
    }
}

async fn execute_inner(
    args: DeployArgs,
    cli: &crate::common::context::CommandContext,
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
            let definitions = store.deployments(&name).await?;
            interaction::complete(
                &mut args,
                &definitions,
                crate::common::terminal::interactive(cli.output.is_json()),
                &mut interaction::TerminalPrompts {
                    output: &cli.output,
                },
            )?;
            let definition = definition(args)?;
            let configured = store.add_deployment(&name, definition).await?;
            let execution = run_target(&store, &name, &configured, true, Some(&progress)).await;
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
            let mut entries = Vec::with_capacity(selected.len());
            for definition in selected {
                let execution = run_target(&store, &name, &definition, true, Some(&progress)).await;
                entries.push(execution.binding);
                execution_events.extend(execution.events);
            }
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
    tokio::select! {
        biased;
        () = execution.cancellation.cancelled() => (Vec::new(), vec![event(MessageKind::Error,
            "Deployment interrupted; issued certificate retained. Inspect saved deployment state before retrying.")]),
        result = tokio::time::timeout_at(tokio::time::Instant::from_std(execution.deadline), automatic_inner(store, name, generation)) => result.unwrap_or_else(|_| (Vec::new(), vec![event(MessageKind::Error, "Deployment deadline exceeded; issued certificate retained. Inspect saved deployment state before retrying.")])),
    }
}

async fn automatic_inner(
    store: &CliIssueStore,
    name: &CertificateName,
    generation: &str,
) -> (Vec<DeploymentBinding>, Vec<DeploymentEvent>) {
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
    for definition in definitions {
        let same_generation = definition.generation.as_deref() == Some(generation);
        if same_generation && definition.phase == DeploymentPhase::Deployed {
            result.push(definition);
            continue;
        }
        let execution = run_target(store, name, &definition, false, None).await;
        events.extend(execution.events);
        result.push(execution.binding);
    }
    (result, events)
}

async fn run_target(
    store: &CliIssueStore,
    name: &CertificateName,
    definition: &DeploymentBinding,
    force: bool,
    progress: Option<&Progress>,
) -> DeploymentExecution {
    let id = definition.id.as_str();
    match run_one(store, name, id, force, progress).await {
        Ok(mut execution) => {
            if execution.binding.phase != DeploymentPhase::Deployed {
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
    force: bool,
    progress: Option<&Progress>,
) -> CliResult<DeploymentExecution> {
    let mut session = store.open_deployment(name, id).await?;
    let mut events = Vec::new();
    let same_generation =
        session.definition().generation.as_deref() == Some(session.artifacts().generation.as_str());
    if !force && same_generation && session.definition().phase == DeploymentPhase::Deployed {
        return Ok(DeploymentExecution {
            binding: session.definition().clone(),
            events,
        });
    }
    if !force
        && same_generation
        && matches!(
            session.definition().phase,
            DeploymentPhase::Reloading | DeploymentPhase::ReloadUncertain
        )
    {
        record_event(
            &mut events,
            MessageKind::Warning,
            "Previous reload outcome is uncertain; inspect the service and explicitly retry.",
            progress,
        );
        return Ok(DeploymentExecution {
            binding: session.definition().clone(),
            events,
        });
    }
    let current_generation = session.artifacts().generation.clone();
    record_event(
        &mut events,
        MessageKind::Info,
        &format!("Started deployment '{id}' for generation {current_generation}"),
        progress,
    );
    session
        .save_state(DeploymentPhase::Publishing, 0, None)
        .await?;
    if let Err(error) = session.publish().await {
        session
            .save_state(DeploymentPhase::PublishFailed, 0, Some(error.to_string()))
            .await?;
        record_event(
            &mut events,
            MessageKind::Warning,
            &format!("Deployment '{id}' file publication failed: {error}"),
            progress,
        );
        return Ok(DeploymentExecution {
            binding: session.definition().clone(),
            events,
        });
    }
    record_event(
        &mut events,
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
            &mut events,
            MessageKind::Success,
            &format!("Deployment '{id}' completed (no reload command configured)"),
            progress,
        );
        return Ok(DeploymentExecution {
            binding: session.definition().clone(),
            events,
        });
    }
    let binding = session.definition().clone();
    if let Err(error) =
        reload_with_retries(&mut session, &binding, name, &mut events, progress).await
    {
        record_event(
            &mut events,
            MessageKind::Error,
            &error.to_string(),
            progress,
        );
    }
    Ok(DeploymentExecution {
        binding: session.definition().clone(),
        events,
    })
}

async fn reload_with_retries(
    session: &mut aster_acme_cli_storage::issuance::DeploymentSession,
    binding: &DeploymentBinding,
    name: &CertificateName,
    events: &mut Vec<DeploymentEvent>,
    progress: Option<&Progress>,
) -> CliResult<()> {
    let attempts_allowed = binding.max_retries.saturating_add(1);
    for attempt in 1..=attempts_allowed {
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
        ))
        .await;
        if result.timed_out {
            session.save_state(DeploymentPhase::ReloadUncertain, attempt,
                Some("reload command timed out; process-tree cleanup requested; inspect the service before retry".into())).await?;
            return Err("reload command timed out; use cert deploy run CERT_NAME -n DEPLOY_NAME after checking the service".into());
        }
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
                return Ok(());
            }
            Ok(status) => {
                session
                    .save_state(
                        DeploymentPhase::ReloadFailed,
                        attempt,
                        Some(format!("reload command exited unsuccessfully: {status}")),
                    )
                    .await?;
                if attempt < attempts_allowed {
                    let shift = u32::from(attempt.saturating_sub(1)).min(2);
                    tokio::time::sleep(Duration::from_millis(250_u64 << shift).min(MAX_BACKOFF))
                        .await;
                }
            }
            Err(error) => {
                session
                    .save_state(
                        DeploymentPhase::ReloadFailed,
                        attempt,
                        Some(format!(
                            "reload command could not start or be observed: {error}"
                        )),
                    )
                    .await?;
                if attempt < attempts_allowed {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
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
    Ok(())
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
