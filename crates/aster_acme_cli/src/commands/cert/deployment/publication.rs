//! Deployment publication stage.

use crate::commands::cert::deployment::execution::Execution;
use crate::commands::cert::deployment::record_event;
use crate::commands::cert::deployment::reload_state::reload_with_retries;
use crate::commands::cert::{
    progress::Progress,
    report::{DeploymentEvent, DeploymentExecution},
};
use crate::common::{error::CliResult, output::MessageKind};
use aster_acme::{
    deployment::{DeploymentIntent, DeploymentPhase},
    issuance::CertificateName,
};
use aster_acme_cli_storage::issuance::{CliIssueStore, DeploymentBinding};

pub(super) async fn run_target(
    store: &CliIssueStore,
    name: &CertificateName,
    definition: &DeploymentBinding,
    intent: DeploymentIntent<'_, DeploymentBinding>,
    progress: Option<&Progress>,
    execution: Option<&Execution>,
    output: Option<&crate::common::session::OutputSession>,
) -> DeploymentExecution {
    let id = definition.id.as_str();
    match Box::pin(run_one(
        store, name, id, intent, progress, execution, output,
    ))
    .await
    {
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
            let cancelled = error.is::<crate::common::terminal::Canceled>();
            if cancelled && let Some(execution) = execution {
                execution.cancellation.cancel();
            }
            let mut events = Vec::new();
            record_event(
                &mut events,
                MessageKind::Error,
                &format!("Deployment '{id}' failed before completion: {error}"),
                progress,
            );
            for event in &mut events {
                event.cancelled = cancelled;
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

pub(super) async fn run_one(
    store: &CliIssueStore,
    name: &CertificateName,
    id: &str,
    intent: DeploymentIntent<'_, DeploymentBinding>,
    progress: Option<&Progress>,
    execution: Option<&Execution>,
    output: Option<&crate::common::session::OutputSession>,
) -> CliResult<DeploymentExecution> {
    if execution.is_some_and(|execution| execution.check().is_err())
        && matches!(intent, DeploymentIntent::Explicit)
    {
        return Err(
            "deployment was cancelled or its execution deadline expired before startup".into(),
        );
    }
    let pkcs12_password = interactive_pkcs12_password(store, name, id, &intent, output).await?;
    let mut session = store.open_deployment(name, id, pkcs12_password).await?;
    let mut events = Vec::new();
    if !session.admits(intent, time::OffsetDateTime::now_utc()) {
        return Ok(DeploymentExecution {
            attempted: false,
            binding: session.definition().clone(),
            events: events.clone(),
        });
    }
    let current_generation = session.artifacts().generation.clone();
    if let DeploymentIntent::AfterIssuance { generation } = intent
        && session.definition().generation.as_deref() != Some(generation)
        && session.definition().pending_generation.as_deref() != Some(generation)
    {
        session.save_pending_generation(generation).await?;
    }
    if execution.is_some_and(|execution| execution.check().is_err()) {
        record_event(
            &mut events,
            MessageKind::Warning,
            &format!(
                "Deployment '{id}' for generation {current_generation} is queued for the next maintenance cycle"
            ),
            progress,
        );
        return Ok(DeploymentExecution {
            attempted: false,
            binding: session.definition().clone(),
            events,
        });
    }
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

pub(super) fn uncertain(binding: &DeploymentBinding) -> bool {
    binding.phase.reload_uncertain()
}

/// Prompt for the PKCS#12 password when an explicit interactive run needs one:
/// the binding publishes a bundle but stores no password source. Automatic
/// paths (retry, daemon, JSON) never prompt and defer to the stored source.
async fn interactive_pkcs12_password(
    store: &CliIssueStore,
    name: &CertificateName,
    id: &str,
    intent: &DeploymentIntent<'_, DeploymentBinding>,
    output: Option<&crate::common::session::OutputSession>,
) -> CliResult<Option<zeroize::Zeroizing<String>>> {
    let Some(output) = output else {
        return Ok(None);
    };
    if !matches!(intent, DeploymentIntent::Explicit)
        || !crate::common::terminal::interactive(output.is_json())
    {
        return Ok(None);
    }
    let binding = store.deployment(name, id).await?;
    let aster_acme_cli_storage::issuance::DeploymentTarget::Files {
        pkcs12: Some(_),
        pkcs12_password_env: None,
        pkcs12_password_file: None,
        ..
    } = &binding.target
    else {
        return Ok(None);
    };
    let password = crate::common::terminal::password_prompt(
        &format!("PKCS#12 password for deployment '{id}':"),
        output,
    )?;
    Ok(Some(password))
}

pub(super) async fn prepare_publication(
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
            session.restore_checkpoint(&previous).await?;
        }
        return Err("deployment cancelled before file publication".into());
    }
    Ok(())
}

// Keep publication and its checkpoint in one awaited lifecycle. The injected
// operation lets tests suspend real publication without process-global hooks.
pub(super) async fn publish_and_finish(
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

pub(super) async fn finish_publication(
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
    if let aster_acme_cli_storage::issuance::DeploymentTarget::Files { pkcs12, .. } =
        &session.definition().target
        && let Some(event) = events.last_mut()
    {
        event.pkcs12_path.clone_from(pkcs12);
    }
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
