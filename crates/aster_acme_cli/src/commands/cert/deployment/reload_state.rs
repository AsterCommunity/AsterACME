//! Reload attempts, durable outcomes and retry scheduling.

use crate::commands::cert::deployment::execution::Execution;
use crate::commands::cert::deployment::publication::uncertain;
use crate::commands::cert::deployment::reload;
use crate::commands::cert::deployment::{MAX_BACKOFF, record_event};
use crate::commands::cert::{progress::Progress, report::DeploymentEvent};
use crate::common::{error::CliResult, output::MessageKind};
use aster_acme::{deployment::DeploymentPhase, issuance::CertificateName};
use aster_acme_cli_storage::issuance::DeploymentBinding;
use std::time::Duration;

pub(super) async fn reload_with_retries(
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

pub(super) async fn record_reload_failure(
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
pub(super) async fn settle_reload_attempt(
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
        session.restore_checkpoint(previous).await?;
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
pub(super) async fn finish_reload_attempt(
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
pub(super) async fn reload_interrupted(
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

pub(super) async fn reload_backoff(attempt: u8, process_failed_to_start: bool) {
    let delay = if process_failed_to_start {
        Duration::from_millis(250)
    } else {
        let shift = u32::from(attempt.saturating_sub(1)).min(2);
        Duration::from_millis(250_u64 << shift).min(MAX_BACKOFF)
    };
    tokio::time::sleep(delay).await;
}
