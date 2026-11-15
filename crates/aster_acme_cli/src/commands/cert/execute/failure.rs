//! Certificate failure execution.
use crate::commands::cert::progress::Progress;
use crate::common::error::CliResult;
use crate::common::output::MessageKind;
use aster_acme::storage::issuance::IssueSession;
use aster_acme::{
    issuance::{IssueError, IssueRecord},
    solver::ExecutionContext,
};

pub(super) async fn report_issue_failure(
    session: &mut dyn IssueSession,
    record: &IssueRecord,
    progress: &Progress,
    execution: &ExecutionContext,
    error: Box<dyn std::error::Error>,
) -> CliResult<crate::commands::cert::report::CertificateResult> {
    let saved = session.record().await?;
    if !execution.cancellation.is_cancelled()
        && let Some(failure) = saved.renewal_failure(time::OffsetDateTime::now_utc())
    {
        let retry = session
            .record_renewal_failure(
                failure.occurred_at,
                failure.ca_retry_at,
                failure.blocked_reason,
            )
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

pub(in crate::commands::cert) fn report_renewal_retry(
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
