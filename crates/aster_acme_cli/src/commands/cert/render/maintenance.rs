//! Maintenance report presentation; no side effects.

use crate::commands::cert::report::{CertificateResult, RenewalBatch, RenewalResult};
use crate::common::output;
use aster_acme::issuance::IssueOutcome;

/// Semantic log records for a resident daemon cycle. Reports remain the single
/// source for renew/deploy outcomes; the daemon only streams these saved events.
pub(crate) struct MaintenanceLogEvent {
    pub(crate) at: time::OffsetDateTime,
    pub(crate) kind: output::MessageKind,
    pub(crate) message: String,
}

pub(crate) fn maintenance_log_events(
    ari: &aster_acme::maintenance::Report,
    renewals: &RenewalBatch,
    deployments: &[crate::commands::cert::report::DeploymentReport],
) -> Vec<MaintenanceLogEvent> {
    let mut events = Vec::new();
    events.extend(ari_log_events(ari));
    for entry in &renewals.entries {
        events.push(renewal_log_event(entry));
        if let RenewalResult::Outcome(CertificateResult::Issued {
            deployment_events, ..
        }) = &entry.result
        {
            events.extend(deployment_events.iter().map(|event| MaintenanceLogEvent {
                at: event.at,
                kind: event.kind,
                message: format!("{}: {}", entry.name, event.message),
            }));
        }
    }
    for report in deployments {
        events.extend(report.events.iter().map(|event| MaintenanceLogEvent {
            at: event.at,
            kind: event.kind,
            message: format!("{}: {}", report.name, event.message),
        }));
    }
    events
}

pub(in crate::commands::cert::render) fn ari_log_events(
    report: &aster_acme::maintenance::Report,
) -> Vec<MaintenanceLogEvent> {
    use aster_acme::maintenance::Outcome;
    report
        .entries
        .iter()
        .map(|entry| {
            let (kind, status) = match &entry.outcome {
                Outcome::Refreshed => (output::MessageKind::Success, "ARI refreshed".to_owned()),
                Outcome::RetryScheduled => (
                    output::MessageKind::Warning,
                    "ARI retry scheduled".to_owned(),
                ),
                Outcome::Unavailable => {
                    (output::MessageKind::Warning, "ARI unavailable".to_owned())
                }
                Outcome::Skipped => (
                    output::MessageKind::Info,
                    "ARI refresh no longer due".to_owned(),
                ),
                Outcome::Failed(error) => (
                    output::MessageKind::Error,
                    crate::common::error::diagnostic(error).0,
                ),
                Outcome::Cancelled => (
                    output::MessageKind::Warning,
                    "ARI refresh cancelled".to_owned(),
                ),
                Outcome::NotStarted => (
                    output::MessageKind::Warning,
                    "ARI refresh not started".to_owned(),
                ),
            };
            MaintenanceLogEvent {
                at: time::OffsetDateTime::now_utc(),
                kind,
                message: format!("{}: {status}", entry.name),
            }
        })
        .collect()
}

pub(in crate::commands::cert::render) fn renewal_log_event(
    entry: &crate::commands::cert::report::RenewalEntry,
) -> MaintenanceLogEvent {
    use crate::commands::cert::report::RenewalResult;
    let (kind, message) = match &entry.result {
        RenewalResult::Outcome(
            CertificateResult::Issuance(outcome) | CertificateResult::Issued { outcome, .. },
        ) => match outcome {
            IssueOutcome::Completed { record, .. } => (
                output::MessageKind::Done,
                format!("Renewed certificate {}", record.name),
            ),
            IssueOutcome::ActionRequired { record, .. } => (
                output::MessageKind::Warning,
                format!("Renewal action required for {}", record.name),
            ),
        },
        RenewalResult::Outcome(CertificateResult::NotDue(record)) => (
            output::MessageKind::Info,
            format!("{}: renewal is not due", record.name),
        ),
        RenewalResult::Skipped(reason) => (
            output::MessageKind::Warning,
            format!("{}: {}", entry.name, reason.message()),
        ),
        RenewalResult::Failed { message, .. } => (
            output::MessageKind::Error,
            format!("{}: {}", entry.name, message),
        ),
        RenewalResult::Cancelled => (
            output::MessageKind::Warning,
            format!("{}: renewal cancelled", entry.name),
        ),
    };
    MaintenanceLogEvent {
        at: time::OffsetDateTime::now_utc(),
        kind,
        message,
    }
}
