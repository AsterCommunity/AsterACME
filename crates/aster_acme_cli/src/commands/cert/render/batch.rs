//! Batch report presentation; no side effects.

use crate::commands::cert::render::outcome::{ResultOutput, issued_result, result_output};
use crate::commands::cert::report::{
    BatchDisposition, CertificateResult, RenewalBatch, RenewalResult, RenewalSummary, SkipReason,
};
use crate::common::error::CliResult;
use crate::common::output;
use crate::common::output::Style;
use crate::common::session::Format;
use crate::common::time::timestamp;
use aster_acme::issuance::IssueOutcome;
use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(in crate::commands::cert::render) enum BatchItemOutput<'a> {
    Skipped {
        reason: SkipReason,
    },
    Failed {
        message: &'a str,
        hint: Option<&'a str>,
    },
    Cancelled,
    #[serde(untagged)]
    Outcome(ResultOutput<'a>),
}

#[derive(Serialize)]
pub(in crate::commands::cert::render) struct BatchEntryOutput<'a> {
    name: &'a str,
    result: BatchItemOutput<'a>,
}

#[derive(Serialize)]
pub(in crate::commands) struct BatchOutput<'a> {
    status: BatchDisposition,
    summary: RenewalSummary,
    results: Vec<BatchEntryOutput<'a>>,
}

pub(in crate::commands) fn batch_output<'a>(
    report: &'a RenewalBatch,
    data_dir: &std::path::Path,
) -> BatchOutput<'a> {
    let status = report.disposition();
    let results = report
        .entries
        .iter()
        .map(|entry| BatchEntryOutput {
            name: &entry.name,
            result: match &entry.result {
                RenewalResult::Outcome(result) => {
                    BatchItemOutput::Outcome(result_output(result, data_dir))
                }
                RenewalResult::Skipped(reason) => BatchItemOutput::Skipped { reason: *reason },
                RenewalResult::Failed { message, hint } => BatchItemOutput::Failed {
                    message,
                    hint: hint.as_deref(),
                },
                RenewalResult::Cancelled => BatchItemOutput::Cancelled,
            },
        })
        .collect();
    BatchOutput {
        status,
        summary: report.summary(),
        results,
    }
}

pub(in crate::commands::cert::render) fn batch_summary(
    summary: &RenewalSummary,
    total: usize,
) -> String {
    if total > 0 && summary.not_due == total {
        return format!("{total} certificates checked; none due for renewal.");
    }
    let counts = [
        ("Completed", summary.completed),
        ("action required", summary.action_required),
        ("not due", summary.not_due),
        ("skipped", summary.skipped),
        ("failed", summary.failed),
        ("cancelled", summary.cancelled),
    ]
    .into_iter()
    .filter(|(_, count)| *count > 0)
    .map(|(label, count)| format!("{label}: {count}"))
    .collect::<Vec<_>>();
    if counts.is_empty() {
        "No managed certificates to check.".into()
    } else {
        format!("{}.", counts.join("; "))
    }
}

pub(crate) fn batch(
    report: &RenewalBatch,
    format: Format,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    let summary = report.summary();
    if format.json {
        return Ok(serde_json::to_string_pretty(&batch_output(
            report, data_dir,
        ))?);
    }
    let color = format.color;
    if report.entries.is_empty() {
        let (kind, message) = if report.was_cancelled() {
            (
                output::MessageKind::Warning,
                "Batch renewal cancelled before any certificates were processed.",
            )
        } else {
            (
                output::MessageKind::Info,
                "No managed certificates to check.",
            )
        };
        return Ok(format!("{} {message}", kind.badge(color)));
    }
    let mut rows = vec![["NAME".into(), "STATUS".into(), "NEXT RENEWAL (UTC)".into()]];
    let mut details = Vec::new();
    for entry in &report.entries {
        let (status, renew_at, detail) = render_batch_entry(entry, format, data_dir)?;
        if let Some(detail) = detail {
            details.push(detail);
        }
        rows.push([
            output::safe(&entry.name),
            status.into(),
            timestamp(renew_at),
        ]);
    }
    let kind = match report.disposition() {
        BatchDisposition::Completed => output::MessageKind::Info,
        BatchDisposition::ActionRequired | BatchDisposition::Cancelled => {
            output::MessageKind::Warning
        }
        BatchDisposition::PartialFailure => output::MessageKind::Error,
    };
    let mut lines = vec![format!("{} Batch renewal results:", kind.badge(color))];
    lines.extend(crate::common::table::listing(
        &rows,
        color,
        |row, column| match column {
            1 => batch_status_style(&report.entries[row].result),
            _ => Style::Plain,
        },
    ));
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        kind.badge(color),
        batch_summary(&summary, report.entries.len())
    ));
    for detail in details {
        lines.push(String::new());
        lines.push(detail);
    }
    Ok(lines.join("\n"))
}

pub(in crate::commands::cert::render) fn render_batch_entry(
    entry: &crate::commands::cert::report::RenewalEntry,
    format: Format,
    data_dir: &std::path::Path,
) -> CliResult<(&'static str, Option<time::OffsetDateTime>, Option<String>)> {
    let color = format.color;
    match &entry.result {
        RenewalResult::Outcome(CertificateResult::NotDue(record)) => Ok((
            "not due",
            record.renewal.as_ref().map(|plan| plan.renew_at),
            None,
        )),
        RenewalResult::Outcome(CertificateResult::Issuance(outcome)) => {
            let status = match outcome {
                IssueOutcome::Completed { record, .. } => (
                    "completed",
                    record.renewal.as_ref().map(|plan| plan.renew_at),
                ),
                IssueOutcome::ActionRequired { .. } => ("action required", None),
            };
            Ok((
                status.0,
                status.1,
                Some(crate::commands::cert::render::outcome::outcome(
                    outcome, format, data_dir,
                )?),
            ))
        }
        RenewalResult::Outcome(CertificateResult::Issued {
            outcome,
            deployments,
            deployment_events,
        }) => {
            let (status, renew_at) = match outcome {
                IssueOutcome::Completed { record, .. }
                    if deployment_events
                        .iter()
                        .any(|event| event.kind == output::MessageKind::Error)
                        || deployments
                            .iter()
                            .any(|entry| !entry.checkpoint().is_deployed()) =>
                {
                    (
                        "deployment failed",
                        record.renewal.as_ref().map(|p| p.renew_at),
                    )
                }
                IssueOutcome::Completed { record, .. } => {
                    ("completed", record.renewal.as_ref().map(|p| p.renew_at))
                }
                IssueOutcome::ActionRequired { .. } => ("action required", None),
            };
            Ok((
                status,
                renew_at,
                Some(issued_result(
                    outcome,
                    deployments,
                    deployment_events,
                    format,
                    data_dir,
                )?),
            ))
        }
        RenewalResult::Skipped(reason) => Ok((
            "skipped",
            None,
            Some(format!(
                "{} {}: {}",
                output::MessageKind::Warning.badge(color),
                output::safe(&entry.name),
                reason.message()
            )),
        )),
        RenewalResult::Failed { message, hint } => Ok((
            "failed",
            None,
            Some(format!(
                "{} {}: {}{}",
                output::MessageKind::Error.badge(color),
                output::safe(&entry.name),
                output::safe(message),
                hint.as_ref().map_or_else(String::new, |hint| format!(
                    "\n{}",
                    output::tips(hint, color)
                ))
            )),
        )),
        RenewalResult::Cancelled => Ok((
            "cancelled",
            None,
            Some(format!(
                "{} {}: stopped; inspect the saved request and selected certificate",
                output::MessageKind::Warning.badge(color),
                output::safe(&entry.name)
            )),
        )),
    }
}

pub(in crate::commands::cert::render) fn batch_status_style(result: &RenewalResult) -> Style {
    match result {
        RenewalResult::Outcome(CertificateResult::Issuance(IssueOutcome::Completed { .. })) => {
            Style::Green
        }
        RenewalResult::Outcome(CertificateResult::Issued {
            outcome: IssueOutcome::Completed { .. },
            deployments,
            deployment_events,
        }) if deployment_events
            .iter()
            .any(|event| event.kind == output::MessageKind::Error)
            || deployments
                .iter()
                .any(|entry| !entry.checkpoint().is_deployed()) =>
        {
            Style::Red
        }
        RenewalResult::Outcome(CertificateResult::Issued {
            outcome: IssueOutcome::Completed { .. },
            ..
        }) => Style::Green,
        RenewalResult::Outcome(CertificateResult::NotDue(_)) => Style::Cyan,
        RenewalResult::Outcome(
            CertificateResult::Issuance(IssueOutcome::ActionRequired { .. })
            | CertificateResult::Issued {
                outcome: IssueOutcome::ActionRequired { .. },
                ..
            },
        )
        | RenewalResult::Skipped(_)
        | RenewalResult::Cancelled => Style::Yellow,
        RenewalResult::Failed { .. } => Style::Red,
    }
}
