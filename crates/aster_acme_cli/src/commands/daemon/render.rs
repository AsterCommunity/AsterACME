//! One final maintenance document, using shared time/table/error policies.

use crate::common::{
    error::{CliResult, diagnostic},
    output::{self, MessageKind, Style},
    session::Format,
    table,
    time::timestamp,
};
use aster_acme::maintenance::Outcome;

pub(crate) fn started(
    output_session: &crate::common::session::OutputSession,
    interval: std::time::Duration,
    data_dir: &std::path::Path,
) -> CliResult<()> {
    let at = time::OffsetDateTime::now_utc();
    if output_session.is_json() {
        output_session.stream_json(&serde_json::json!({
            "event": "started",
            "at": rfc3339(at)?,
            "interval_seconds": interval.as_secs(),
            "data_dir": data_dir,
        }))?;
    } else {
        output_session.progress_at(
            MessageKind::Info,
            &format!(
                "Daemon started; maintenance interval {}s",
                interval.as_secs()
            ),
            at,
        );
    }
    Ok(())
}

/// Stream one cycle with the same timestamp and severity layout as issuance logs.
pub(crate) fn cycle(
    output_session: &crate::common::session::OutputSession,
    cycle: u64,
    result: &CliResult<crate::commands::daemon::DaemonReport>,
) -> CliResult<bool> {
    let at = time::OffsetDateTime::now_utc();
    match result {
        Ok(report) => {
            let exit_status = crate::commands::daemon::exit_status(report);
            let failed = exit_status == crate::common::session::ExitStatus::Failed;
            if output_session.is_json() {
                let value = report_output(report)?;
                output_session.stream_json(&serde_json::json!({
                    "event": "cycle",
                    "at": rfc3339(at)?,
                    "cycle": cycle,
                    "status": match exit_status {
                        crate::common::session::ExitStatus::Failed => "failed",
                        crate::common::session::ExitStatus::Cancelled => "cancelled",
                        crate::common::session::ExitStatus::Success => "completed",
                    },
                    "report": value,
                }))?;
            } else {
                let logs = crate::commands::cert::render::maintenance::maintenance_log_events(
                    &report.ari,
                    &report.renewals,
                    &report.deployment_retries,
                );
                for event in &logs {
                    output_session.progress_at(event.kind, &event.message, event.at);
                }
                let deployment_count = report
                    .deployment_retries
                    .iter()
                    .map(|item| item.entries.len())
                    .sum::<usize>();
                let counts = format!(
                    "ARI {}, renewals {}, deployment retries {}",
                    report.ari.entries.len(),
                    report.renewals.len(),
                    deployment_count,
                );
                let (kind, status) = if failed {
                    (MessageKind::Warning, "failed")
                } else if report.ari.cancelled
                    || report.renewals.was_cancelled()
                    || report.deployment_cancelled
                {
                    (MessageKind::Warning, "cancelled")
                } else {
                    (MessageKind::Info, "completed")
                };
                output_session.progress_at(
                    kind,
                    &format!("Maintenance cycle {cycle} {status}: {counts}"),
                    at,
                );
            }
            Ok(failed)
        }
        Err(error) => {
            let (message, _) = diagnostic(error.as_ref());
            if output_session.is_json() {
                output_session.stream_json(&serde_json::json!({
                    "event": "cycle",
                    "at": rfc3339(at)?,
                    "cycle": cycle,
                    "status": "failed",
                    "error": message,
                }))?;
            } else {
                output_session.progress_at(
                    MessageKind::Error,
                    &format!("Maintenance cycle {cycle} failed: {message}"),
                    at,
                );
            }
            Ok(true)
        }
    }
}

pub(crate) fn stopped(
    output_session: &crate::common::session::OutputSession,
    report: &crate::commands::daemon::DaemonStopped,
) -> CliResult<String> {
    let at = time::OffsetDateTime::now_utc();
    if output_session.is_json() {
        output_session.stream_json(&serde_json::json!({
            "event": "stopped",
            "at": rfc3339(at)?,
            "cycles": report.cycles,
            "failed_cycles": report.failed_cycles,
        }))?;
    } else {
        output_session.progress_at(
            MessageKind::Info,
            &format!(
                "Daemon stopped after {} cycle(s); {} failed.",
                report.cycles, report.failed_cycles
            ),
            at,
        );
    }
    Ok(String::new())
}

fn rfc3339(at: time::OffsetDateTime) -> CliResult<String> {
    Ok(at.format(&time::format_description::well_known::Rfc3339)?)
}

pub(crate) fn render_stopped(
    report: &crate::commands::daemon::DaemonStopped,
    format: Format,
) -> CliResult<String> {
    if format.json {
        return Ok(serde_json::to_string(&serde_json::json!({
            "event": "stopped",
            "cycles": report.cycles,
            "data_dir": report.data_dir,
        }))?);
    }
    Ok(format!(
        "{} Daemon stopped after {} maintenance cycle(s).",
        MessageKind::Info.badge(format.color),
        report.cycles
    ))
}

pub(crate) fn status(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Refreshed => "refreshed",
        Outcome::RetryScheduled => "retry scheduled",
        Outcome::Unavailable => "ARI unavailable",
        Outcome::Skipped => "no longer due",
        Outcome::Failed(_) => "failed",
        Outcome::Cancelled => "cancelled",
        Outcome::NotStarted => "not started",
    }
}

pub(crate) fn render(
    report: &crate::commands::daemon::DaemonReport,
    format: Format,
) -> CliResult<String> {
    if format.json {
        return Ok(serde_json::to_string_pretty(&report_output(report)?)?);
    }

    if report.ari.entries.is_empty()
        && report.renewals.is_empty()
        && report.deployment_retries.is_empty()
    {
        let (kind, message) = if report.ari.cancelled
            || report.renewals.was_cancelled()
            || report.deployment_cancelled
        {
            (
                MessageKind::Warning,
                "Maintenance cancelled before any certificate work was started.",
            )
        } else {
            (
                MessageKind::Info,
                "No ARI refreshes, automatic renewals, or deployment retries were due.",
            )
        };
        return Ok(format!("{} {message}", kind.badge(format.color)));
    }
    let mut sections = Vec::with_capacity(2 + report.deployment_retries.len());
    if !report.ari.entries.is_empty() {
        sections.push(render_ari(&report.ari, format)?);
    }
    if !report.renewals.is_empty() {
        sections.push(crate::commands::cert::render::batch::batch(
            &report.renewals,
            format,
            &report.data_dir,
        )?);
    }
    for deployment in &report.deployment_retries {
        sections.push(
            crate::commands::cert::render::deployment::deployment_report(deployment, format)?,
        );
    }
    Ok(sections.join("\n\n"))
}

fn render_ari(report: &aster_acme::maintenance::Report, format: Format) -> CliResult<String> {
    if format.json {
        return Ok(serde_json::to_string(&ari_output(report)?)?);
    }
    if report.entries.is_empty() {
        return Ok("No ARI refreshes were due.".into());
    }
    let mut rows = vec![[
        "NAME".into(),
        "ARI STATUS".into(),
        "NEXT RENEWAL (UTC)".into(),
        "ARI NEXT CHECK (UTC)".into(),
        "ERROR".into(),
    ]];
    for entry in &report.entries {
        let error = match &entry.outcome {
            Outcome::Failed(error) => diagnostic(error).0,
            _ => "—".into(),
        };
        rows.push([
            entry.name.as_str().into(),
            status(&entry.outcome).into(),
            timestamp(entry.renew_at),
            timestamp(entry.next_check_at),
            error,
        ]);
    }
    let kind = if report.cancelled {
        MessageKind::Warning
    } else if report
        .entries
        .iter()
        .any(|entry| matches!(entry.outcome, Outcome::Failed(_)))
    {
        MessageKind::Error
    } else if report.entries.iter().any(|entry| {
        matches!(
            entry.outcome,
            Outcome::RetryScheduled | Outcome::Unavailable
        )
    }) {
        MessageKind::Warning
    } else {
        MessageKind::Info
    };
    let mut lines = vec![format!(
        "{} ARI maintenance results:",
        kind.badge(format.color)
    )];
    lines.extend(table::listing(
        &rows,
        format.color,
        |row, column| match column {
            1 => match report.entries[row].outcome {
                Outcome::Refreshed => Style::Green,
                Outcome::Failed(_) => Style::Red,
                Outcome::RetryScheduled
                | Outcome::Unavailable
                | Outcome::Cancelled
                | Outcome::NotStarted => Style::Yellow,
                Outcome::Skipped => Style::Cyan,
            },
            _ => Style::Plain,
        },
    ));
    if report.cancelled {
        lines.push("Maintenance interrupted; completed observations are saved.".into());
    }
    lines.push(output::tips("Unchanged ARI windows retain the selected renewal time. Failures retain existing plans; manual validation methods are skipped and eligible renewals run configured deployments.", format.color));
    Ok(lines.join("\n"))
}

#[derive(serde::Serialize)]
struct MaintenanceOutput<'a> {
    cancelled: bool,
    ari: AriOutput<'a>,
    renewal: crate::commands::cert::render::batch::BatchOutput<'a>,
    deployment_retries: Vec<crate::commands::cert::render::deployment::DeploymentReportOutput<'a>>,
}

#[derive(serde::Serialize)]
struct AriOutput<'a> {
    entries: Vec<AriEntryOutput<'a>>,
    cancelled: bool,
}

fn report_output(
    report: &crate::commands::daemon::DaemonReport,
) -> CliResult<MaintenanceOutput<'_>> {
    Ok(MaintenanceOutput {
        cancelled: report.ari.cancelled
            || report.renewals.was_cancelled()
            || report.deployment_cancelled,
        ari: ari_output(&report.ari)?,
        renewal: crate::commands::cert::render::batch::batch_output(
            &report.renewals,
            &report.data_dir,
        ),
        deployment_retries: report
            .deployment_retries
            .iter()
            .map(crate::commands::cert::render::deployment::deployment_output)
            .collect(),
    })
}

#[derive(serde::Serialize)]
struct AriEntryOutput<'a> {
    name: &'a str,
    operation_id: &'a str,
    status: &'static str,
    error: Option<AriErrorOutput>,
    renew_at: Option<String>,
    next_check_at: Option<String>,
}

#[derive(serde::Serialize)]
struct AriErrorOutput {
    message: String,
}

fn ari_output(report: &aster_acme::maintenance::Report) -> CliResult<AriOutput<'_>> {
    let entries = report
        .entries
        .iter()
        .map(|entry| {
            Ok(AriEntryOutput {
                name: entry.name.as_str(),
                operation_id: &entry.operation_id,
                status: status(&entry.outcome),
                error: match &entry.outcome {
                    Outcome::Failed(error) => Some(AriErrorOutput {
                        message: error.to_string(),
                    }),
                    _ => None,
                },
                renew_at: entry.renew_at.map(rfc3339).transpose()?,
                next_check_at: entry.next_check_at.map(rfc3339).transpose()?,
            })
        })
        .collect::<CliResult<Vec<_>>>()?;
    Ok(AriOutput {
        entries,
        cancelled: report.cancelled,
    })
}
