//! One final maintenance document, using shared time/table/error policies.
use crate::common::{
    error::{CliResult, diagnostic},
    output::{self, MessageKind, Style},
    session::Format,
    table,
    time::timestamp,
};
use aster_acme::maintenance::Outcome;

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

pub(crate) fn render(report: &super::DaemonReport, format: Format) -> CliResult<String> {
    if format.json {
        let ari_value: serde_json::Value =
            serde_json::from_str(&render_ari(&report.ari, Format::plain(true))?)?;
        let renewal_value: serde_json::Value =
            serde_json::from_str(&crate::commands::cert::render::batch(
                &report.renewals,
                Format::plain(true),
                &report.data_dir,
            )?)?;
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "cancelled": report.ari.cancelled || report.renewals.was_cancelled(),
            "ari": ari_value,
            "renewal": renewal_value,
        }))?);
    }
    let ari = render_ari(&report.ari, format)?;
    let renewal = crate::commands::cert::render::batch(&report.renewals, format, &report.data_dir)?;
    Ok(format!("{ari}\n\n{renewal}"))
}

fn render_ari(report: &aster_acme::maintenance::Report, format: Format) -> CliResult<String> {
    if format.json {
        let entries = report.entries.iter().map(|entry| {
            let error = match &entry.outcome {
                Outcome::Failed(error) => Some(serde_json::json!({"message": error.to_string()})),
                _ => None,
            };
            Ok(serde_json::json!({"name":entry.name.as_str(),"operation_id":entry.operation_id,"status":status(&entry.outcome),"error":error,"renew_at":entry.renew_at.map(|at|at.format(&time::format_description::well_known::Rfc3339)).transpose()?,"next_check_at":entry.next_check_at.map(|at|at.format(&time::format_description::well_known::Rfc3339)).transpose()?}))
        }).collect::<CliResult<Vec<_>>>()?;
        return Ok(serde_json::to_string(
            &serde_json::json!({"entries":entries,"cancelled":report.cancelled}),
        )?);
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
