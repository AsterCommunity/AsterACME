//! Offline deployment details; no filesystem access, process execution or CA queries.

use crate::common::time::timestamp;
use crate::common::{
    error::CliResult,
    output::{self, Style, field},
    session::Format,
};
use aster_acme_cli_storage::issuance::{DeploymentBinding, DeploymentTarget};
use serde::Serialize;
use std::path::Path;

pub(crate) fn event(event: &crate::commands::cert::report::DeploymentEvent, color: bool) -> String {
    let mut lines = event.message.lines();
    let title = lines.next().unwrap_or("");
    let details = lines.map(str::to_owned).collect::<Vec<_>>();
    crate::common::log::render(event.kind, title, &details, event.at, color)
}

pub(super) fn details(
    name: &str,
    binding: &DeploymentBinding,
    format: Format,
) -> CliResult<String> {
    if format.json {
        #[derive(Serialize)]
        struct View<'a> {
            certificate: &'a str,
            deployment: &'a DeploymentBinding,
            observation: &'static str,
        }
        return Ok(serde_json::to_string_pretty(&View {
            certificate: name,
            deployment: binding,
            observation: "saved local state",
        })?);
    }
    let mut lines = vec![
        output::styled(
            &format!(
                "Deployment '{}' for {}",
                output::safe(&binding.id),
                output::safe(name)
            ),
            Style::BoldCyan,
            format.color,
        ),
        field("Certificate name:", &output::safe(name), format.color),
        field("Deployment:", &output::safe(&binding.id), format.color),
    ];
    lines.extend(target_lines(&binding.target, format.color));
    let reload = if binding.reload_command.is_empty() {
        "not configured (file publication only)".into()
    } else {
        shlex::try_join(binding.reload_command.iter().map(String::as_str))?
    };
    let (phase, style) = deployment_phase(binding.phase);
    for (label, value) in [
        ("Reload command:", output::safe(&reload)),
        (
            "Reload timeout:",
            format!("{} seconds per attempt", binding.timeout_seconds),
        ),
        ("Extra reload retries:", binding.max_retries.to_string()),
        (
            "Certificate file mode:",
            mode(binding.permissions.file_mode),
        ),
        ("Private-key mode:", mode(binding.permissions.key_mode)),
        (
            "Last generation:",
            binding
                .generation
                .as_deref()
                .map_or_else(|| "—".into(), output::safe),
        ),
        (
            "Pending generation:",
            binding
                .pending_generation
                .as_deref()
                .map_or_else(|| "—".into(), output::safe),
        ),
        ("Saved status:", output::styled(phase, style, format.color)),
        ("Reload attempts:", binding.attempts.to_string()),
        (
            "Last error:",
            binding
                .last_error
                .as_deref()
                .map_or_else(|| "—".into(), output::safe),
        ),
        (
            "Observation:",
            "saved local state; service health not queried".into(),
        ),
    ] {
        lines.push(field(label, &value, format.color));
    }
    Ok(lines.join("\n"))
}

fn mode(value: Option<u32>) -> String {
    value.map_or_else(
        || {
            if cfg!(unix) {
                "0600 (default)".into()
            } else {
                "platform inherited permissions".into()
            }
        },
        |mode| format!("{mode:04o}"),
    )
}

fn target_lines(target: &DeploymentTarget, color: bool) -> Vec<String> {
    let mut lines = Vec::new();
    match target {
        DeploymentTarget::Directory { path } => {
            lines.push(field("Target mode:", "directory", color));
            lines.push(field(
                "Target directory:",
                &output::safe(&path.display().to_string()),
                color,
            ));
            for (label, file) in [
                ("Certificate:", "cert.pem"),
                ("Private key:", "private-key.pem"),
                ("CA chain:", "ca.pem"),
                ("Full chain:", "fullchain.pem"),
            ] {
                lines.push(field(label, &path_text(Some(&path.join(file))), color));
            }
        }
        DeploymentTarget::Files {
            certificate,
            private_key,
            ca_chain,
            fullchain,
        } => {
            lines.push(field("Target mode:", "exact files", color));
            for (label, path) in [
                ("Certificate:", certificate),
                ("Private key:", private_key),
                ("CA chain:", ca_chain),
                ("Full chain:", fullchain),
            ] {
                lines.push(field(label, &path_text(path.as_deref()), color));
            }
        }
    }
    lines
}

fn path_text(path: Option<&Path>) -> String {
    path.map_or_else(
        || "not configured".into(),
        |path| output::safe(&path.display().to_string()),
    )
}

#[cfg(test)]
mod tests;

#[derive(Serialize)]
pub(in crate::commands::cert::render) struct DeploymentStatusView<'a> {
    pub(super) id: &'a str,
    generation: Option<&'a str>,
    pending_generation: Option<&'a str>,
    phase: aster_acme::deployment::DeploymentPhase,
    attempts: u8,
    retry_failures: u32,
    #[serde(with = "time::serde::rfc3339::option")]
    retry_at: Option<time::OffsetDateTime>,
    last_error: Option<&'a str>,
    pub(super) execution_error: Option<&'a str>,
}

impl<'a> From<&'a aster_acme_cli_storage::issuance::DeploymentBinding>
    for DeploymentStatusView<'a>
{
    fn from(binding: &'a aster_acme_cli_storage::issuance::DeploymentBinding) -> Self {
        Self {
            id: &binding.id,
            generation: binding.generation.as_deref(),
            pending_generation: binding.pending_generation.as_deref(),
            phase: binding.phase,
            attempts: binding.attempts,
            retry_failures: binding.retry_failures,
            retry_at: binding.retry_at,
            last_error: binding.last_error.as_deref(),
            execution_error: None,
        }
    }
}

pub(in crate::commands::cert::render) fn deployment_removed(
    name: &str,
    id: &str,
    format: Format,
) -> CliResult<String> {
    #[derive(Serialize)]
    struct View<'a> {
        status: &'static str,
        certificate: &'a str,
        deployment: &'a str,
    }
    if format.json {
        return Ok(serde_json::to_string_pretty(&View {
            status: "removed",
            certificate: name,
            deployment: id,
        })?);
    }
    Ok(format!(
        "{} Deployment '{}' removed.",
        output::MessageKind::Done.badge(format.color),
        output::safe(id)
    ))
}

pub(crate) fn deployment_report(
    report: &crate::commands::cert::report::DeploymentReport,
    format: Format,
) -> CliResult<String> {
    #[derive(Serialize)]
    struct View<'a> {
        certificate: &'a str,
        deployments: Vec<DeploymentStatusView<'a>>,
        events: &'a [crate::commands::cert::report::DeploymentEvent],
    }
    if format.json {
        return Ok(serde_json::to_string_pretty(&View {
            certificate: &report.name,
            events: &report.events,
            deployments: report
                .entries
                .iter()
                .map(|binding| {
                    let mut view = DeploymentStatusView::from(binding);
                    view.execution_error = current_error(&report.events, &binding.id);
                    view
                })
                .collect(),
        })?);
    }
    if report.entries.is_empty() {
        if !report.events.is_empty() {
            return Ok(report
                .events
                .iter()
                .map(|event| {
                    format!(
                        "{} {}",
                        event.kind.badge(format.color),
                        output::safe(&event.message)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"));
        }
        return Ok(format!(
            "No deployment targets configured for {}.\n{}",
            output::safe(&report.name),
            output::tips(
                "Use cert deploy add --help to configure a target.",
                format.color
            ),
        ));
    }
    Ok(deployment_table(
        &report.name,
        &report.entries,
        report.attempted,
        &report.events,
        format,
    ))
}

pub(in crate::commands::cert::render) fn deployment_table(
    name: &str,
    entries: &[aster_acme_cli_storage::issuance::DeploymentBinding],
    attempted: bool,
    events: &[crate::commands::cert::report::DeploymentEvent],
    format: Format,
) -> String {
    let mut rows = vec![[
        "DEPLOYMENT".into(),
        "GENERATION".into(),
        "STATUS".into(),
        "ATTEMPTS".into(),
        "RETRY AT (UTC)".into(),
        "ERROR".into(),
    ]];
    for entry in entries {
        let error = current_error(events, &entry.id);
        rows.push([
            entry.id.clone(),
            entry
                .pending_generation
                .clone()
                .or_else(|| entry.generation.clone())
                .unwrap_or_else(|| "—".into()),
            if error.is_some() {
                "execution failed".into()
            } else if entry.pending_generation.is_some() {
                "pending deployment".into()
            } else {
                deployment_phase(entry.phase).0.into()
            },
            entry.attempts.to_string(),
            timestamp(entry.retry_at),
            error
                .map(str::to_owned)
                .or_else(|| entry.last_error.clone())
                .unwrap_or_else(|| "—".into()),
        ]);
    }
    let mut lines = vec![format!(
        "Local deployments for {} (saved execution status):",
        output::safe(name)
    )];
    lines.extend(crate::common::table::listing(
        &rows,
        format.color,
        |row, column| match column {
            2 if current_error(events, &entries[row].id).is_some() => Style::Red,
            2 if entries[row].pending_generation.is_some() => Style::Yellow,
            2 => deployment_phase(entries[row].phase).1,
            _ => Style::Plain,
        },
    ));
    lines.push(output::tips(
        "Use cert deploy show CERT_NAME DEPLOY_NAME for configuration and saved execution details.",
        format.color,
    ));
    if attempted {
        lines.push(output::tips(
            "After checking the service, retry with cert deploy run CERT_NAME -n DEPLOY_NAME.",
            format.color,
        ));
    }
    lines.join("\n")
}

pub(in crate::commands::cert::render) fn current_error<'a>(
    events: &'a [crate::commands::cert::report::DeploymentEvent],
    id: &str,
) -> Option<&'a str> {
    events
        .iter()
        .rev()
        .find(|event| {
            event.kind == output::MessageKind::Error && event.deployment.as_deref() == Some(id)
        })
        .map(|event| event.message.as_str())
}

pub(in crate::commands::cert::render) fn deployment_phase(
    phase: aster_acme::deployment::DeploymentPhase,
) -> (&'static str, Style) {
    use aster_acme::deployment::DeploymentPhase;
    match phase {
        DeploymentPhase::Configured => ("configured", Style::Yellow),
        DeploymentPhase::Publishing => ("publishing", Style::Yellow),
        DeploymentPhase::PublishFailed => ("publication failed", Style::Red),
        DeploymentPhase::PublicationComplete => ("published; reload not run", Style::Yellow),
        DeploymentPhase::Reloading => ("reloading", Style::Yellow),
        DeploymentPhase::ReloadFailed => ("reload failed", Style::Red),
        DeploymentPhase::ReloadUncertain => ("reload unconfirmed", Style::Yellow),
        DeploymentPhase::Deployed => ("deployed", Style::Green),
    }
}
