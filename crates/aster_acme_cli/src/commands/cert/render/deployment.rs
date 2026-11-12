//! Offline deployment details; no filesystem access, process execution or CA queries.
use crate::commands::cert::render::deployment_phase;
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
