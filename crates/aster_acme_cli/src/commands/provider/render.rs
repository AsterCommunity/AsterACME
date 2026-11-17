//! Provider report presentation.
use crate::commands::provider::report::{ProfileView, ProviderReport};
use crate::common::{
    error::CliResult,
    output::{MessageKind, Style, field, safe, styled},
    session::Format,
};

pub(crate) fn render(report: &ProviderReport, format: Format) -> CliResult<String> {
    if format.json {
        return Ok(serde_json::to_string_pretty(report)?);
    }
    if let Some(name) = &report.removed {
        return Ok(format!(
            "{} Removed provider profile {}.",
            MessageKind::Success.badge(format.color),
            safe(name)
        ));
    }
    if report.operation == "cleanup" {
        return Ok(render_cleanup(report, format.color));
    }
    if report.operation == "backends" {
        let mut rows = vec![["BACKEND ID".into(), "NAME".into(), "CONFIGURATION".into()]];
        for backend in &report.backends {
            rows.push([
                backend.id.into(),
                backend.label.into(),
                backend
                    .fields
                    .iter()
                    .map(|field| field.name)
                    .collect::<Vec<_>>()
                    .join(", "),
            ]);
        }
        return Ok(
            crate::common::table::listing(&rows, format.color, |_, _| Style::Plain).join("\n"),
        );
    }
    if report.profiles.is_empty() {
        return Ok("No DNS provider profiles configured.".into());
    }
    if report.operation == "listed" {
        let mut rows = vec![["NAME".into(), "BACKEND".into(), "ALLOWED ZONES".into()]];
        for profile in &report.profiles {
            rows.push([
                profile.name.clone(),
                profile.backend_id.clone(),
                if profile.allowed_zones.is_empty() {
                    "all (unrestricted)".into()
                } else {
                    profile.allowed_zones.join(", ")
                },
            ]);
        }
        return Ok(
            crate::common::table::listing(&rows, format.color, |_, column| {
                if column == 0 {
                    Style::Green
                } else {
                    Style::Plain
                }
            })
            .join("\n"),
        );
    }
    let mut lines = vec![styled(
        &match report.operation {
            "added" => "Added DNS provider profile.".to_owned(),
            "updated" => "Updated DNS provider profile.".to_owned(),
            "shown" => "DNS provider profile:".to_owned(),
            _ => "DNS provider profiles:".to_owned(),
        },
        Style::BoldCyan,
        format.color,
    )];
    for profile in &report.profiles {
        lines.extend(detail_lines(profile, format.color)?);
    }
    Ok(lines.join("\n").trim_end().to_owned())
}

pub(super) fn detail_lines(profile: &ProfileView, color: bool) -> CliResult<Vec<String>> {
    let mut lines = vec![
        field(
            "Name:",
            &styled(&safe(&profile.name), Style::BoldGreen, color),
            color,
        ),
        field(
            "Requested TTL (seconds):",
            &profile.ttl_seconds.to_string(),
            color,
        ),
        field("Backend:", &safe(&profile.backend_id), color),
        field(
            "Backend config version:",
            &profile.backend_config_version.to_string(),
            color,
        ),
    ];
    if !profile.executable.as_os_str().is_empty() {
        lines.push(field(
            "Executable:",
            &safe(&profile.executable.to_string_lossy()),
            color,
        ));
    }
    lines.push(field(
        "Profile file:",
        &safe(&profile.profile_path.to_string_lossy()),
        color,
    ));
    lines.push(field(
        "Allowed zones:",
        &if profile.allowed_zones.is_empty() {
            "all (unrestricted)".to_owned()
        } else {
            safe(&profile.allowed_zones.join(", "))
        },
        color,
    ));
    lines.push(field(
        "Profile version:",
        &profile.profile_version.to_string(),
        color,
    ));
    lines.push(field("Custom values:", &profile.custom_values, color));
    if !profile.args.is_empty() {
        lines.push(field(
            "Arguments:",
            &safe(&serde_json::to_string(&profile.args)?),
            color,
        ));
    }
    Ok(lines)
}

fn render_cleanup(report: &ProviderReport, color: bool) -> String {
    if report.cleanup.is_empty() {
        return if report.incomplete {
            "Provider cleanup deadline expired before all matching requests were examined.".into()
        } else {
            "No terminal DNS publication cleanup is pending for this provider.".into()
        };
    }
    let mut lines = report
        .cleanup
        .iter()
        .map(|item| {
            format!(
                "{} {}: {}{}",
                if item.completed {
                    MessageKind::Success
                } else {
                    MessageKind::Warning
                }
                .badge(color),
                safe(&item.certificate),
                if item.completed {
                    "cleanup complete"
                } else {
                    "cleanup pending"
                },
                item.error
                    .as_ref()
                    .map_or(String::new(), |error| format!(": {}", safe(error)))
            )
        })
        .collect::<Vec<_>>();
    if report.incomplete {
        lines.push(format!(
            "{} Provider cleanup did not examine all matching requests before its deadline.",
            MessageKind::Error.badge(color)
        ));
    }
    lines.join("\n")
}
