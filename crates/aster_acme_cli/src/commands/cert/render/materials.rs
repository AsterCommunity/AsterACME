//! Materials report presentation; no side effects.

use crate::common::output;
use aster_acme::issuance::ValidationRequirement;

/// Shared method-specific material presentation for prompts and final outcomes.
/// All strings are escaped before reaching the terminal.
pub(in crate::commands::cert) fn requirement_lines(
    requirements: &[ValidationRequirement],
) -> Vec<String> {
    let mut lines = Vec::new();
    for requirement in requirements {
        match requirement {
            ValidationRequirement::DnsPersist01 { record } => lines.push(format!(
                "{}  TXT  {}  (persistent; retain for renewal)",
                output::safe(record.name.as_str()),
                output::safe(&record.presentation_value())
            )),
            ValidationRequirement::Dns01 { name, value } => lines.push(format!(
                "{}  TXT  {}",
                output::safe(name),
                output::safe(value)
            )),
            ValidationRequirement::Http01 { url, path, content } => {
                lines.push(format!("URL: {}", output::safe(url)));
                lines.push(format!(
                    "File: {}",
                    output::safe(path.trim_start_matches('/'))
                ));
                lines.push(format!(
                    "Content (exact, no newline required): {}",
                    output::safe(content)
                ));
            }
            ValidationRequirement::TlsAlpn01 { domain, .. } => {
                lines.push(format!("TLS-ALPN: {}", output::safe(domain)));
            }
        }
    }
    lines
}
