//! Lifecycle report presentation; no side effects.

use crate::commands::cert::render::details::renewal_lines;
use crate::common::error::CliResult;
use crate::common::output;
use crate::common::output::field;
use crate::common::session::Format;
use aster_acme::issuance::IssueRecord;
use aster_acme_core::revocation::RevocationState;
use serde::Serialize;

pub(in crate::commands::cert) fn removed(
    name: &str,
    scope: &aster_acme_cli_storage::issuance::removal::RemovalScope,
    ids: &[String],
    in_use_removed: bool,
    format: Format,
) -> CliResult<String> {
    use aster_acme_cli_storage::issuance::removal::RemovalScope;
    #[derive(Serialize)]
    struct CertificateDeletionOutput<'a> {
        name: &'a str,
        scope: &'static str,
        operation_ids: &'a [String],
        removed_locally: bool,
        generations: usize,
        in_use_removed: bool,
        ca_request_performed: bool,
    }
    let scope_label = match scope {
        RemovalScope::Operation(_) => "request",
        RemovalScope::History => "history",
        RemovalScope::Revoked => "revoked",
        RemovalScope::All => "all",
        RemovalScope::Failed => "failed",
    };
    if format.json {
        return Ok(serde_json::to_string_pretty(&CertificateDeletionOutput {
            name,
            scope: scope_label,
            operation_ids: ids,
            removed_locally: !ids.is_empty() || matches!(scope, RemovalScope::All),
            generations: ids.len(),
            in_use_removed,
            ca_request_performed: false,
        })?);
    }
    let color = format.color;
    let message = match scope {
        RemovalScope::Failed if ids.is_empty() => format!(
            "No terminally failed requests to remove for {}.",
            output::safe(name)
        ),
        RemovalScope::Failed => format!(
            "Removed {} terminally failed certificate request(s) for {}.",
            ids.len(),
            output::safe(name)
        ),
        RemovalScope::Operation(_) => format!(
            "Removed local certificate request for {}.",
            output::safe(name)
        ),
        RemovalScope::All => format!(
            "Removed all local certificate requests for {}.",
            output::safe(name)
        ),
        RemovalScope::History if ids.is_empty() => format!(
            "No historical issued versions to remove for {}.",
            output::safe(name)
        ),
        RemovalScope::History => format!(
            "Removed {} historical certificate version(s) for {}.",
            ids.len(),
            output::safe(name)
        ),
        RemovalScope::Revoked if ids.is_empty() => format!(
            "No confirmed revoked versions to remove for {}.",
            output::safe(name)
        ),
        RemovalScope::Revoked => format!(
            "Removed {} confirmed revoked certificate version(s) for {}.",
            ids.len(),
            output::safe(name)
        ),
    };
    let mut lines = vec![format!(
        "{} {message}",
        crate::common::output::MessageKind::Success.badge(color)
    )];
    if in_use_removed {
        lines.push(field(
            "In use:",
            "cleared; no historical version selected",
            color,
        ));
    }
    Ok(lines.join("\n"))
}

pub(in crate::commands::cert) fn revoked(
    record: &IssueRecord,
    format: Format,
) -> CliResult<String> {
    #[derive(Serialize)]
    struct RevokedOutput<'a> {
        status: &'static str,
        operation: &'a IssueRecord,
    }
    match record.revocation.state {
        RevocationState::Confirmed => {}
        RevocationState::NotRequested | RevocationState::Pending => {
            return Err(
                "Cannot report certificate revocation as successful without CA confirmation."
                    .into(),
            );
        }
    }
    if format.json {
        return Ok(serde_json::to_string_pretty(&RevokedOutput {
            status: "revoked",
            operation: record,
        })?);
    }
    let color = format.color;
    let mut lines = vec![format!(
        "{} Revoked certificate {}. Local files retained.",
        crate::common::output::MessageKind::Success.badge(color),
        output::safe(record.name.as_str())
    )];
    if let Some(signer) = &record.revocation.signer {
        lines.push(field("Sign with:", signer.method().name(), color));
    }
    lines.extend(renewal_lines(
        record,
        time::OffsetDateTime::now_utc(),
        color,
    ));
    Ok(lines.join("\n"))
}
