//! Human and typed JSON presentation; never contains private keys or CSRs.
use crate::common::error::CliResult;
use crate::common::output;
use crate::common::output::field;
use crate::common::time::timestamp;
use aster_acme::issuance::{DnsRequirement, IssueOutcome, IssueRecord};
use serde::Serialize;
use std::io::{self, IsTerminal};

/// Labels describe execution progress without presenting Rust enum debug output.
pub(super) fn phase_label(phase: aster_acme_core::workflow::IssuancePhase) -> &'static str {
    use aster_acme_core::workflow::IssuancePhase;
    match phase {
        IssuancePhase::PreparingAccount => "preparing account",
        IssuancePhase::CreatingOrder => "creating order",
        IssuancePhase::Authorizing => "authorizing domains",
        IssuancePhase::AwaitingOrderReady => "waiting for order readiness",
        IssuancePhase::Finalizing => "submitting CSR",
        IssuancePhase::AwaitingCertificate => "waiting for certificate",
        IssuancePhase::Downloading => "saving certificate",
        IssuancePhase::Completed => "completed",
    }
}

#[derive(Serialize)]
struct OrderView<'a> {
    #[serde(flatten)]
    operation: &'a IssueRecord,
    expired_locally: bool,
    verified: bool,
    source: &'static str,
}

pub(super) fn list(records: &[IssueRecord], json: bool) -> CliResult<String> {
    if json {
        return show(records, true, false);
    }
    if records.is_empty() {
        return Ok("No saved certificate requests.".into());
    }
    let now = time::OffsetDateTime::now_utc();
    let color = output::colors(io::stdout().is_terminal());
    let mut rows = vec![[
        "NAME".into(),
        "REQUESTED (UTC)".into(),
        "PHASE".into(),
        "CA STATUS".into(),
        "EXPIRES (UTC)".into(),
        "ACCOUNT".into(),
    ]];
    for record in records {
        rows.push([
            output::safe(record.name.as_str()),
            timestamp(Some(record.created_at)),
            if record.expired(now) {
                "expired locally".into()
            } else {
                phase_label(record.phase).into()
            },
            record.order.as_ref().map_or_else(
                || "not observed".into(),
                |order| String::from(order.status.clone()),
            ),
            timestamp(record.order.as_ref().and_then(|order| order.expires)),
            output::safe(&record.account_name),
        ]);
    }
    let mut lines = vec!["Local orders (remote status not verified; times in UTC):".into()];
    for (index, line) in crate::common::table::align(&rows).into_iter().enumerate() {
        let style = if index == 0 {
            "1;36"
        } else if records[index - 1].expired(now) {
            "33"
        } else if !records[index - 1].unfinished() {
            "32"
        } else {
            ""
        };
        lines.push(output::styled(&line, style, color && !style.is_empty()));
    }
    lines.push(output::tips(
        "Use cert show <NAME> for request IDs, CA details and TXT records.",
        color,
    ));
    Ok(lines.join("\n"))
}

pub(super) fn show(records: &[IssueRecord], json: bool, verified: bool) -> CliResult<String> {
    let now = time::OffsetDateTime::now_utc();
    if json {
        let views = records
            .iter()
            .map(|operation| OrderView {
                operation,
                expired_locally: operation.expired(now),
                verified,
                source: if verified { "remote" } else { "local" },
            })
            .collect::<Vec<_>>();
        return Ok(serde_json::to_string_pretty(&views)?);
    }
    if records.is_empty() {
        return Ok("No saved certificate requests.".into());
    }
    let color = output::colors(io::stdout().is_terminal());
    Ok(records
        .iter()
        .map(|record| show_text(record, now, color, verified))
        .collect::<Vec<_>>()
        .join("\n\n"))
}

fn show_text(
    record: &IssueRecord,
    now: time::OffsetDateTime,
    color: bool,
    verified: bool,
) -> String {
    use aster_acme_core::protocol::OrderStatus;
    let expired = record.expired(now);
    let phase_style = if expired {
        "33"
    } else if !record.unfinished() {
        "32"
    } else {
        "33"
    };
    let mut lines = vec![
        output::styled(&output::safe(record.name.as_str()), "1;36", color),
        field("Request:", &record.operation_id, color),
        field("Requested:", &timestamp(Some(record.created_at)), color),
        field(
            "Domains:",
            &record
                .identifiers
                .iter()
                .map(aster_acme::identifier::DnsIdentifier::value)
                .collect::<Vec<_>>()
                .join(", "),
            color,
        ),
        field(
            "Phase:",
            &output::styled(
                if expired {
                    "expired locally"
                } else {
                    phase_label(record.phase)
                },
                phase_style,
                color,
            ),
            color,
        ),
        field("CA:", &output::safe(record.directory.as_str()), color),
    ];
    let (status, status_style) = record.order.as_ref().map_or_else(
        || ("not observed".into(), "33"),
        |order| {
            let style = match &order.status {
                OrderStatus::Valid => "32",
                OrderStatus::Invalid | OrderStatus::Unknown(_) => "31",
                OrderStatus::Pending | OrderStatus::Ready | OrderStatus::Processing => "33",
            };
            (String::from(order.status.clone()), style)
        },
    );
    lines.push(field(
        "Order status:",
        &output::styled(&output::safe(&status), status_style, color),
        color,
    ));
    let deadline_text = timestamp(record.order.as_ref().and_then(|order| order.expires));
    lines.push(field(
        "Order expires:",
        &output::styled(&deadline_text, "33", color && expired),
        color,
    ));
    lines.extend(authorization_lines(record, color));
    if let Some(order) = &record.order
        && let Some(problem) = &order.error
    {
        lines.push(field(
            "CA error:",
            &output::styled(
                &output::safe(problem.detail.as_deref().unwrap_or(&problem.kind)),
                "31",
                color,
            ),
            color,
        ));
    }
    if let Some(at) = record.certificate_not_after {
        let style = if at <= now { "31" } else { "32" };
        lines.push(field(
            "Certificate expires:",
            &output::styled(&timestamp(Some(at)), style, color),
            color,
        ));
    }
    lines.push(field(
        "Remote status:",
        &output::styled(
            if verified {
                "verified with CA"
            } else {
                "not verified. Use cert show --verify to query the CA"
            },
            if verified { "32" } else { "33" },
            color,
        ),
        color,
    ));
    lines.join("\n")
}

fn authorization_lines(record: &IssueRecord, color: bool) -> Vec<String> {
    use aster_acme_core::protocol::AuthorizationStatus;
    let mut lines = Vec::new();
    for authorization in &record.authorizations {
        let domain = output::safe(&authorization.resource.identifier.value);
        let style = match &authorization.resource.status {
            AuthorizationStatus::Valid => "32",
            AuthorizationStatus::Pending => "33",
            AuthorizationStatus::Expired
            | AuthorizationStatus::Deactivated
            | AuthorizationStatus::Revoked
            | AuthorizationStatus::Invalid
            | AuthorizationStatus::Unknown(_) => "31",
        };
        let status = output::safe(&String::from(authorization.resource.status.clone()));
        lines.push(field(
            "Authorization:",
            &format!(
                "{domain} | {} | expires {}",
                output::styled(&status, style, color),
                timestamp(authorization.resource.expires)
            ),
            color,
        ));
        if let Some(dns) = &authorization.dns {
            lines.push(format!(
                "    {} {} = {}",
                output::styled("Manual TXT retained:", "33", color),
                output::safe(&dns.name),
                output::safe(&dns.value)
            ));
        }
    }
    lines
}

#[derive(Serialize)]
struct ResultOutput<'a> {
    status: &'static str,
    operation: &'a IssueRecord,
    records: &'a [DnsRequirement],
    resume: Option<String>,
    artifacts: Option<ArtifactPaths>,
}

#[derive(Serialize)]
struct ArtifactPaths {
    fullchain: std::path::PathBuf,
    certificate: std::path::PathBuf,
    ca_chain: std::path::PathBuf,
    private_key: std::path::PathBuf,
}

pub(super) fn outcome(
    outcome: &IssueOutcome,
    json: bool,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    let (status, record, records) = match outcome {
        IssueOutcome::ActionRequired { record, records } => {
            ("action_required", record.as_ref(), records.as_slice())
        }
        IssueOutcome::Completed { record, cleanup } => {
            ("completed", record.as_ref(), cleanup.as_slice())
        }
    };
    let resume = matches!(outcome, IssueOutcome::ActionRequired { .. }).then(|| {
        format!(
            "aster-acme cert issue --resume '{}' --operation {}",
            record.name.as_str(),
            record.operation_id
        )
    });
    let artifacts = matches!(outcome, IssueOutcome::Completed { .. }).then(|| {
        let generation = data_dir
            .join("certs")
            .join(record.name.as_str())
            .join("current");
        ArtifactPaths {
            fullchain: generation.join("fullchain.pem"),
            certificate: generation.join("cert.pem"),
            ca_chain: generation.join("ca.pem"),
            private_key: generation.join("private-key.pem"),
        }
    });
    if json {
        return Ok(serde_json::to_string_pretty(&ResultOutput {
            status,
            operation: record,
            records,
            resume,
            artifacts,
        })?);
    }
    let color = output::colors(io::stdout().is_terminal());
    let (label, style, message) = if resume.is_some() {
        ("[WARN]", "1;33", "Action required for")
    } else {
        ("[DONE]", "1;32", "Issued certificate")
    };
    let mut lines = vec![format!(
        "{} {message} {}",
        output::styled(label, style, color),
        output::safe(record.name.as_str())
    )];
    lines.push(format!("  Request: {}", record.operation_id));
    if let Some(paths) = artifacts {
        lines.push(format!(
            "  Full chain: {}",
            output::safe(&paths.fullchain.display().to_string())
        ));
        lines.push(format!(
            "  Certificate: {}",
            output::safe(&paths.certificate.display().to_string())
        ));
        lines.push(format!(
            "  CA chain: {}",
            output::safe(&paths.ca_chain.display().to_string())
        ));
        lines.push(format!(
            "  Private key: {}",
            output::safe(&paths.private_key.display().to_string())
        ));
    }
    if !records.is_empty() {
        lines.push(
            if resume.is_some() {
                "Add every TXT value below. Values at the same name must coexist:"
            } else {
                "Validation finished. You may remove these specific manual TXT values:"
            }
            .into(),
        );
        for record in records {
            lines.push(format!(
                "  {}  TXT  {}",
                output::safe(&record.name),
                output::safe(&record.value)
            ));
        }
    }
    if resume.is_some() {
        lines.push(format!(
            "To resume, run:\n  aster-acme cert issue --resume '{}'",
            record.name.as_str()
        ));
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn details_style_statuses_and_keep_human_times_fixed_without_altering_json() {
        let record:IssueRecord=serde_json::from_value(serde_json::json!({
            "solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"example.com",
            "created_at":"2026-01-01T00:00:00.123456Z","account_name":"default","account_id":"id","account_thumbprint":"key",
            "directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],
            "phase":"completed","creation_submitted":true,"order_url":"https://ca.example/order","finalize_submitted":"submitted",
            "order":{"status":"valid","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[],"finalize":"https://ca.example/finalize"},
            "authorizations":[],"certificate_not_after":"2099-01-01T00:00:00Z"
        })).unwrap();
        let colored = show_text(&record, time::OffsetDateTime::now_utc(), true, false);
        assert!(colored.contains("\x1b[32mcompleted\x1b[0m"));
        assert!(colored.contains("\x1b[32mvalid\x1b[0m"));
        assert!(colored.contains("2026-01-01 00:00:00 UTC"));
        assert!(!colored.contains(".123456"));
        let plain = show_text(&record, time::OffsetDateTime::now_utc(), false, false);
        assert!(!plain.contains('\x1b'));
        let machine = show(std::slice::from_ref(&record), true, false).unwrap();
        assert!(machine.contains("2026-01-01T00:00:00.123456Z"));
        assert!(!machine.contains('\x1b'));
        let result = IssueOutcome::Completed {
            record: Box::new(record),
            cleanup: vec![],
        };
        let output = outcome(&result, true, std::path::Path::new("/data")).unwrap();
        let fields: serde_json::Value = serde_json::from_str(&output).unwrap();
        for (key, file) in [
            ("fullchain", "fullchain.pem"),
            ("certificate", "cert.pem"),
            ("ca_chain", "ca.pem"),
            ("private_key", "private-key.pem"),
        ] {
            assert_eq!(
                fields["artifacts"][key],
                format!("/data/certs/example.com/current/{file}")
            );
        }
    }
}
