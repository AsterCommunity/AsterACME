//! Human and typed JSON presentation; never contains private keys or CSRs.
use crate::common::error::CliResult;
use crate::common::output;
use crate::common::output::field;
use crate::common::time::timestamp;
use aster_acme::issuance::{DnsRequirement, IssueOutcome, IssueRecord};
use aster_acme_core::revocation::RevocationState;
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

/// Shared request status for tables and generation selectors; revocation is explicit.
pub(super) fn request_status(record: &IssueRecord, now: time::OffsetDateTime) -> &'static str {
    match record.revocation.state {
        RevocationState::Confirmed => "revoked",
        RevocationState::Pending => "revocation pending",
        RevocationState::NotRequested if record.expired(now) => "expired locally",
        RevocationState::NotRequested if !record.unfinished() && !record.is_current => {
            "completed (historical)"
        }
        RevocationState::NotRequested => phase_label(record.phase),
    }
}

/// Compact SAN summary shared by the table and generation selector; full details stay in show.
pub(super) fn domain_summary(record: &IssueRecord) -> String {
    if record.identifiers.is_empty() {
        return output::safe(record.name.as_str());
    }
    let mut domains = record
        .identifiers
        .iter()
        .take(3)
        .map(aster_acme::identifier::DnsIdentifier::value)
        .collect::<Vec<_>>();
    let remaining = record.identifiers.len().saturating_sub(domains.len());
    if remaining > 0 {
        domains.push(format!("+{remaining}"));
    }
    output::safe(&domains.join(", "))
}

#[derive(Serialize)]
struct OrderView<'a> {
    #[serde(flatten)]
    operation: &'a IssueRecord,
    expired_locally: bool,
    renewal_due: bool,
    current: bool,
    ca_query: CaQuery,
    revocation_source: RevocationSource,
}

/// These observations describe this invocation, not the entire saved certificate.
#[derive(Serialize)]
struct CaQuery {
    order_refreshed: bool,
    authorizations_refreshed: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum RevocationSource {
    LocalState,
    SavedCaResponse,
}

impl From<RevocationState> for RevocationSource {
    fn from(state: RevocationState) -> Self {
        match state {
            RevocationState::NotRequested | RevocationState::Pending => Self::LocalState,
            RevocationState::Confirmed => Self::SavedCaResponse,
        }
    }
}

impl RevocationSource {
    const fn label(self) -> &'static str {
        match self {
            Self::LocalState => "local state",
            Self::SavedCaResponse => "saved CA response",
        }
    }
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
        "DOMAINS".into(),
        "CURRENT".into(),
        "REQUESTED (UTC)".into(),
        "PHASE".into(),
        "ORDER STATUS".into(),
        "CERT EXPIRES (UTC)".into(),
        "NEXT RENEWAL (UTC)".into(),
        "ACCOUNT".into(),
    ]];
    for record in records {
        rows.push([
            output::safe(record.name.as_str()),
            domain_summary(record),
            if record.is_current { "*" } else { "" }.into(),
            timestamp(Some(record.created_at)),
            request_status(record, now).into(),
            record.order.as_ref().map_or_else(
                || "not observed".into(),
                |order| String::from(order.status.clone()),
            ),
            timestamp(record.certificate_not_after),
            timestamp(
                record
                    .renewal
                    .as_ref()
                    .filter(|_| {
                        record.is_current
                            && matches!(record.revocation.state, RevocationState::NotRequested)
                    })
                    .map(|plan| plan.renew_at),
            ),
            output::safe(&record.account_name),
        ]);
    }
    let mut lines =
        vec!["Local certificates (CA order status from saved observations; times in UTC):".into()];
    for (index, line) in crate::common::table::align(&rows).into_iter().enumerate() {
        let style = if index == 0 {
            "1;36"
        } else if matches!(
            records[index - 1].revocation.state,
            RevocationState::Confirmed
        ) {
            "31"
        } else if matches!(
            records[index - 1].revocation.state,
            RevocationState::Pending
        ) || records[index - 1].expired(now)
        {
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
                renewal_due: operation.is_current
                    && matches!(operation.revocation.state, RevocationState::NotRequested)
                    && operation
                        .renewal
                        .as_ref()
                        .is_some_and(|plan| plan.renew_at <= now),
                current: operation.is_current,
                ca_query: CaQuery {
                    order_refreshed: verified,
                    authorizations_refreshed: verified,
                },
                revocation_source: operation.revocation.state.into(),
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
    let mut lines = request_lines(record, expired, color);
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
    lines.extend(revocation_lines(record, color));
    lines.extend(renewal_lines(record, now, color));
    lines.push(field(
        "CA query:",
        &output::styled(
            if verified {
                "order and authorizations refreshed"
            } else {
                "not performed (local data only)"
            },
            if verified { "32" } else { "33" },
            color,
        ),
        color,
    ));
    lines.join("\n")
}

// Immutable request identity and local progress, shared by offline and refreshed details.
fn request_lines(record: &IssueRecord, expired: bool, color: bool) -> Vec<String> {
    let phase_style = if !expired && !record.unfinished() {
        "32"
    } else {
        "33"
    };
    vec![
        output::styled(&output::safe(record.name.as_str()), "1;36", color),
        field("Request:", &record.operation_id, color),
        field(
            "Current:",
            if record.is_current { "yes" } else { "no" },
            color,
        ),
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
    ]
}

fn revocation_lines(record: &IssueRecord, color: bool) -> Vec<String> {
    let mut lines = Vec::new();
    let (revocation, style) = match record.revocation.state {
        RevocationState::NotRequested => ("not requested", ""),
        RevocationState::Pending => ("pending; CA outcome unconfirmed", "33"),
        RevocationState::Confirmed => ("confirmed revoked", "31"),
    };
    lines.push(field(
        "Revocation:",
        &output::styled(revocation, style, color && !style.is_empty()),
        color,
    ));
    lines.push(field(
        "Revocation source:",
        RevocationSource::from(record.revocation.state).label(),
        color,
    ));
    if let Some(at) = record.revocation.confirmed_at {
        lines.push(field("Revoked at:", &timestamp(Some(at)), color));
    }
    if let Some(at) = record.revocation.requested_at {
        lines.push(field("Revocation requested:", &timestamp(Some(at)), color));
    }
    if let Some(reason) = record.revocation.reason {
        lines.push(field("Revocation reason:", &reason.to_string(), color));
    }
    lines
}

fn renewal_lines(record: &IssueRecord, now: time::OffsetDateTime, color: bool) -> Vec<String> {
    match record.revocation.state {
        RevocationState::Confirmed => {
            return vec![field(
                "Next renewal:",
                &output::styled("disabled (revoked)", "31", color),
                color,
            )];
        }
        RevocationState::Pending => {
            return vec![field(
                "Next renewal:",
                &output::styled("suspended (revocation unconfirmed)", "33", color),
                color,
            )];
        }
        RevocationState::NotRequested => {}
    }
    let Some(plan) = &record.renewal else {
        return Vec::new();
    };
    if !record.is_current {
        return vec![
            field("Next renewal:", "not scheduled (historical version)", color),
            field(
                "Previous renewal plan:",
                &timestamp(Some(plan.renew_at)),
                color,
            ),
        ];
    }
    let source = match plan.source {
        aster_acme::renewal::RenewalSource::Ari => "ARI",
        aster_acme::renewal::RenewalSource::Fallback => "fallback (2/3 of certificate validity)",
    };
    let mut lines = vec![
        field(
            "Next renewal:",
            &output::styled(
                &timestamp(Some(plan.renew_at)),
                if plan.renew_at <= now { "33" } else { "32" },
                color,
            ),
            color,
        ),
        field("Renewal source:", source, color),
        field(
            "Renewal due:",
            if plan.renew_at <= now { "yes" } else { "no" },
            color,
        ),
    ];
    if let Some(window) = &plan.suggested_window {
        lines.push(field(
            "ARI window:",
            &format!(
                "{} — {}",
                timestamp(Some(window.start)),
                timestamp(Some(window.end))
            ),
            color,
        ));
    }
    if let Some(at) = plan.next_check_at {
        lines.push(field("ARI next check:", &timestamp(Some(at)), color));
    }
    if plan.last_query_failed {
        lines.push(field(
            "ARI status:",
            &output::styled(
                "query incomplete or failed; saved renewal time retained",
                "33",
                color,
            ),
            color,
        ));
    }
    if let Some(url) = &plan.explanation_url {
        lines.push(field("ARI explanation:", &output::safe(url), color));
    }
    lines
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
                output::styled("Saved validation TXT:", "33", color),
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
    if resume.is_none() {
        lines.extend(renewal_lines(
            record,
            time::OffsetDateTime::now_utc(),
            color,
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

pub(super) fn removed(
    name: &str,
    scope: &aster_acme_cli_storage::issuance::removal::RemovalScope,
    ids: &[String],
    current_removed: bool,
    json: bool,
) -> CliResult<String> {
    use aster_acme_cli_storage::issuance::removal::RemovalScope;
    #[derive(Serialize)]
    struct CertificateDeletionOutput<'a> {
        name: &'a str,
        scope: &'static str,
        operation_ids: &'a [String],
        removed_locally: bool,
        generations: usize,
        current_removed: bool,
        ca_request_performed: bool,
    }
    let scope_label = match scope {
        RemovalScope::Operation(_) => "request",
        RemovalScope::History => "history",
        RemovalScope::Revoked => "revoked",
        RemovalScope::All => "all",
    };
    if json {
        return Ok(serde_json::to_string_pretty(&CertificateDeletionOutput {
            name,
            scope: scope_label,
            operation_ids: ids,
            removed_locally: !ids.is_empty() || matches!(scope, RemovalScope::All),
            generations: ids.len(),
            current_removed,
            ca_request_performed: false,
        })?);
    }
    let color = output::colors(io::stdout().is_terminal());
    let message = match scope {
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
        output::styled("[OK]", "1;32", color)
    )];
    if current_removed {
        lines.push(field(
            "Current:",
            "cleared; no historical version selected",
            color,
        ));
    }
    Ok(lines.join("\n"))
}

pub(super) fn revoked(record: &IssueRecord, json: bool) -> CliResult<String> {
    #[derive(Serialize)]
    struct RevokedOutput<'a> {
        status: &'static str,
        operation: &'a IssueRecord,
    }
    if json {
        return Ok(serde_json::to_string_pretty(&RevokedOutput {
            status: "revoked",
            operation: record,
        })?);
    }
    let color = output::colors(io::stdout().is_terminal());
    let mut lines = vec![format!(
        "{} Revoked certificate {}. Local files retained.",
        output::styled("[OK]", "1;32", color),
        output::safe(record.name.as_str())
    )];
    lines.extend(renewal_lines(
        record,
        time::OffsetDateTime::now_utc(),
        color,
    ));
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
        let mut record = record;
        record.is_current = true;
        record.renewal = Some(serde_json::from_value(serde_json::json!({
            "certificate_id":"a.b","not_before":"2026-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z",
            "renew_at":"2026-02-01T00:00:00Z","source":"fallback","suggested_window":null,"explanation_url":null,
            "last_checked_at":null,"next_check_at":null,"last_query_failed":false
        })).unwrap());
        let colored = show_text(&record, time::OffsetDateTime::now_utc(), true, false);
        assert!(colored.contains("\x1b[32mcompleted\x1b[0m"));
        assert!(colored.contains("\x1b[32mvalid\x1b[0m"));
        assert!(colored.contains("2026-01-01 00:00:00 UTC"));
        assert!(!colored.contains(".123456"));
        let plain = show_text(&record, time::OffsetDateTime::now_utc(), false, false);
        assert!(!plain.contains('\x1b'));
        assert!(plain.contains("Next renewal:"));
        assert!(plain.contains("2026-02-01 00:00:00 UTC"));
        assert!(plain.contains("fallback (2/3 of certificate validity)"));
        assert!(
            list(std::slice::from_ref(&record), false)
                .unwrap()
                .contains("NEXT RENEWAL (UTC)")
        );
        let machine = show(std::slice::from_ref(&record), true, false).unwrap();
        assert!(machine.contains("2026-01-01T00:00:00.123456Z"));
        assert!(!machine.contains('\x1b'));
        let result = IssueOutcome::Completed {
            record: Box::new(record),
            cleanup: vec![],
        };
        let human = outcome(&result, false, std::path::Path::new("/data")).unwrap();
        assert!(human.contains("Next renewal:"));
        assert!(human.contains("2026-02-01 00:00:00 UTC"));
        assert!(human.find("Private key:").unwrap() < human.find("Next renewal:").unwrap());
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
        let IssueOutcome::Completed { record, .. } = &result else {
            panic!("completed result expected")
        };
        for state in [RevocationState::Pending, RevocationState::Confirmed] {
            let mut record = record.as_ref().clone();
            record.revocation.state = state;
            let human = show_text(&record, time::OffsetDateTime::now_utc(), false, false);
            assert!(human.contains(match state {
                RevocationState::Pending => "suspended (revocation unconfirmed)",
                RevocationState::Confirmed => "disabled (revoked)",
                RevocationState::NotRequested => unreachable!(),
            }));
            assert!(!human.contains("2026-02-01 00:00:00 UTC"));
            let json: serde_json::Value =
                serde_json::from_str(&show(std::slice::from_ref(&record), true, false).unwrap())
                    .unwrap();
            assert_eq!(json[0]["renewal_due"], false);
            if matches!(state, RevocationState::Confirmed) {
                assert!(revoked(&record, false).unwrap().contains("Next renewal:"));
                assert!(
                    revoked(&record, false)
                        .unwrap()
                        .contains("disabled (revoked)")
                );
            }
        }
    }
    #[test]
    fn local_deletion_output_does_not_assert_a_remote_certificate_status() {
        let machine: serde_json::Value = serde_json::from_str(
            &removed(
                "example.com",
                &aster_acme_cli_storage::issuance::removal::RemovalScope::All,
                &["a".into(), "b".into(), "c".into()],
                true,
                true,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(machine["removed_locally"], true);
        assert_eq!(machine["generations"], 3);
        assert_eq!(machine["ca_request_performed"], false);
        assert!(machine.get("ca_revoked").is_none());
        let human = removed(
            "example.com",
            &aster_acme_cli_storage::issuance::removal::RemovalScope::All,
            &["a".into(), "b".into(), "c".into()],
            true,
            false,
        )
        .unwrap();
        assert!(human.contains("Removed all local certificate requests for example.com."));
        assert!(!human.contains("Revoked"));
    }
}
