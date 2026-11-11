//! Human and typed JSON presentation; never contains private keys or CSRs.
use crate::common::error::CliResult;
use crate::common::output;
use crate::common::output::Style;
use crate::common::output::field;
use crate::common::time::timestamp;
use aster_acme::issuance::{DnsRequirement, IssueOutcome, IssueRecord};
use aster_acme_core::revocation::RevocationState;
use serde::Serialize;
use std::io::{self, IsTerminal};

use super::report::{
    BatchDisposition, CertificateResult, RenewalBatch, RenewalResult, RenewalSummary, SkipReason,
};

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
        RevocationState::NotRequested if record.finalize_rejection.is_some() => {
            "failed (CSR rejected)"
        }
        RevocationState::NotRequested if record.expired(now) => "expired locally",
        RevocationState::NotRequested if !record.unfinished() && !record.is_in_use => {
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
    in_use: bool,
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
        return show(records, true, false, DetailView::InUse);
    }
    if records.is_empty() {
        return Ok("No saved certificate requests.".into());
    }
    let now = time::OffsetDateTime::now_utc();
    let color = output::colors(io::stdout().is_terminal());
    let mut rows = vec![[
        "NAME".into(),
        "DOMAINS".into(),
        "KEY TYPE".into(),
        "REQUESTED (UTC)".into(),
        "STATUS".into(),
        "ORDER STATUS".into(),
        "CERT EXPIRES (UTC)".into(),
        "NEXT RENEWAL (UTC)".into(),
        "ACCOUNT".into(),
    ]];
    for record in records {
        rows.push([
            output::safe(record.name.as_str()),
            domain_summary(record),
            record.key_algorithm.name().into(),
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
                        record.is_in_use
                            && matches!(record.revocation.state, RevocationState::NotRequested)
                    })
                    .map(|plan| plan.renew_at),
            ),
            output::safe(&record.account_name),
        ]);
    }
    let mut lines =
        vec!["Local certificates (CA order status from saved observations; times in UTC):".into()];
    lines.extend(crate::common::table::align(
        &rows,
        Some(&|row, column, cell| {
            let style = match (row, column) {
                (0, _) => Style::BoldCyan,
                (_, 4) => local_status_style(&records[row - 1], now),
                (_, 5) => {
                    order_status_style(records[row - 1].order.as_ref().map(|order| &order.status))
                }
                _ => Style::Plain,
            };
            output::styled(cell, style, color)
        }),
    ));
    lines.push(output::tips(
        "Use cert show <NAME> for request IDs, CA details and TXT records.",
        color,
    ));
    Ok(lines.join("\n"))
}

fn local_status_style(record: &IssueRecord, now: time::OffsetDateTime) -> Style {
    match record.revocation.state {
        RevocationState::Confirmed => Style::Red,
        RevocationState::Pending => Style::Yellow,
        RevocationState::NotRequested if record.finalize_rejection.is_some() => Style::Red,
        RevocationState::NotRequested if record.expired(now) || record.unfinished() => {
            Style::Yellow
        }
        RevocationState::NotRequested => Style::Green,
    }
}

fn order_status_style(status: Option<&aster_acme_core::protocol::OrderStatus>) -> Style {
    use aster_acme_core::protocol::OrderStatus;
    match status {
        Some(OrderStatus::Valid) => Style::Green,
        Some(OrderStatus::Invalid | OrderStatus::Unknown(_)) => Style::Red,
        Some(OrderStatus::Ready) => Style::Blue,
        Some(OrderStatus::Pending | OrderStatus::Processing) | None => Style::Yellow,
    }
}

/// Human detail scope; `in_use` is shown only when choosing an explicit version.
#[derive(Clone, Copy)]
pub(super) enum DetailView {
    InUse,
    Version,
}

pub(super) fn show(
    records: &[IssueRecord],
    json: bool,
    verified: bool,
    view: DetailView,
) -> CliResult<String> {
    let now = time::OffsetDateTime::now_utc();
    if json {
        let views = records
            .iter()
            .map(|operation| OrderView {
                operation,
                expired_locally: operation.expired(now),
                renewal_due: operation.is_in_use
                    && matches!(operation.revocation.state, RevocationState::NotRequested)
                    && operation
                        .renewal
                        .as_ref()
                        .is_some_and(|plan| plan.renew_at <= now),
                in_use: operation.is_in_use,
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
        .map(|record| {
            let mut text = show_text(record, now, color, verified);
            if let DetailView::Version = view {
                text.push('\n');
                text.push_str(&field(
                    "In use:",
                    if record.is_in_use { "yes" } else { "no" },
                    color,
                ));
            }
            text
        })
        .collect::<Vec<_>>()
        .join("\n\n"))
}

fn show_text(
    record: &IssueRecord,
    now: time::OffsetDateTime,
    color: bool,
    verified: bool,
) -> String {
    let expired = record.expired(now);
    let mut lines = request_lines(record, now, color);
    let (status, status_style) = record.order.as_ref().map_or_else(
        || ("not observed".into(), Style::Yellow),
        |order| {
            let style = order_status_style(Some(&order.status));
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
        &output::styled(&deadline_text, Style::Yellow, color && expired),
        color,
    ));
    lines.extend(authorization_lines(record, color));
    if let Some(problem) = &record.finalize_rejection {
        lines.push(field(
            "CSR rejection:",
            &output::safe(
                &problem
                    .detail
                    .clone()
                    .unwrap_or_else(|| problem.kind.to_string()),
            ),
            color,
        ));
    }
    if let Some(order) = &record.order
        && let Some(problem) = &order.error
    {
        lines.push(field(
            "CA error:",
            &output::styled(
                &output::safe(
                    &problem
                        .detail
                        .clone()
                        .unwrap_or_else(|| problem.kind.to_string()),
                ),
                Style::Red,
                color,
            ),
            color,
        ));
    }
    if let Some(at) = record.certificate_not_after {
        let style = if at <= now { Style::Red } else { Style::Green };
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
            if verified {
                Style::Green
            } else {
                Style::Yellow
            },
            color,
        ),
        color,
    ));
    lines.join("\n")
}

// Immutable request identity and local progress, shared by offline and refreshed details.
fn request_lines(record: &IssueRecord, now: time::OffsetDateTime, color: bool) -> Vec<String> {
    vec![
        output::styled(&output::safe(record.name.as_str()), Style::BoldCyan, color),
        field("Request:", &record.operation_id, color),
        field("Key type:", record.key_algorithm.name(), color),
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
            "Status:",
            &output::styled(
                request_status(record, now),
                local_status_style(record, now),
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
        RevocationState::NotRequested => ("not requested", Style::Plain),
        RevocationState::Pending => ("pending; CA outcome unconfirmed", Style::Yellow),
        RevocationState::Confirmed => ("confirmed revoked", Style::Red),
    };
    lines.push(field(
        "Revocation:",
        &output::styled(revocation, style, color),
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
                &output::styled("disabled (revoked)", Style::Red, color),
                color,
            )];
        }
        RevocationState::Pending => {
            return vec![field(
                "Next renewal:",
                &output::styled("suspended (revocation unconfirmed)", Style::Yellow, color),
                color,
            )];
        }
        RevocationState::NotRequested => {}
    }
    let Some(plan) = &record.renewal else {
        return Vec::new();
    };
    if !record.is_in_use {
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
                if plan.renew_at <= now {
                    Style::Yellow
                } else {
                    Style::Green
                },
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
                Style::Yellow,
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
        let domain = if authorization.resource.wildcard {
            output::safe(&format!("*.{}", authorization.resource.identifier.value))
        } else {
            output::safe(&authorization.resource.identifier.value)
        };
        let style = match &authorization.resource.status {
            AuthorizationStatus::Valid => Style::Green,
            AuthorizationStatus::Pending => Style::Yellow,
            AuthorizationStatus::Expired
            | AuthorizationStatus::Deactivated
            | AuthorizationStatus::Revoked
            | AuthorizationStatus::Invalid
            | AuthorizationStatus::Unknown(_) => Style::Red,
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
                output::styled("Saved validation TXT:", Style::Yellow, color),
                output::safe(&dns.name),
                output::safe(&dns.value)
            ));
        }
    }
    lines
}

/// A result cannot simultaneously expose pending instructions and completed artifacts.
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ResultOutput<'a> {
    ActionRequired {
        operation: &'a IssueRecord,
        records: &'a [DnsRequirement],
        resume: String,
    },
    Completed {
        operation: &'a IssueRecord,
        records: &'a [DnsRequirement],
        artifacts: ArtifactPaths,
    },
    NotDue {
        operation: &'a IssueRecord,
    },
}

#[derive(Serialize)]
struct ArtifactPaths {
    fullchain: std::path::PathBuf,
    certificate: std::path::PathBuf,
    ca_chain: std::path::PathBuf,
    private_key: std::path::PathBuf,
}

fn artifact_lines(paths: &ArtifactPaths) -> Vec<String> {
    let mut lines = Vec::new();
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
    lines
}

pub(super) fn result(
    result: &CertificateResult,
    json: bool,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    match result {
        CertificateResult::Issuance(issued) => outcome(issued, json, data_dir),
        CertificateResult::NotDue(record) => not_due(record, json),
    }
}

// One typed conversion shared by single results and batch JSON; no parsing rendered JSON.
fn result_output<'a>(
    result: &'a CertificateResult,
    data_dir: &std::path::Path,
) -> ResultOutput<'a> {
    match result {
        CertificateResult::NotDue(record) => ResultOutput::NotDue { operation: record },
        CertificateResult::Issuance(outcome) => ResultOutput::from_outcome(outcome, data_dir),
    }
}

impl<'a> ResultOutput<'a> {
    fn from_outcome(outcome: &'a IssueOutcome, data_dir: &std::path::Path) -> Self {
        match outcome {
            IssueOutcome::ActionRequired { record, records } => Self::ActionRequired {
                operation: record,
                records,
                resume: format!(
                    "aster-acme cert issue --resume '{}' --operation {}",
                    record.name.as_str(),
                    record.operation_id
                ),
            },
            IssueOutcome::Completed { record, cleanup } => {
                let generation = data_dir
                    .join("certs")
                    .join(record.name.as_str())
                    .join("in_use");
                Self::Completed {
                    operation: record,
                    records: cleanup,
                    artifacts: ArtifactPaths {
                        fullchain: generation.join("fullchain.pem"),
                        certificate: generation.join("cert.pem"),
                        ca_chain: generation.join("ca.pem"),
                        private_key: generation.join("private-key.pem"),
                    },
                }
            }
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum BatchItemOutput<'a> {
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
struct BatchEntryOutput<'a> {
    name: &'a str,
    result: BatchItemOutput<'a>,
}

#[derive(Serialize)]
struct BatchOutput<'a> {
    status: BatchDisposition,
    summary: RenewalSummary,
    results: Vec<BatchEntryOutput<'a>>,
}

fn batch_output<'a>(report: &'a RenewalBatch, data_dir: &std::path::Path) -> BatchOutput<'a> {
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

fn batch_summary(summary: &RenewalSummary, total: usize) -> String {
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

pub(super) fn batch(
    report: &RenewalBatch,
    json: bool,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    let summary = report.summary();
    if json {
        return Ok(serde_json::to_string_pretty(&batch_output(
            report, data_dir,
        ))?);
    }
    let color = output::colors(io::stdout().is_terminal());
    let mut rows = vec![["NAME".into(), "STATUS".into(), "DETAILS".into()]];
    let mut details = Vec::new();
    for entry in &report.entries {
        let (status, detail) = match &entry.result {
            RenewalResult::Outcome(CertificateResult::NotDue(record)) => (
                "not due",
                timestamp(record.renewal.as_ref().map(|plan| plan.renew_at)),
            ),
            RenewalResult::Outcome(result) => {
                details.push(self::result(result, false, data_dir)?);
                match result {
                    CertificateResult::Issuance(IssueOutcome::Completed { .. }) => {
                        ("completed", "new certificate selected".into())
                    }
                    CertificateResult::Issuance(IssueOutcome::ActionRequired { .. }) => {
                        ("action required", "publish the saved TXT records".into())
                    }
                    CertificateResult::NotDue(_) => ("not due", String::new()),
                }
            }
            RenewalResult::Skipped(reason) => ("skipped", reason.message().into()),
            RenewalResult::Failed { message, hint } => {
                details.push(format!(
                    "{} {}: {}{}",
                    output::styled("[ERROR]", Style::BoldRed, color),
                    output::safe(&entry.name),
                    output::safe(message),
                    hint.as_ref().map_or_else(String::new, |hint| format!(
                        "\n{}",
                        output::tips(hint, color)
                    ))
                ));
                ("failed", message.clone())
            }
            RenewalResult::Cancelled => (
                "cancelled",
                "stopped; inspect the saved request and selected certificate".into(),
            ),
        };
        rows.push([
            output::safe(&entry.name),
            status.into(),
            output::safe(&detail),
        ]);
    }
    let (label, style) = match report.disposition() {
        BatchDisposition::Completed => ("[INFO]", Style::BoldCyan),
        BatchDisposition::ActionRequired | BatchDisposition::Cancelled => {
            ("[WARN]", Style::BoldYellow)
        }
        BatchDisposition::PartialFailure => ("[ERROR]", Style::BoldRed),
    };
    let mut lines = vec![format!(
        "{} Batch renewal results:",
        output::styled(label, style, color)
    )];
    lines.extend(crate::common::table::align(
        &rows,
        Some(&|row, column, cell| {
            let style = match (row, column) {
                (0, _) => Style::BoldCyan,
                (_, 1) => match &report.entries[row - 1].result {
                    RenewalResult::Outcome(CertificateResult::Issuance(
                        IssueOutcome::Completed { .. },
                    )) => Style::Green,
                    RenewalResult::Outcome(CertificateResult::NotDue(_)) => Style::Cyan,
                    RenewalResult::Outcome(CertificateResult::Issuance(
                        IssueOutcome::ActionRequired { .. },
                    ))
                    | RenewalResult::Skipped(_)
                    | RenewalResult::Cancelled => Style::Yellow,
                    RenewalResult::Failed { .. } => Style::Red,
                },
                _ => Style::Plain,
            };
            output::styled(cell, style, color)
        }),
    ));
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        output::styled(label, style, color),
        batch_summary(&summary, report.entries.len())
    ));
    for detail in details {
        lines.push(String::new());
        lines.push(detail);
    }
    Ok(lines.join("\n"))
}

pub(super) fn outcome(
    outcome: &IssueOutcome,
    json: bool,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    let (record, records) = match outcome {
        IssueOutcome::ActionRequired { record, records } => (record.as_ref(), records.as_slice()),
        IssueOutcome::Completed { record, cleanup } => (record.as_ref(), cleanup.as_slice()),
    };
    let result = ResultOutput::from_outcome(outcome, data_dir);
    if json {
        return Ok(serde_json::to_string_pretty(&result)?);
    }
    let color = output::colors(io::stdout().is_terminal());
    let (label, style, message) = match outcome {
        IssueOutcome::ActionRequired { .. } => ("[WARN]", Style::BoldYellow, "Action required for"),
        IssueOutcome::Completed { record, .. } => match &record.renewal_of {
            Some(_) => ("[DONE]", Style::BoldGreen, "Renewed certificate"),
            None => ("[DONE]", Style::BoldGreen, "Issued certificate"),
        },
    };
    let mut lines = vec![format!(
        "{} {message} {}",
        output::styled(label, style, color),
        output::safe(record.name.as_str())
    )];
    lines.push(format!("  Request: {}", record.operation_id));
    if let ResultOutput::Completed { artifacts, .. } = &result {
        lines.extend(artifact_lines(artifacts));
    }
    if let IssueOutcome::Completed { .. } = outcome {
        lines.extend(renewal_lines(
            record,
            time::OffsetDateTime::now_utc(),
            color,
        ));
    }
    if !records.is_empty() {
        lines.push(
            match outcome {
                IssueOutcome::ActionRequired { .. } => {
                    "Add every TXT value below. Values at the same name must coexist:"
                }
                IssueOutcome::Completed { .. } => {
                    "Validation finished. You may remove these specific manual TXT values:"
                }
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
    if let IssueOutcome::ActionRequired { .. } = outcome {
        lines.push(format!(
            "To resume, run:\n  aster-acme cert issue --resume '{}'",
            record.name.as_str()
        ));
    }
    Ok(lines.join("\n"))
}

pub(super) fn not_due(record: &IssueRecord, json: bool) -> CliResult<String> {
    if json {
        return Ok(serde_json::to_string_pretty(&ResultOutput::NotDue {
            operation: record,
        })?);
    }
    let color = output::colors(io::stdout().is_terminal());
    let mut lines = vec![format!(
        "{} Certificate {} is not due for renewal.",
        output::styled("[INFO]", Style::Cyan, color),
        output::safe(record.name.as_str())
    )];
    lines.extend(renewal_lines(
        record,
        time::OffsetDateTime::now_utc(),
        color,
    ));
    lines.push(output::tips(
        "Use cert renew <NAME> --now to renew early.",
        color,
    ));
    Ok(lines.join("\n"))
}

pub(super) fn removed(
    name: &str,
    scope: &aster_acme_cli_storage::issuance::removal::RemovalScope,
    ids: &[String],
    in_use_removed: bool,
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
        in_use_removed: bool,
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
            in_use_removed,
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
        output::styled("[OK]", Style::BoldGreen, color)
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

pub(super) fn revoked(record: &IssueRecord, json: bool) -> CliResult<String> {
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
    if json {
        return Ok(serde_json::to_string_pretty(&RevokedOutput {
            status: "revoked",
            operation: record,
        })?);
    }
    let color = output::colors(io::stdout().is_terminal());
    let mut lines = vec![format!(
        "{} Revoked certificate {}. Local files retained.",
        output::styled("[OK]", Style::BoldGreen, color),
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
            "key_algorithm":"ecdsa-p256","solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"example.com",
            "created_at":"2026-01-01T00:00:00.123456Z","account_name":"default","account_id":"id","account_thumbprint":"key",
            "directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],
            "phase":"completed","creation_submitted":true,"order_url":"https://ca.example/order","finalize_submitted":"submitted",
            "order":{"status":"valid","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[],"finalize":"https://ca.example/finalize"},
            "authorizations":[],"certificate_not_after":"2099-01-01T00:00:00Z"
        })).unwrap();
        let mut record = record;
        record.is_in_use = true;
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
        assert!(plain.contains("Key type:"));
        assert!(plain.contains("ecdsa-p256"));
        assert!(
            list(std::slice::from_ref(&record), false)
                .unwrap()
                .contains("KEY TYPE")
        );
        assert!(!plain.contains('\x1b'));
        assert!(plain.contains("Next renewal:"));
        assert!(plain.contains("2026-02-01 00:00:00 UTC"));
        assert!(plain.contains("fallback (2/3 of certificate validity)"));
        assert!(
            list(std::slice::from_ref(&record), false)
                .unwrap()
                .contains("NEXT RENEWAL (UTC)")
        );
        let machine = show(
            std::slice::from_ref(&record),
            true,
            false,
            DetailView::InUse,
        )
        .unwrap();
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
                format!("/data/certs/example.com/in_use/{file}")
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
            let json: serde_json::Value = serde_json::from_str(
                &show(
                    std::slice::from_ref(&record),
                    true,
                    false,
                    DetailView::InUse,
                )
                .unwrap(),
            )
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
    #[test]
    fn rejected_csr_local_failure_keeps_ready_order_status_and_distinct_colors() {
        use aster_acme_protocol::problem::{Problem, ProblemKind};
        let mut record:IssueRecord=serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p521","solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"example.com",
            "created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"id","account_thumbprint":"key",
            "directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],
            "phase":"finalizing","creation_submitted":true,"order_url":"https://ca.example/order","finalize_submitted":"submitted",
            "order":{"status":"ready","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[],"finalize":"https://ca.example/finalize"},"authorizations":[]
        })).unwrap();
        record.finalize_rejection = Some(Problem {
            kind: ProblemKind::BadCsr,
            detail: Some("P-521 not allowed".into()),
            instance: None,
            subproblems: vec![],
            extensions: serde_json::Map::new(),
        });
        let now = time::OffsetDateTime::now_utc();
        assert_eq!(request_status(&record, now), "failed (CSR rejected)");
        assert_eq!(local_status_style(&record, now), Style::Red);
        assert_eq!(
            order_status_style(record.order.as_ref().map(|order| &order.status)),
            Style::Blue
        );
        let table = list(std::slice::from_ref(&record), false).unwrap();
        assert!(table.contains("STATUS"));
        assert!(!table.contains("PHASE"));
        assert!(table.contains("failed (CSR rejected)"));
        assert!(table.contains("ready"));
        let details = show_text(&record, now, true, false);
        assert!(details.contains("\x1b[31mfailed (CSR rejected)\x1b[0m"));
        assert!(details.contains("\x1b[34mready\x1b[0m"));
        let json: serde_json::Value =
            serde_json::from_str(&show(&[record], true, false, DetailView::InUse).unwrap())
                .unwrap();
        assert_eq!(json[0]["order"]["status"], "ready");
    }
    #[test]
    fn final_output_variants_cannot_mix_manual_actions_artifacts_or_not_due_results() {
        let record:IssueRecord=serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p256","solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"web","created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"id","account_thumbprint":"key","directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],"phase":"authorizing","creation_submitted":true,"authorizations":[],"finalize_submitted":"not_submitted"
        })).unwrap();
        let pending = IssueOutcome::ActionRequired {
            record: Box::new(record.clone()),
            records: vec![DnsRequirement {
                name: "_acme-challenge.example.com".into(),
                value: "txt-value".into(),
            }],
        };
        let root = std::path::Path::new("/data");
        let json: serde_json::Value =
            serde_json::from_str(&outcome(&pending, true, root).unwrap()).unwrap();
        assert_eq!(json["status"], "action_required");
        assert!(json.get("artifacts").is_none());
        assert!(outcome(&pending, false, root).unwrap().contains("[WARN]"));
        assert!(!outcome(&pending, false, root).unwrap().contains("[DONE]"));
        for renewal in [false, true] {
            let mut complete = record.clone();
            complete.phase = aster_acme_core::workflow::IssuancePhase::Completed;
            if renewal {
                complete.renewal_of = Some(aster_acme::issuance::RenewalPredecessor {
                    operation_id: "old".into(),
                    certificate_id: None,
                });
            }
            let completed = IssueOutcome::Completed {
                record: Box::new(complete),
                cleanup: vec![],
            };
            let human = outcome(&completed, false, root).unwrap();
            assert!(human.contains(if renewal {
                "Renewed certificate"
            } else {
                "Issued certificate"
            }));
            let json: serde_json::Value =
                serde_json::from_str(&outcome(&completed, true, root).unwrap()).unwrap();
            assert_eq!(json["status"], "completed");
            assert!(json.get("resume").is_none());
            assert!(json.get("artifacts").is_some());
        }
        let json: serde_json::Value =
            serde_json::from_str(&not_due(&record, true).unwrap()).unwrap();
        assert_eq!(json["status"], "not_due");
        assert!(json.get("resume").is_none());
        assert!(json.get("artifacts").is_none());
        for state in [RevocationState::NotRequested, RevocationState::Pending] {
            let mut record = record.clone();
            record.revocation.state = state;
            assert!(revoked(&record, true).is_err());
        }
    }
}
