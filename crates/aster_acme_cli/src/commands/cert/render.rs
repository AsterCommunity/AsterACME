//! Human and typed JSON presentation; never contains private keys or CSRs.
use crate::common::error::CliResult;
use crate::common::output;
use crate::common::output::Style;
use crate::common::output::field;
use crate::common::session::Format;
use crate::common::time::timestamp;
use aster_acme::issuance::{IssueOutcome, IssueRecord, ValidationRequirement};
use aster_acme_core::revocation::RevocationState;
use serde::Serialize;

pub(crate) mod deployment;

use crate::commands::cert::report::{
    BatchDisposition, CertificateResult, RenewalBatch, RenewalResult, RenewalSummary, SkipReason,
};

pub(crate) fn render(
    report: &super::report::CertificateReport,
    format: Format,
) -> CliResult<String> {
    use crate::commands::cert::report::CertificateReport;
    match report {
        CertificateReport::Result {
            result: report,
            data_dir,
        } => result(report, format, data_dir),
        CertificateReport::Batch { report, data_dir } => batch(report, format, data_dir),
        CertificateReport::List(records) => list(records, format),
        CertificateReport::Show {
            record,
            verified,
            view,
        } => show(
            std::slice::from_ref(record.as_ref()),
            format,
            *verified,
            *view,
        ),
        CertificateReport::Revoked(record) => revoked(record, format),
        CertificateReport::Removed {
            name,
            scope,
            ids,
            in_use_removed,
        } => removed(name, scope, ids, *in_use_removed, format),
        CertificateReport::Deployment(report) => deployment_report(report, format),
        CertificateReport::DeploymentDetails { name, binding } => {
            deployment::details(name, binding, format)
        }
        CertificateReport::DeploymentUpdated { name, binding } => {
            if format.json {
                return deployment::details(name, binding, format);
            }
            Ok(format!(
                "{} Deployment '{}' updated. Run cert deploy run {} -n {} to publish it.",
                output::MessageKind::Done.badge(format.color),
                output::safe(&binding.id),
                output::safe(name),
                output::safe(&binding.id)
            ))
        }
        CertificateReport::DeploymentRemoved { name, id } => deployment_removed(name, id, format),
    }
}

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
        RevocationState::NotRequested if record.creation_failure.is_some() => {
            let failure = record.creation_failure.as_ref();
            match failure
                .and_then(|failure| failure.problem.as_ref())
                .map(|problem| &problem.kind)
            {
                Some(aster_acme_protocol::problem::ProblemKind::RateLimited) => {
                    return "creation deferred";
                }
                Some(aster_acme_protocol::problem::ProblemKind::ServerInternal) => {
                    return "creation unconfirmed";
                }
                _ => {}
            }
            match failure.map(|failure| failure.status) {
                Some(408 | 429) => "creation deferred",
                Some(400..=499) => "creation rejected",
                _ => "creation unconfirmed",
            }
        }
        RevocationState::NotRequested if record.finalize_rejection.is_some() => {
            "failed (CSR rejected)"
        }
        RevocationState::NotRequested if record.expired(now) => "expired locally",
        RevocationState::NotRequested if record.authorization_failure().is_some() => {
            "authorization failed"
        }
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

pub(super) fn list(records: &[IssueRecord], format: Format) -> CliResult<String> {
    if format.json {
        return show(records, format, false, DetailView::InUse);
    }
    if records.is_empty() {
        return Ok("No saved certificate requests.".into());
    }
    let now = time::OffsetDateTime::now_utc();
    let color = format.color;
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
    lines.extend(crate::common::table::listing(
        &rows,
        color,
        |row, column| match column {
            4 => local_status_style(&records[row], now),
            5 => order_status_style(records[row].order.as_ref().map(|order| &order.status)),
            _ => Style::Plain,
        },
    ));
    lines.push(output::tips(
        "Use cert show <NAME> for request IDs, CA details and saved validation requirements.",
        color,
    ));
    Ok(lines.join("\n"))
}

fn local_status_style(record: &IssueRecord, now: time::OffsetDateTime) -> Style {
    match record.revocation.state {
        RevocationState::Confirmed => Style::Red,
        RevocationState::Pending => Style::Yellow,
        RevocationState::NotRequested
            if record.finalize_rejection.is_some()
                || record.creation_failure.is_some()
                || record.authorization_failure().is_some() =>
        {
            Style::Red
        }
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
pub(crate) enum DetailView {
    InUse,
    Version,
}

pub(super) fn show(
    records: &[IssueRecord],
    format: Format,
    verified: bool,
    view: DetailView,
) -> CliResult<String> {
    let now = time::OffsetDateTime::now_utc();
    if format.json {
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
    let color = format.color;
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
    if let Some(failure) = &record.creation_failure {
        lines.push(field("newOrder HTTP:", &failure.status.to_string(), color));
        lines.push(field("Retry after:", &timestamp(failure.retry_at), color));
    }
    if let Some(problem) = &record.finalize_rejection {
        lines.push(field(
            "CSR rejection:",
            &output::safe(&problem.problem.as_ref().map_or_else(
                || format!("HTTP {}", problem.status),
                |problem| {
                    problem
                        .detail
                        .clone()
                        .unwrap_or_else(|| problem.kind.to_string())
                },
            )),
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
    let mut lines = vec![
        output::styled(&output::safe(record.name.as_str()), Style::BoldCyan, color),
        field("Request:", &record.operation_id, color),
        field("Key type:", record.key_algorithm.name(), color),
        field(
            "Validation:",
            &output::safe(&format!(
                "{} ({})",
                record.solver_id,
                record.challenge.name()
            )),
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
            "Status:",
            &output::styled(
                request_status(record, now),
                local_status_style(record, now),
                color,
            ),
            color,
        ),
        field("CA:", &output::safe(record.directory.as_str()), color),
    ];
    if matches!(
        super::validation::ValidationMethod::from_record(record),
        Ok(super::validation::ValidationMethod::Webroot)
    ) && let Ok(config) =
        serde_json::from_value::<super::validation::WebrootConfig>(record.solver_config.clone())
    {
        lines.push(field(
            "Webroot:",
            &output::safe(&config.root.display().to_string()),
            color,
        ));
    }
    if let Some(problem) = record.failure_problem() {
        let message = format!(
            "{} ({})",
            problem
                .detail
                .as_deref()
                .unwrap_or("no explanation provided"),
            problem.kind
        );
        lines.push(field("CA problem:", &output::safe(&message), color));
    }
    if let Ok(config) =
        serde_json::from_value::<super::validation::StandaloneConfig>(record.solver_config.clone())
    {
        lines.push(field(
            "Listen address:",
            &config.listen_address.to_string(),
            color,
        ));
    }
    lines
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
        aster_acme::renewal::RenewalSource::Fallback => {
            "fallback (randomized before validity threshold)"
        }
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
    if let Some(retry) = &record.renewal_retry {
        lines.extend(renewal_retry_lines(retry, color));
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

fn renewal_retry_lines(
    retry: &aster_acme::issuance::RenewalRetryState,
    color: bool,
) -> Vec<String> {
    let mut lines = vec![field(
        "Renewal failures:",
        &retry.failures.to_string(),
        color,
    )];
    if let Some(reason) = &retry.blocked_reason {
        lines.push(field(
            "Automatic retry:",
            &format!("blocked: {reason}"),
            color,
        ));
    } else {
        let effective_retry = retry.retry_at.into_iter().chain(retry.ca_retry_at).max();
        lines.push(field(
            "Automatic retry:",
            &timestamp(effective_retry),
            color,
        ));
        if let Some(at) = retry.ca_retry_at {
            lines.push(field("CA Retry-After:", &timestamp(Some(at)), color));
        }
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
        if let Some(requirement) = &authorization.validation {
            lines.extend(
                requirement_lines(std::slice::from_ref(requirement))
                    .into_iter()
                    .map(|line| format!("    Saved validation: {line}")),
            );
        }
    }
    lines
}

/// Shared method-specific material presentation for prompts and final outcomes.
/// All strings are escaped before reaching the terminal.
pub(super) fn requirement_lines(requirements: &[ValidationRequirement]) -> Vec<String> {
    let mut lines = Vec::new();
    for requirement in requirements {
        match requirement {
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

/// A result cannot simultaneously expose pending instructions and completed artifacts.
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ResultOutput<'a> {
    ActionRequired {
        operation: &'a IssueRecord,
        records: &'a [ValidationRequirement],
        resume: String,
    },
    Completed {
        operation: &'a IssueRecord,
        records: &'a [ValidationRequirement],
        artifacts: ArtifactPaths,
        deployments: Vec<DeploymentStatusView<'a>>,
        deployment_events: &'a [super::report::DeploymentEvent],
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

#[derive(Serialize)]
struct DeploymentStatusView<'a> {
    id: &'a str,
    generation: Option<&'a str>,
    phase: aster_acme::deployment::DeploymentPhase,
    attempts: u8,
    retry_failures: u32,
    #[serde(with = "time::serde::rfc3339::option")]
    retry_at: Option<time::OffsetDateTime>,
    last_error: Option<&'a str>,
    execution_error: Option<&'a str>,
}

impl<'a> From<&'a aster_acme_cli_storage::issuance::DeploymentBinding>
    for DeploymentStatusView<'a>
{
    fn from(binding: &'a aster_acme_cli_storage::issuance::DeploymentBinding) -> Self {
        Self {
            id: &binding.id,
            generation: binding.generation.as_deref(),
            phase: binding.phase,
            attempts: binding.attempts,
            retry_failures: binding.retry_failures,
            retry_at: binding.retry_at,
            last_error: binding.last_error.as_deref(),
            execution_error: None,
        }
    }
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
    format: Format,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    match result {
        CertificateResult::Issuance(issued) => outcome(issued, format, data_dir),
        CertificateResult::Issued {
            outcome: issued,
            deployments,
            deployment_events,
        } => issued_result(issued, deployments, deployment_events, format, data_dir),
        CertificateResult::NotDue(record) => not_due(record, format),
    }
}

fn issued_result(
    issued: &IssueOutcome,
    deployments: &[aster_acme_cli_storage::issuance::DeploymentBinding],
    deployment_events: &[super::report::DeploymentEvent],
    format: Format,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    if format.json {
        return Ok(serde_json::to_string_pretty(
            &ResultOutput::from_outcome(issued, data_dir, deployments)
                .with_events(deployment_events),
        )?);
    }
    let text = outcome(issued, format, data_dir)?;
    if deployments.is_empty() && deployment_events.is_empty() {
        return Ok(text);
    }
    let mut lines = vec![text, String::new()];
    lines.extend(
        deployment_events
            .iter()
            .map(|event| deployment::event(event, format.color)),
    );
    if !deployments.is_empty() {
        lines.push(String::new());
        let name = match issued {
            IssueOutcome::Completed { record, .. }
            | IssueOutcome::ActionRequired { record, .. } => record.name.as_str(),
        };
        lines.push(deployment_table(
            name,
            deployments,
            true,
            deployment_events,
            format,
        ));
    }
    Ok(lines.join("\n"))
}

fn deployment_removed(name: &str, id: &str, format: Format) -> CliResult<String> {
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
    report: &super::report::DeploymentReport,
    format: Format,
) -> CliResult<String> {
    #[derive(Serialize)]
    struct View<'a> {
        certificate: &'a str,
        deployments: Vec<DeploymentStatusView<'a>>,
        events: &'a [super::report::DeploymentEvent],
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

fn deployment_table(
    name: &str,
    entries: &[aster_acme_cli_storage::issuance::DeploymentBinding],
    attempted: bool,
    events: &[super::report::DeploymentEvent],
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
            entry.generation.clone().unwrap_or_else(|| "—".into()),
            if error.is_some() {
                "execution failed".into()
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

fn current_error<'a>(events: &'a [super::report::DeploymentEvent], id: &str) -> Option<&'a str> {
    events
        .iter()
        .rev()
        .find(|event| {
            event.kind == output::MessageKind::Error && event.deployment.as_deref() == Some(id)
        })
        .map(|event| event.message.as_str())
}

fn deployment_phase(phase: aster_acme::deployment::DeploymentPhase) -> (&'static str, Style) {
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

// One typed conversion shared by single results and batch JSON; no parsing rendered JSON.
fn result_output<'a>(
    result: &'a CertificateResult,
    data_dir: &std::path::Path,
) -> ResultOutput<'a> {
    match result {
        CertificateResult::NotDue(record) => ResultOutput::NotDue { operation: record },
        CertificateResult::Issuance(outcome) => ResultOutput::from_outcome(outcome, data_dir, &[]),
        CertificateResult::Issued {
            outcome,
            deployments,
            deployment_events,
        } => ResultOutput::from_outcome(outcome, data_dir, deployments)
            .with_events(deployment_events),
    }
}

impl<'a> ResultOutput<'a> {
    fn with_events(mut self, events: &'a [super::report::DeploymentEvent]) -> Self {
        if let Self::Completed {
            deployment_events,
            deployments,
            ..
        } = &mut self
        {
            *deployment_events = events;
            for binding in deployments {
                binding.execution_error = current_error(events, binding.id);
            }
        }
        self
    }

    fn from_outcome(
        outcome: &'a IssueOutcome,
        data_dir: &std::path::Path,
        deployments: &'a [aster_acme_cli_storage::issuance::DeploymentBinding],
    ) -> Self {
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
                    deployments: deployments.iter().map(DeploymentStatusView::from).collect(),
                    deployment_events: &[],
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

pub(crate) fn batch(
    report: &RenewalBatch,
    format: Format,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    let summary = report.summary();
    if format.json {
        return Ok(serde_json::to_string_pretty(&batch_output(
            report, data_dir,
        ))?);
    }
    let color = format.color;
    if report.entries.is_empty() {
        let (kind, message) = if report.was_cancelled() {
            (
                output::MessageKind::Warning,
                "Batch renewal cancelled before any certificates were processed.",
            )
        } else {
            (
                output::MessageKind::Info,
                "No managed certificates to check.",
            )
        };
        return Ok(format!("{} {message}", kind.badge(color)));
    }
    let mut rows = vec![["NAME".into(), "STATUS".into(), "NEXT RENEWAL (UTC)".into()]];
    let mut details = Vec::new();
    for entry in &report.entries {
        let (status, renew_at, detail) = render_batch_entry(entry, format, data_dir)?;
        if let Some(detail) = detail {
            details.push(detail);
        }
        rows.push([
            output::safe(&entry.name),
            status.into(),
            timestamp(renew_at),
        ]);
    }
    let kind = match report.disposition() {
        BatchDisposition::Completed => output::MessageKind::Info,
        BatchDisposition::ActionRequired | BatchDisposition::Cancelled => {
            output::MessageKind::Warning
        }
        BatchDisposition::PartialFailure => output::MessageKind::Error,
    };
    let mut lines = vec![format!("{} Batch renewal results:", kind.badge(color))];
    lines.extend(crate::common::table::listing(
        &rows,
        color,
        |row, column| match column {
            1 => batch_status_style(&report.entries[row].result),
            _ => Style::Plain,
        },
    ));
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        kind.badge(color),
        batch_summary(&summary, report.entries.len())
    ));
    for detail in details {
        lines.push(String::new());
        lines.push(detail);
    }
    Ok(lines.join("\n"))
}

fn render_batch_entry(
    entry: &super::report::RenewalEntry,
    format: Format,
    data_dir: &std::path::Path,
) -> CliResult<(&'static str, Option<time::OffsetDateTime>, Option<String>)> {
    let color = format.color;
    match &entry.result {
        RenewalResult::Outcome(CertificateResult::NotDue(record)) => Ok((
            "not due",
            record.renewal.as_ref().map(|plan| plan.renew_at),
            None,
        )),
        RenewalResult::Outcome(CertificateResult::Issuance(outcome)) => {
            let status = match outcome {
                IssueOutcome::Completed { record, .. } => (
                    "completed",
                    record.renewal.as_ref().map(|plan| plan.renew_at),
                ),
                IssueOutcome::ActionRequired { .. } => ("action required", None),
            };
            Ok((
                status.0,
                status.1,
                Some(self::outcome(outcome, format, data_dir)?),
            ))
        }
        RenewalResult::Outcome(CertificateResult::Issued {
            outcome,
            deployments,
            deployment_events,
        }) => {
            let (status, renew_at) = match outcome {
                IssueOutcome::Completed { record, .. }
                    if deployment_events
                        .iter()
                        .any(|event| event.kind == output::MessageKind::Error)
                        || deployments.iter().any(|entry| {
                            entry.phase != aster_acme::deployment::DeploymentPhase::Deployed
                        }) =>
                {
                    (
                        "deployment failed",
                        record.renewal.as_ref().map(|p| p.renew_at),
                    )
                }
                IssueOutcome::Completed { record, .. } => {
                    ("completed", record.renewal.as_ref().map(|p| p.renew_at))
                }
                IssueOutcome::ActionRequired { .. } => ("action required", None),
            };
            Ok((
                status,
                renew_at,
                Some(issued_result(
                    outcome,
                    deployments,
                    deployment_events,
                    format,
                    data_dir,
                )?),
            ))
        }
        RenewalResult::Skipped(reason) => Ok((
            "skipped",
            None,
            Some(format!(
                "{} {}: {}",
                output::MessageKind::Warning.badge(color),
                output::safe(&entry.name),
                reason.message()
            )),
        )),
        RenewalResult::Failed { message, hint } => Ok((
            "failed",
            None,
            Some(format!(
                "{} {}: {}{}",
                output::MessageKind::Error.badge(color),
                output::safe(&entry.name),
                output::safe(message),
                hint.as_ref().map_or_else(String::new, |hint| format!(
                    "\n{}",
                    output::tips(hint, color)
                ))
            )),
        )),
        RenewalResult::Cancelled => Ok((
            "cancelled",
            None,
            Some(format!(
                "{} {}: stopped; inspect the saved request and selected certificate",
                output::MessageKind::Warning.badge(color),
                output::safe(&entry.name)
            )),
        )),
    }
}

fn batch_status_style(result: &RenewalResult) -> Style {
    match result {
        RenewalResult::Outcome(CertificateResult::Issuance(IssueOutcome::Completed { .. })) => {
            Style::Green
        }
        RenewalResult::Outcome(CertificateResult::Issued {
            outcome: IssueOutcome::Completed { .. },
            deployments,
            deployment_events,
        }) if deployment_events
            .iter()
            .any(|event| event.kind == output::MessageKind::Error)
            || deployments
                .iter()
                .any(|entry| entry.phase != aster_acme::deployment::DeploymentPhase::Deployed) =>
        {
            Style::Red
        }
        RenewalResult::Outcome(CertificateResult::Issued {
            outcome: IssueOutcome::Completed { .. },
            ..
        }) => Style::Green,
        RenewalResult::Outcome(CertificateResult::NotDue(_)) => Style::Cyan,
        RenewalResult::Outcome(
            CertificateResult::Issuance(IssueOutcome::ActionRequired { .. })
            | CertificateResult::Issued {
                outcome: IssueOutcome::ActionRequired { .. },
                ..
            },
        )
        | RenewalResult::Skipped(_)
        | RenewalResult::Cancelled => Style::Yellow,
        RenewalResult::Failed { .. } => Style::Red,
    }
}

pub(super) fn outcome(
    outcome: &IssueOutcome,
    format: Format,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    let (record, records) = match outcome {
        IssueOutcome::ActionRequired { record, records } => (record.as_ref(), records.as_slice()),
        IssueOutcome::Completed { record, cleanup } => (record.as_ref(), cleanup.as_slice()),
    };
    let result = ResultOutput::from_outcome(outcome, data_dir, &[]);
    if format.json {
        return Ok(serde_json::to_string_pretty(&result)?);
    }
    let color = format.color;
    let (kind, message) = match outcome {
        IssueOutcome::ActionRequired { .. } => {
            (output::MessageKind::Warning, "Action required for")
        }
        IssueOutcome::Completed { record, .. } => match &record.renewal_of {
            Some(_) => (output::MessageKind::Done, "Renewed certificate"),
            None => (output::MessageKind::Done, "Issued certificate"),
        },
    };
    let mut lines = vec![format!(
        "{} {message} {}",
        kind.badge(color),
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
                    "Publish every validation requirement below; retain unrelated files and records:"
                }
                IssueOutcome::Completed { .. } => {
                    "Validation finished. You may remove these specific saved manual validation values/files:"
                }
            }
            .into(),
        );
        lines.extend(
            requirement_lines(records)
                .into_iter()
                .map(|line| format!("  {line}")),
        );
    }
    if let IssueOutcome::ActionRequired { .. } = outcome {
        lines.push(format!(
            "To resume, run:\n  aster-acme cert issue --resume '{}'",
            record.name.as_str()
        ));
    }
    Ok(lines.join("\n"))
}

pub(super) fn not_due(record: &IssueRecord, format: Format) -> CliResult<String> {
    if format.json {
        return Ok(serde_json::to_string_pretty(&ResultOutput::NotDue {
            operation: record,
        })?);
    }
    let color = format.color;
    let mut lines = vec![format!(
        "{} Certificate {} is not due for renewal.",
        crate::common::output::MessageKind::Info.badge(color),
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

pub(super) fn revoked(record: &IssueRecord, format: Format) -> CliResult<String> {
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
    lines.extend(renewal_lines(
        record,
        time::OffsetDateTime::now_utc(),
        color,
    ));
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use crate::commands::cert::render::*;

    #[test]
    fn deployment_list_empty_and_json_match_other_local_lists() {
        let report = super::super::report::DeploymentReport {
            events: Vec::new(),
            name: "web".into(),
            entries: Vec::new(),
            attempted: false,
        };
        let text = deployment_report(&report, Format::plain(false)).unwrap();
        assert!(text.starts_with("No deployment targets configured for web."));
        assert!(!text.contains("GENERATION"));
        assert!(text.contains("Tips:"));
        assert!(!text.contains('\x1b'));
        let json: serde_json::Value =
            serde_json::from_str(&deployment_report(&report, Format::plain(true)).unwrap())
                .unwrap();
        assert_eq!(json["certificate"], "web");
        assert_eq!(json["deployments"], serde_json::json!([]));
    }

    #[test]
    fn deployment_list_uses_shared_alignment_and_semantic_styles_for_every_phase() {
        use aster_acme::deployment::DeploymentPhase;
        use aster_acme_cli_storage::issuance::{DeploymentBinding, DeploymentTarget};
        let phases = [
            DeploymentPhase::Configured,
            DeploymentPhase::Publishing,
            DeploymentPhase::PublishFailed,
            DeploymentPhase::PublicationComplete,
            DeploymentPhase::Reloading,
            DeploymentPhase::ReloadFailed,
            DeploymentPhase::ReloadUncertain,
            DeploymentPhase::Deployed,
        ];
        let report = super::super::report::DeploymentReport {
            events: Vec::new(),
            name: "web\n".into(),
            entries: phases
                .iter()
                .enumerate()
                .map(|(index, phase)| DeploymentBinding {
                    permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
                    id: format!("target-{index}"),
                    target: DeploymentTarget::Directory {
                        path: "/tmp".into(),
                    },
                    reload_command: vec!["secret-command".into()],
                    timeout_seconds: 30,
                    max_retries: 0,
                    generation: None,
                    phase: *phase,
                    attempts: 0,
                    retry_failures: 0,
                    retry_at: None,
                    last_error: Some("error\nvalue".into()),
                })
                .collect(),
            attempted: false,
        };
        let plain = deployment_report(&report, Format::plain(false)).unwrap();
        let colored = deployment_report(
            &report,
            Format {
                json: false,
                color: true,
            },
        )
        .unwrap();
        assert!(plain.starts_with("Local deployments for web\\n (saved execution status):"));
        assert!(plain.contains("reload unconfirmed"));
        assert!(plain.contains("error\\nvalue"));
        assert!(!plain.contains("secret-command"));
        assert!(colored.contains("\x1b[1;36mDEPLOYMENT"));
        assert!(colored.contains("\x1b[31mreload failed"));
        assert!(colored.contains("\x1b[32mdeployed"));
        let header = plain.lines().nth(1).unwrap();
        for line in plain
            .lines()
            .skip(2)
            .filter(|line| !line.starts_with("Tips:"))
        {
            use unicode_width::UnicodeWidthStr as _;
            assert_eq!(
                line[..line.find("error\\nvalue").unwrap()].width(),
                header[..header.find("ERROR").unwrap()].width()
            );
        }
    }

    fn detailed_record() -> IssueRecord {
        let record:IssueRecord=serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p256","challenge":"dns-01","solver_config":{},"solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"example.com",
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
        record
    }

    #[test]
    fn details_style_statuses_and_keep_human_times_fixed_without_altering_json() {
        let record = detailed_record();
        let colored = show_text(&record, time::OffsetDateTime::now_utc(), true, false);
        assert!(colored.contains("\x1b[32mcompleted\x1b[0m"));
        assert!(colored.contains("\x1b[32mvalid\x1b[0m"));
        assert!(colored.contains("2026-01-01 00:00:00 UTC"));
        assert!(!colored.contains(".123456"));
        let plain = show_text(&record, time::OffsetDateTime::now_utc(), false, false);
        assert!(plain.contains("Key type:"));
        assert!(plain.contains("ecdsa-p256"));
        assert!(
            list(
                std::slice::from_ref(&record),
                crate::common::session::Format::plain(false)
            )
            .unwrap()
            .contains("KEY TYPE")
        );
        assert!(!plain.contains('\x1b'));
        assert!(plain.contains("Next renewal:"));
        assert!(plain.contains("2026-02-01 00:00:00 UTC"));
        assert!(plain.contains("fallback (randomized before validity threshold)"));
        assert!(
            list(
                std::slice::from_ref(&record),
                crate::common::session::Format::plain(false)
            )
            .unwrap()
            .contains("NEXT RENEWAL (UTC)")
        );
        let machine = show(
            std::slice::from_ref(&record),
            crate::common::session::Format::plain(true),
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
        let human = outcome(
            &result,
            crate::common::session::Format::plain(false),
            std::path::Path::new("/data"),
        )
        .unwrap();
        assert!(human.contains("Next renewal:"));
        assert!(human.contains("2026-02-01 00:00:00 UTC"));
        assert!(human.find("Private key:").unwrap() < human.find("Next renewal:").unwrap());
        let output = outcome(
            &result,
            crate::common::session::Format::plain(true),
            std::path::Path::new("/data"),
        )
        .unwrap();
        let fields: serde_json::Value = serde_json::from_str(&output).unwrap();
        for (key, file) in [
            ("fullchain", "fullchain.pem"),
            ("certificate", "cert.pem"),
            ("ca_chain", "ca.pem"),
            ("private_key", "private-key.pem"),
        ] {
            assert_eq!(
                fields["artifacts"][key],
                std::path::Path::new("/data")
                    .join("certs")
                    .join("example.com")
                    .join("in_use")
                    .join(file)
                    .to_string_lossy()
                    .as_ref()
            );
        }
    }

    #[test]
    fn revoked_and_pending_records_suspend_scheduling_without_claiming_fresh_verification() {
        let record = Box::new(detailed_record());
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
                    crate::common::session::Format::plain(true),
                    false,
                    DetailView::InUse,
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(json[0]["renewal_due"], false);
            if matches!(state, RevocationState::Confirmed) {
                assert!(
                    revoked(&record, crate::common::session::Format::plain(false))
                        .unwrap()
                        .contains("Next renewal:")
                );
                assert!(
                    revoked(&record, crate::common::session::Format::plain(false))
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
                crate::common::session::Format::plain(true),
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
            crate::common::session::Format::plain(false),
        )
        .unwrap();
        assert!(human.contains("Removed all local certificate requests for example.com."));
        assert!(!human.contains("Revoked"));
    }
    #[test]
    fn rejected_csr_local_failure_keeps_ready_order_status_and_distinct_colors() {
        use aster_acme_protocol::problem::{Problem, ProblemKind};
        let mut record:IssueRecord=serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p521","challenge":"dns-01","solver_config":{},"solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"example.com",
            "created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"id","account_thumbprint":"key",
            "directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],
            "phase":"finalizing","creation_submitted":true,"order_url":"https://ca.example/order","finalize_submitted":"submitted",
            "order":{"status":"ready","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[],"finalize":"https://ca.example/finalize"},"authorizations":[]
        })).unwrap();
        record.finalize_rejection = Some(aster_acme::issuance::RequestFailure {
            status: 400,
            retry_at: None,
            problem: Some(Problem {
                kind: ProblemKind::BadCsr,
                detail: Some("P-521 not allowed".into()),
                instance: None,
                subproblems: vec![],
                extensions: serde_json::Map::new(),
            }),
        });
        let now = time::OffsetDateTime::now_utc();
        assert_eq!(request_status(&record, now), "failed (CSR rejected)");
        assert_eq!(local_status_style(&record, now), Style::Red);
        assert_eq!(
            order_status_style(record.order.as_ref().map(|order| &order.status)),
            Style::Blue
        );
        let table = list(
            std::slice::from_ref(&record),
            crate::common::session::Format::plain(false),
        )
        .unwrap();
        assert!(table.contains("STATUS"));
        assert!(!table.contains("PHASE"));
        assert!(table.contains("failed (CSR rejected)"));
        assert!(table.contains("ready"));
        let details = show_text(&record, now, true, false);
        assert!(details.contains("\x1b[31mfailed (CSR rejected)\x1b[0m"));
        assert!(details.contains("\x1b[34mready\x1b[0m"));
        let json: serde_json::Value = serde_json::from_str(
            &show(
                &[record],
                crate::common::session::Format::plain(true),
                false,
                DetailView::InUse,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json[0]["order"]["status"], "ready");
    }
    #[test]
    fn final_output_variants_cannot_mix_manual_actions_artifacts_or_not_due_results() {
        let record:IssueRecord=serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p256","challenge":"dns-01","solver_config":{},"solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"web","created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"id","account_thumbprint":"key","directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],"phase":"authorizing","creation_submitted":true,"authorizations":[],"finalize_submitted":"not_submitted"
        })).unwrap();
        let pending = IssueOutcome::ActionRequired {
            record: Box::new(record.clone()),
            records: vec![ValidationRequirement::Dns01 {
                name: "_acme-challenge.example.com".into(),
                value: "txt-value".into(),
            }],
        };
        let root = std::path::Path::new("/data");
        let json: serde_json::Value = serde_json::from_str(
            &outcome(&pending, crate::common::session::Format::plain(true), root).unwrap(),
        )
        .unwrap();
        assert_eq!(json["status"], "action_required");
        assert!(json.get("artifacts").is_none());
        assert!(
            outcome(&pending, crate::common::session::Format::plain(false), root)
                .unwrap()
                .contains("[WARN]")
        );
        assert!(
            !outcome(&pending, crate::common::session::Format::plain(false), root)
                .unwrap()
                .contains("[DONE]")
        );
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
            let human = outcome(
                &completed,
                crate::common::session::Format::plain(false),
                root,
            )
            .unwrap();
            assert!(human.contains(if renewal {
                "Renewed certificate"
            } else {
                "Issued certificate"
            }));
            let json: serde_json::Value = serde_json::from_str(
                &outcome(
                    &completed,
                    crate::common::session::Format::plain(true),
                    root,
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(json["status"], "completed");
            assert!(json.get("resume").is_none());
            assert!(json.get("artifacts").is_some());
        }
        let json: serde_json::Value = serde_json::from_str(
            &not_due(&record, crate::common::session::Format::plain(true)).unwrap(),
        )
        .unwrap();
        assert_eq!(json["status"], "not_due");
        assert!(json.get("resume").is_none());
        assert!(json.get("artifacts").is_none());
        for state in [RevocationState::NotRequested, RevocationState::Pending] {
            let mut record = record.clone();
            record.revocation.state = state;
            assert!(revoked(&record, crate::common::session::Format::plain(true)).is_err());
        }
    }

    #[test]
    fn authorizing_status_and_order_status_keep_their_own_aligned_columns_with_or_without_color() {
        let mut record = detailed_record();
        record.phase = aster_acme_core::workflow::IssuancePhase::Authorizing;
        record.order.as_mut().unwrap().status = aster_acme_core::protocol::OrderStatus::Pending;
        for color in [false, true] {
            let rendered =
                list(std::slice::from_ref(&record), Format { json: false, color }).unwrap();
            let plain = rendered
                .replace("\x1b[1;36m", "")
                .replace("\x1b[33m", "")
                .replace("\x1b[0m", "");
            let header = plain
                .lines()
                .find(|line| line.contains("ORDER STATUS"))
                .unwrap();
            let row = plain
                .lines()
                .find(|line| line.contains("authorizing domains"))
                .unwrap();
            assert!(row.contains("authorizing domains  "));
            assert_eq!(row.find("pending"), header.find("ORDER STATUS"));
        }
    }
    #[test]
    fn new_order_errors_have_local_status_without_inventing_a_ca_order() {
        for (status, label) in [
            (400, "creation rejected"),
            (403, "creation rejected"),
            (409, "creation rejected"),
            (408, "creation deferred"),
            (429, "creation deferred"),
            (503, "creation unconfirmed"),
        ] {
            let mut record = detailed_record();
            record.phase = aster_acme_core::workflow::IssuancePhase::CreatingOrder;
            record.order = None;
            record.order_url = None;
            record.authorizations.clear();
            record.creation_failure = Some(aster_acme::issuance::RequestFailure {
                status, retry_at: None, problem: Some(serde_json::from_value(serde_json::json!({"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"forbidden by policy"})).unwrap()),
            });
            assert_eq!(
                request_status(&record, time::OffsetDateTime::now_utc()),
                label
            );
            for (kind, expected) in [
                (
                    aster_acme_protocol::problem::ProblemKind::RateLimited,
                    "creation deferred",
                ),
                (
                    aster_acme_protocol::problem::ProblemKind::ServerInternal,
                    "creation unconfirmed",
                ),
            ] {
                let mut atypical = record.clone();
                let failure = atypical.creation_failure.as_mut().unwrap();
                failure.status = 400;
                failure.problem.as_mut().unwrap().kind = kind;
                assert_eq!(
                    request_status(&atypical, time::OffsetDateTime::now_utc()),
                    expected
                );
            }
            let human = show(
                std::slice::from_ref(&record),
                crate::common::session::Format::plain(false),
                false,
                DetailView::InUse,
            )
            .unwrap();
            assert!(human.contains(label));
            assert!(human.contains("not observed"));
            assert!(human.contains("forbidden by policy"));
            assert!(human.contains("newOrder HTTP:"));
            let json: serde_json::Value = serde_json::from_str(
                &show(
                    &[record],
                    crate::common::session::Format::plain(true),
                    false,
                    DetailView::InUse,
                )
                .unwrap(),
            )
            .unwrap();
            assert!(json[0]["order"].is_null());
            assert_eq!(json[0]["creation_failure"]["status"], status);
            assert_eq!(
                json[0]["creation_failure"]["problem"]["detail"],
                "forbidden by policy"
            );
        }
    }

    #[test]
    fn deployment_json_status_never_serializes_reload_command_arguments() {
        let entry = aster_acme_cli_storage::issuance::DeploymentBinding {
            permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
            id: "nginx".into(),
            target: aster_acme_cli_storage::issuance::DeploymentTarget::Directory {
                path: std::path::PathBuf::from("/etc/nginx/certs"),
            },
            reload_command: vec!["systemctl".into(), "--password=secret".into()],
            timeout_seconds: 30,
            max_retries: 3,
            generation: Some("generation-1".into()),
            phase: aster_acme::deployment::DeploymentPhase::Deployed,
            attempts: 1,
            retry_failures: 0,
            retry_at: None,
            last_error: None,
        };
        let serialized = serde_json::to_string(&DeploymentStatusView::from(&entry)).unwrap();
        assert!(serialized.contains("generation-1"));
        assert!(!serialized.contains("systemctl"));
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn issued_deployment_failure_is_visible_in_single_and_batch_json_and_exit_status() {
        use crate::commands::cert::report::{CertificateReport, RenewalEntry, RenewalResult};
        use aster_acme::deployment::DeploymentPhase;
        use aster_acme_cli_storage::issuance::{DeploymentBinding, DeploymentTarget};
        for phase in [
            DeploymentPhase::Deployed,
            DeploymentPhase::ReloadFailed,
            DeploymentPhase::ReloadUncertain,
        ] {
            let result_value = CertificateResult::Issued {
                deployment_events: Vec::new(),
                outcome: IssueOutcome::Completed {
                    record: Box::new(detailed_record()),
                    cleanup: Vec::new(),
                },
                deployments: vec![DeploymentBinding {
                    permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
                    id: "nginx".into(),
                    target: DeploymentTarget::Directory {
                        path: "/tmp".into(),
                    },
                    reload_command: vec!["secret-command".into()],
                    timeout_seconds: 30,
                    max_retries: 0,
                    generation: Some("generation".into()),
                    phase,
                    attempts: 1,
                    retry_failures: 0,
                    retry_at: None,
                    last_error: None,
                }],
            };
            let failed = phase != DeploymentPhase::Deployed;
            let report = CertificateReport::Result {
                result: result_value,
                data_dir: "/tmp".into(),
            };
            assert!(matches!(
                (report.exit_status(), failed),
                (crate::common::session::ExitStatus::Failed, true)
                    | (crate::common::session::ExitStatus::Success, false)
            ));
            let text = render(&report, Format::plain(true)).unwrap();
            let json: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(json["deployments"][0]["id"], "nginx");
            assert!(!text.contains("secret-command"));
            let CertificateReport::Result { result, .. } = report else {
                panic!("expected result");
            };
            let batch_report = RenewalBatch {
                entries: vec![RenewalEntry {
                    name: "web".into(),
                    result: RenewalResult::Outcome(result),
                }],
                cancelled: false,
            };
            assert_eq!(batch_report.summary().failed, usize::from(failed));
            assert_eq!(batch_report.summary().completed, usize::from(!failed));
            let json: serde_json::Value = serde_json::from_str(
                &batch(
                    &batch_report,
                    Format::plain(true),
                    std::path::Path::new("/tmp"),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                json["results"][0]["result"]["deployments"][0]["id"],
                "nginx"
            );
            assert!(
                batch(
                    &batch_report,
                    Format::plain(false),
                    std::path::Path::new("/tmp")
                )
                .unwrap()
                .contains(if failed {
                    "deployment failed"
                } else {
                    "completed"
                })
            );
        }
    }
    #[test]
    fn automatic_deployment_uses_same_table_and_orders_events_after_certificate_summary() {
        use crate::commands::cert::report::{DeploymentEvent, DeploymentReport};
        use aster_acme::deployment::DeploymentPhase;
        use aster_acme_cli_storage::issuance::{DeploymentBinding, DeploymentTarget};
        let record = detailed_record();
        let entry = DeploymentBinding {
            permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
            id: "nginx".into(),
            target: DeploymentTarget::Directory {
                path: "/tmp".into(),
            },
            reload_command: vec!["private-command".into()],
            timeout_seconds: 30,
            max_retries: 0,
            generation: Some("generation".into()),
            phase: DeploymentPhase::Deployed,
            attempts: 1,
            retry_failures: 0,
            retry_at: None,
            last_error: None,
        };
        let events = vec![DeploymentEvent {
            deployment: Some("nginx".into()),
            kind: output::MessageKind::Info,
            message: "Started deployment 'nginx'".into(),
            at: record.created_at,
        }];
        let manual = deployment_report(
            &DeploymentReport {
                events: Vec::new(),
                name: record.name.as_str().into(),
                entries: vec![entry.clone()],
                attempted: true,
            },
            Format::plain(false),
        )
        .unwrap();
        let outcome = IssueOutcome::Completed {
            record: Box::new(record),
            cleanup: Vec::new(),
        };
        let automatic = issued_result(
            &outcome,
            &[entry],
            &events,
            Format::plain(false),
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        assert!(automatic.ends_with(&manual));
        assert!(automatic.contains("\n\n[2026-01-01 00:00:00 UTC] [INFO]"));
        assert!(automatic.find("[DONE]").unwrap() < automatic.find("Started deployment").unwrap());
        assert!(!automatic.contains("Deployment targets:"));
        assert!(!automatic.contains("private-command"));
    }
}
