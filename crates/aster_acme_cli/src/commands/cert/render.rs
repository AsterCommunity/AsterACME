//! Human and typed JSON presentation; never contains private keys or CSRs.

use crate::commands::cert::render::deployment::{deployment_removed, deployment_report};
use crate::commands::cert::render::inspection::show;
use crate::commands::cert::render::outcome::result;
use crate::commands::cert::render::{
    batch::batch,
    inspection::list,
    lifecycle::{removed, revoked},
};
use crate::common::error::CliResult;
use crate::common::output;
use crate::common::session::Format;
use aster_acme::issuance::IssueRecord;
use aster_acme_core::revocation::RevocationState;

pub(crate) mod deployment;

pub(crate) mod batch;
pub(crate) mod details;
pub(crate) mod inspection;
pub(crate) mod lifecycle;
pub(crate) mod maintenance;
pub(crate) mod materials;
pub(crate) mod outcome;

pub(crate) fn render(
    report: &crate::commands::cert::report::CertificateReport,
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

#[cfg(test)]
pub(crate) mod tests;
