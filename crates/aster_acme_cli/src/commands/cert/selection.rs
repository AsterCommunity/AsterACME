//! Deterministic name-to-generation selection; scripts never silently pick the newest.
use crate::common::{error::CliResult, terminal};
use aster_acme::issuance::{CertificateName, IssueRecord};

/// Return a saved terminal problem for an explicit target, without hiding valid
/// unfinished siblings under the same managed name or performing a CA query.
pub(super) fn check_explicit_resume(
    records: &[IssueRecord],
    explicit: &super::args::ResumeTarget,
    operation: Option<&str>,
) -> CliResult<()> {
    if let super::args::ResumeTarget::Named(name) = explicit {
        let matches = |record: &&IssueRecord| {
            record.name.as_str() == name && operation.is_none_or(|id| id == record.operation_id)
        };
        if !records
            .iter()
            .filter(matches)
            .any(IssueRecord::resume_candidate)
            && let Some(invalid) = records
                .iter()
                .filter(matches)
                .find(|record| record.unfinished() && !record.resume_candidate())
        {
            invalid.check_recovery(time::OffsetDateTime::now_utc())?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum CertificateLabel {
    Standard,
    Deployment,
}

pub(super) fn certificate_name(
    records: &[IssueRecord],
    explicit: Option<&str>,
    operation: Option<&str>,
    label: CertificateLabel,
    output: &crate::common::session::OutputSession,
) -> CliResult<CertificateName> {
    if let Some(name) = explicit {
        return Ok(CertificateName::new(name)?);
    }
    if let Some(id) = operation {
        return records
            .iter()
            .find(|record| record.operation_id == id)
            .map(|record| record.name.clone())
            .ok_or_else(|| "No saved certificate request matches --operation.".into());
    }
    if !terminal::interactive(output.is_json()) {
        return Err("Specify a certificate NAME or --operation <ID>, or use an interactive terminal to select a certificate.".into());
    }
    let mut names = std::collections::BTreeMap::new();
    for record in records {
        names.entry(record.name.as_str()).or_insert(record);
    }
    let certificates = names.into_values().collect::<Vec<_>>();
    if certificates.is_empty() {
        return Err("No saved certificates. Use cert issue -d <DOMAIN> to request one.".into());
    }
    let choices = certificates
        .iter()
        .map(|record| certificate_label(record, label))
        .collect::<Vec<_>>();
    let index = terminal::select_index("Choose a certificate:", &choices, 0, output)?;
    Ok(certificates
        .get(index)
        .ok_or("Invalid certificate selection.")?
        .name
        .clone())
}

/// Resolve a deployment target from the completed `in_use` rows returned by storage.
pub(super) fn deployment_certificate_name(
    records: &[IssueRecord],
    explicit: Option<&str>,
    output: &crate::common::session::OutputSession,
) -> CliResult<CertificateName> {
    if let Some(name) = explicit {
        let name = CertificateName::new(name)?;
        if records.iter().any(|record| record.name == name) {
            return Ok(name);
        }
        return Err(format!(
            "Certificate '{}' has no completed, non-revoked in-use version to deploy.",
            name.as_str()
        )
        .into());
    }
    if records.is_empty() {
        return Err(
            "No completed, non-revoked in-use certificates are available for deployment.".into(),
        );
    }
    certificate_name(records, None, None, CertificateLabel::Deployment, output)
}

fn certificate_label(record: &IssueRecord, label: CertificateLabel) -> String {
    let deployments = match label {
        CertificateLabel::Standard => None,
        CertificateLabel::Deployment => Some(match record.deployment_count {
            Some(0) => "deployments: none".into(),
            Some(count) => format!("deployments: {count}"),
            None => "deployments: unknown".into(),
        }),
    };
    crate::common::selection::ChoiceLabel {
        name: record.name.as_str(),
        summary: Some(&super::render::domain_summary(record)),
        at: Some(record.created_at),
        status: Some(super::render::request_status(
            record,
            time::OffsetDateTime::now_utc(),
        )),
        marker: deployments.as_deref(),
    }
    .to_string()
}

/// Selection intent prevents an inactive historical version becoming an implicit `in_use`.
#[derive(Clone, Copy)]
pub(super) enum RequestSelection {
    InUse,
    Any,
    Completed,
}

pub(super) fn choose(
    records: Vec<IssueRecord>,
    name: &CertificateName,
    id: Option<&str>,
    output: &crate::common::session::OutputSession,
) -> CliResult<IssueRecord> {
    let candidates = records
        .into_iter()
        .filter(|record| record.name == *name && id.is_none_or(|id| record.operation_id == id))
        .collect::<Vec<_>>();
    match candidates.len() {
        0 => Err("No matching saved request. Use cert list to inspect existing requests; a new request must be started explicitly.".into()),
        1 => candidates.into_iter().next().ok_or_else(|| "Missing selected request.".into()),
        _ if !terminal::interactive(output.is_json()) => Err("Several saved requests match. Use cert list and specify --operation <ID>; no request was selected automatically.".into()),
        _ => {
            let choices=candidates.iter().map(choice_label).collect::<Vec<_>>();
            let index = terminal::select_index("Choose a saved certificate request:", &choices, 0, output)?;
            candidates.into_iter().nth(index).ok_or_else(||"Invalid request selection.".into())
        }
    }
}

fn choice_label(record: &IssueRecord) -> String {
    crate::common::selection::ChoiceLabel {
        name: &super::render::domain_summary(record),
        summary: None,
        at: Some(record.created_at),
        status: Some(super::render::request_status(
            record,
            time::OffsetDateTime::now_utc(),
        )),
        marker: if record.is_in_use {
            Some("in use")
        } else {
            None
        },
    }
    .to_string()
}

#[cfg(test)]
mod tests;
