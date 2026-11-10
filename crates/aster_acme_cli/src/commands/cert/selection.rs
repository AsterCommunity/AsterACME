//! Deterministic name-to-generation selection; scripts never silently pick the newest.
use crate::common::{error::CliResult, terminal};
use aster_acme::issuance::{CertificateName, IssueRecord};

pub(super) fn certificate_name(
    records: &[IssueRecord],
    explicit: Option<&str>,
    operation: Option<&str>,
    json: bool,
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
    if !terminal::interactive(json) {
        return Err("Specify a certificate NAME or --operation <ID>, or use an interactive terminal to select a certificate.".into());
    }
    let certificates = managed_records(records.to_vec())?;
    if certificates.is_empty() {
        return Err("No saved certificates. Use cert issue -d <DOMAIN> to request one.".into());
    }
    let choices = certificates
        .iter()
        .map(certificate_label)
        .collect::<Vec<_>>();
    let index = terminal::select_index("Choose a certificate:", &choices, 0)?;
    Ok(certificates
        .get(index)
        .ok_or("Invalid certificate selection.")?
        .name
        .clone())
}

fn certificate_label(record: &IssueRecord) -> String {
    crate::common::selection::ChoiceLabel {
        name: record.name.as_str(),
        summary: Some(&super::render::domain_summary(record)),
        at: Some(record.created_at),
        status: Some(super::render::request_status(
            record,
            time::OffsetDateTime::now_utc(),
        )),
        marker: None,
    }
    .to_string()
}

/// Selection intent prevents an inactive historical version becoming an implicit `in_use`.
#[derive(Clone, Copy)]
pub(super) enum RequestSelection {
    Unfinished,
    InUse,
    Any,
}

/// One visible row per managed certificate. Inactive fallback rows are inventory only;
/// they are never promoted or scheduled, and show still requires explicit history selection.
pub(super) fn managed_records(records: Vec<IssueRecord>) -> CliResult<Vec<IssueRecord>> {
    let mut grouped = std::collections::BTreeMap::<String, Vec<IssueRecord>>::new();
    for record in records {
        grouped
            .entry(record.name.as_str().into())
            .or_default()
            .push(record);
    }
    grouped
        .into_values()
        .map(|mut records| {
            if records.iter().filter(|record| record.is_in_use).count() > 1 {
                return Err("Multiple in_use versions found for one managed certificate.".into());
            }
            records.sort_by(|a, b| {
                b.is_in_use
                    .cmp(&a.is_in_use)
                    .then_with(|| b.unfinished().cmp(&a.unfinished()))
                    .then(b.created_at.cmp(&a.created_at))
                    .then(a.operation_id.cmp(&b.operation_id))
            });
            records
                .into_iter()
                .next()
                .ok_or_else(|| "Empty certificate inventory group.".into())
        })
        .collect()
}

pub(super) fn choose(
    records: Vec<IssueRecord>,
    name: &CertificateName,
    id: Option<&str>,
    mode: RequestSelection,
    json: bool,
) -> CliResult<IssueRecord> {
    let mut candidates = records
        .into_iter()
        .filter(|record| {
            record.name == *name
                && match mode {
                    RequestSelection::Unfinished => record.unfinished(),
                    RequestSelection::InUse | RequestSelection::Any => true,
                }
                && id.is_none_or(|id| id == record.operation_id)
        })
        .collect::<Vec<_>>();
    if matches!(mode, RequestSelection::InUse) && id.is_none() {
        let in_use_count = candidates.iter().filter(|record| record.is_in_use).count();
        match in_use_count {
            0 => candidates.retain(IssueRecord::unfinished),
            1 => candidates.retain(|record| record.is_in_use),
            _ => {
                return Err(
                    "Multiple in_use versions found; inspect local certificate storage.".into(),
                );
            }
        }
        if candidates.is_empty() {
            return Err("No in_use or unfinished request is selected. Use cert show --history or --operation <ID> to inspect retained versions.".into());
        }
    }
    match candidates.as_slice() {
        [] => Err("No matching saved request. Use cert list to inspect existing requests; a new request must be started explicitly.".into()),
        [record] => Ok(record.clone()),
        _ if !terminal::interactive(json) => Err("Several saved requests match. Use cert list and specify --operation <ID>; no request was selected automatically.".into()),
        _ => {
            let choices=candidates.iter().map(choice_label).collect::<Vec<_>>();
            let index = terminal::select_index("Choose a saved certificate request:", &choices, 0)?;
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
