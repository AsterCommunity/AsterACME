//! Deterministic name-to-generation selection; scripts never silently pick the newest.
use crate::common::output;
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
        return Err("Specify cert show <NAME> or --operation <ID>, or use an interactive terminal to select a certificate.".into());
    }
    let mut names = records
        .iter()
        .map(|record| record.name.as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        return Err("No saved certificates. Use cert issue -d <DOMAIN> to request one.".into());
    }
    let choices = names
        .iter()
        .map(|name| output::safe(name))
        .collect::<Vec<_>>();
    let index = terminal::select_index("Choose a certificate:", &choices, 0)?;
    Ok(CertificateName::new(
        names.get(index).ok_or("Invalid certificate selection.")?,
    )?)
}

pub(super) fn choose(
    records: Vec<IssueRecord>,
    name: &CertificateName,
    id: Option<&str>,
    unfinished: bool,
    json: bool,
) -> CliResult<IssueRecord> {
    let candidates = records
        .into_iter()
        .filter(|record| {
            record.name == *name
                && (!unfinished || record.unfinished())
                && id.is_none_or(|id| id == record.operation_id)
        })
        .collect::<Vec<_>>();
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
    let primary = record.identifiers.first().map_or_else(
        || record.name.as_str().to_owned(),
        aster_acme::identifier::DnsIdentifier::value,
    );
    let status = if record.expired(time::OffsetDateTime::now_utc()) {
        "expired"
    } else {
        super::render::phase_label(record.phase)
    };
    format!(
        "{} | {} | {status}",
        output::safe(&primary),
        crate::common::time::timestamp(Some(record.created_at))
    )
}

#[cfg(test)]
mod tests;
