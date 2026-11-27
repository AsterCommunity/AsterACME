//! Huawei TXT presentation and value-bound publication markers.
use crate::provider::common::marker::is_publication_marker;
use aster_acme_dns::{ProviderError, backend::configuration_error};
pub(super) fn has_marker(description: &str, marker: &str) -> bool {
    description
        .split(';')
        .any(|part| matches_publication_marker(part, marker))
}

pub(super) fn has_foreign_marker(description: &str, marker: &str) -> bool {
    let Some((expected_id, expected_hash)) = parse_huawei_marker(marker) else {
        return false;
    };
    description
        .split(';')
        .filter_map(parse_huawei_marker)
        .any(|(id, hash)| id != expected_id && hash.eq_ignore_ascii_case(expected_hash))
}

fn matches_publication_marker(actual: &str, expected: &str) -> bool {
    actual == expected && parse_huawei_marker(actual).is_some()
}

fn valid_huawei_marker(id: &str, hash: &str) -> bool {
    is_publication_marker(&format!("asteracme-{id}"))
        && hash.len() == 64
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_huawei_marker(marker: &str) -> Option<(&str, &str)> {
    let (id, hash) = marker.strip_prefix("asteracme-")?.split_once('=')?;
    valid_huawei_marker(id, hash).then_some((id, hash))
}

pub(super) fn add_marker(description: &str, marker: &str) -> Result<String, ProviderError> {
    let result = if description.is_empty() {
        marker.to_owned()
    } else if has_marker(description, marker) {
        description.to_owned()
    } else {
        format!("{description};{marker}")
    };
    if result.len() > 255 {
        return Err(configuration_error(
            "Huawei DNS RRset description exceeds 255 bytes",
        ));
    }
    Ok(result)
}

pub(super) fn remove_marker(description: &str, marker: &str) -> String {
    description
        .split(';')
        .filter(|part| !matches_publication_marker(part, marker))
        .collect::<Vec<_>>()
        .join(";")
}
