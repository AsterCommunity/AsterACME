pub(in crate::provider) fn publication(id: &str) -> String {
    format!("asteracme-{id}")
}

pub(in crate::provider) fn is_publication_marker(marker: &str) -> bool {
    let Some(marker) = marker.strip_prefix("asteracme-") else {
        return false;
    };
    valid_publication_id(marker)
}

pub(in crate::provider) fn matches_publication(marker: &str, id: &str) -> bool {
    marker == publication(id)
}

fn valid_publication_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 90
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
