//! Huawei TXT presentation and value-bound publication markers.
use crate::provider::marker::{is_publication_marker, matches_publication};
use aster_acme_dns::{ProviderError, backend::configuration_error};
pub(super) fn has_marker(description: &str, marker: &str) -> bool {
    description
        .split(';')
        .any(|part| matches_publication_marker(part, marker))
}

pub(super) fn has_foreign_marker(description: &str, marker: &str) -> bool {
    let expected_hash = marker.split_once('=').map(|(_, hash)| hash);
    description
        .split(';')
        .filter(|part| is_publication_marker(part))
        .any(|part| {
            if matches_publication_marker(part, marker) {
                return false;
            }
            let Some(expected_hash) = expected_hash else {
                return true;
            };
            part.split_once('=').is_none_or(|(_, hash)| {
                hash.len() != 64
                    || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || hash.eq_ignore_ascii_case(expected_hash)
            })
        })
}

fn matches_publication_marker(actual: &str, expected: &str) -> bool {
    if actual == expected {
        return true;
    }
    let Some((expected_id, expected_hash)) = expected
        .strip_prefix("asteracme-")
        .and_then(|value| value.split_once('='))
    else {
        return false;
    };
    actual == format!("asteracme:{expected_id}={expected_hash}")
        || matches_publication(actual, expected_id)
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
        .filter(|part| *part != marker)
        .collect::<Vec<_>>()
        .join(";")
}

pub(super) fn txt_encode(value: &str) -> String {
    use std::fmt::Write;
    let mut output = String::from("\"");
    for byte in value.bytes() {
        match byte {
            b'"' | b'\\' => {
                output.push('\\');
                output.push(char::from(byte));
            }
            0x20..=0x7e => output.push(char::from(byte)),
            _ => {
                let _ = write!(output, "\\{byte:03}");
            }
        }
    }
    output.push('"');
    output
}

pub(super) fn txt_decode(value: &str) -> Option<Vec<u8>> {
    let mut input = value.bytes().peekable();
    let mut output = Vec::new();
    let mut chunks = 0;
    while input.peek().is_some() {
        while input.peek().is_some_and(u8::is_ascii_whitespace) {
            input.next();
        }
        if input.peek().is_none() {
            break;
        }
        if input.next()? != b'"' {
            return None;
        }
        chunks += 1;
        let start = output.len();
        loop {
            match input.next()? {
                b'"' => break,
                b'\\' => {
                    let byte = input.next()?;
                    if byte.is_ascii_digit() {
                        let next = input.next()?;
                        let last = input.next()?;
                        if !next.is_ascii_digit() || !last.is_ascii_digit() {
                            return None;
                        }
                        let number = u16::from(byte - b'0') * 100
                            + u16::from(next - b'0') * 10
                            + u16::from(last - b'0');
                        output.push(u8::try_from(number).ok()?);
                    } else {
                        output.push(byte);
                    }
                }
                byte => output.push(byte),
            }
        }
        if output.len() - start > 255 {
            return None;
        }
    }
    (chunks > 0).then_some(output)
}
