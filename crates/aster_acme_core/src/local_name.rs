//! Portable managed-directory names shared by account and certificate identities.
//! This is a pure naming rule, not filesystem access or Windows ACL policy.

/// Accept one ASCII component that can be represented on Unix and Windows.
/// Owners may impose narrower alphabets and lengths. DOS device names remain
/// reserved even with an extension; wildcard DNS identifiers are not file names.
#[must_use]
pub fn valid_component(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || matches!(value, "." | "..")
        || value.ends_with(['.', ' '])
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !matches!(
            stem.strip_prefix("COM")
                .or_else(|| stem.strip_prefix("LPT")),
            Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_names_path_escapes_and_nonportable_characters_are_rejected() {
        for value in [
            "",
            ".",
            "..",
            "CON",
            "con.pem",
            "NUL",
            "LPT1",
            "COM9.txt",
            "a.",
            "a/b",
            "a\\b",
            "a:b",
            "*.example.com",
            "a ",
        ] {
            assert!(!valid_component(value), "{value}");
        }
        for value in [
            "default",
            "example.com",
            "wildcard-example.com",
            "cert-con.example",
            ".generation",
            "COM10",
        ] {
            assert!(valid_component(value), "{value}");
        }
    }
}
