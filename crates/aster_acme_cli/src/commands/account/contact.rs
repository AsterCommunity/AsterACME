//! User email addresses become RFC 8555 contact URIs at the CLI boundary.

use aster_acme::account::AccountError;

/// Accept one plain mailbox or an explicit mailto URI per input, without trimming or
/// decoding user text. Reject URI headers and separators before any HTTP request.
pub(crate) fn normalize(contacts: Vec<String>) -> Result<Vec<String>, AccountError> {
    if contacts.len() > 32 {
        return Err(AccountError::InvalidContact);
    }
    contacts
        .into_iter()
        .map(|contact| {
            let address = contact.strip_prefix("mailto:").unwrap_or(&contact);
            let (local, domain) = address
                .split_once('@')
                .ok_or(AccountError::InvalidContact)?;
            if local.is_empty()
                || domain.is_empty()
                || domain.contains('@')
                || address.chars().any(|c| c.is_whitespace() || c.is_control())
                || address.contains([
                    ':', '?', '#', ',', ';', '%', '<', '>', '"', '\\', '/', '[', ']', '=', '&',
                ])
                || address.len() > 2041
            {
                return Err(AccountError::InvalidContact);
            }
            Ok(format!("mailto:{address}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::commands::account::contact::*;

    #[test]
    fn plain_and_explicit_mailboxes_have_the_same_wire_representation() {
        assert_eq!(
            normalize(vec![
                "you@example.com".into(),
                "mailto:other@example.com".into()
            ])
            .unwrap(),
            vec!["mailto:you@example.com", "mailto:other@example.com"]
        );
        assert_eq!(normalize(vec![]).unwrap(), Vec::<String>::new());
        assert!(normalize(vec!["you@example.com".into(); 32]).is_ok());
        assert!(normalize(vec!["you@example.com".into(); 33]).is_err());
    }

    #[test]
    fn malformed_mailboxes_headers_and_injection_are_rejected() {
        for address in [
            "",
            "mailto:",
            "@example.com",
            "you@",
            "you",
            "you@@example.com",
            " you@example.com",
            "you @example.com",
            "you@example.com\n",
            "you@example.com?subject=test",
            "you@example.com#fragment",
            "a@example.com,b@example.com",
            "a@example.com;b@example.com",
            "a%0Ab@example.com",
            "ops=acme@example.com",
            "ops&acme@example.com",
            "https://a@example.com",
            "<a@example.com>",
        ] {
            for input in [address.to_owned(), format!("mailto:{address}")] {
                assert!(normalize(vec![input.clone()]).is_err(), "{input:?}");
            }
        }
        assert!(normalize(vec![format!("{}@x", "a".repeat(2039))]).is_ok());
        assert!(normalize(vec![format!("{}@x", "a".repeat(2040))]).is_err());
    }
}
