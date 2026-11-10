//! RFC 9773 renewal information wire resources and certificate-specific URLs.

use crate::url::{AcmeUrl, InvalidAcmeUrl};
use serde::{Deserialize, Serialize};

/// CA-suggested renewal interval; semantic validity is checked by the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestedWindow {
    /// Inclusive beginning of the suggested interval.
    #[serde(with = "time::serde::rfc3339")]
    pub start: time::OffsetDateTime,
    /// End of the suggested interval.
    #[serde(with = "time::serde::rfc3339")]
    pub end: time::OffsetDateTime,
}

/// RFC 9773 section 4.2 response; unknown extensions are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewalInfo {
    /// Renewal window, not certificate validity or an order deadline.
    pub suggested_window: SuggestedWindow,
    /// Optional operator-facing explanation; never fetched automatically.
    pub explanation_url: Option<String>,
}

/// Append a certificate identifier to the discovered endpoint, preserving query data.
/// This suffix is defined by RFC 9773 section 4.1, unlike CA-specific ACME paths.
///
/// # Errors
/// Rejects unsafe identifiers or endpoints that cannot be used as a base URL.
pub fn information_url(endpoint: &AcmeUrl, identifier: &str) -> Result<AcmeUrl, InvalidAcmeUrl> {
    let parts = identifier.split('.').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
    {
        return Err(InvalidAcmeUrl);
    }
    let mut url = url::Url::parse(endpoint.as_str()).map_err(|_| InvalidAcmeUrl)?;
    url.path_segments_mut()
        .map_err(|()| InvalidAcmeUrl)?
        .pop_if_empty()
        .push(identifier);
    AcmeUrl::new(url.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovered_paths_queries_and_identifier_boundaries() {
        for endpoint in ["https://ca.example/custom", "https://ca.example/custom/"] {
            assert_eq!(
                information_url(&AcmeUrl::new(endpoint).unwrap(), "aYhb.AIdlQyE")
                    .unwrap()
                    .as_str(),
                "https://ca.example/custom/aYhb.AIdlQyE"
            );
        }
        assert_eq!(
            information_url(
                &AcmeUrl::new("https://ca.example/custom?tenant=1").unwrap(),
                "a.b"
            )
            .unwrap()
            .as_str(),
            "https://ca.example/custom/a.b?tenant=1"
        );
        for id in ["", "a", ".a", "a.", "a.b.c", "a../b", "a.b=", "a.b?x"] {
            assert!(information_url(&AcmeUrl::new("https://ca.example/ari").unwrap(), id).is_err());
        }
    }
}
