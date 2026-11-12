//! Exact server resource URLs, validated without normalizing signed strings.
use serde::{Deserialize, Serialize};
use url::{Host, Url};

/// An unsafe or non-absolute ACME resource URL was supplied.
#[derive(Debug, thiserror::Error)]
#[error("invalid ACME URL: require HTTPS without credentials or fragments")]
pub struct InvalidAcmeUrl;

/// Exact CA-provided URL string, kept intact for the JWS protected `url` field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AcmeUrl(String);

impl std::fmt::Display for AcmeUrl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AcmeUrl {
    /// Validate an absolute HTTPS URL, or an HTTP numeric loopback URL for local tests.
    /// Transport additionally requires opt-in before using loopback HTTP.
    ///
    /// # Errors
    /// Rejects credentials, fragments, non-HTTP schemes and non-loopback plaintext HTTP.
    pub fn new(value: &str) -> Result<Self, InvalidAcmeUrl> {
        let parsed = Url::parse(value).map_err(|_| InvalidAcmeUrl)?;
        let loopback = match parsed.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            Some(Host::Domain(_)) | None => false,
        };
        if parsed.host().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || value.chars().any(|c| {
                c.is_control()
                    || c.is_whitespace()
                    || matches!(c, '"' | '<' | '>' | '`' | '{' | '}' | '\\')
            })
            // RFC 3986 §§2.2/3.4 permits apostrophes, but WHATWG special-query
            // parsing encodes them. RFC 8555 §6.4 forbids re-encoding the signed
            // server URL. Inspect the raw query: parsed.query() already lost it.
            // Path apostrophes and an explicit %27 remain supported.
            || value.split_once('?').is_some_and(|(_, query)| query.contains('\''))
            || value.trim() != value
        {
            return Err(InvalidAcmeUrl);
        }
        // RFC 8555 §6.4 requires the exact supplied target, while WHATWG
        // removes literal/encoded dot segments. Never sign a different path.
        let authority = value.find("://").ok_or(InvalidAcmeUrl)? + 3;
        let rest = &value[authority..];
        let raw_path = rest
            .find('/')
            .filter(|index| rest.find('?').is_none_or(|query| *index < query))
            .map_or("/", |index| {
                rest[index..].split(['?', '#']).next().unwrap_or("/")
            });
        if raw_path != parsed.path() {
            return Err(InvalidAcmeUrl);
        }
        match parsed.scheme() {
            "https" => Ok(Self(value.to_owned())),
            "http" if loopback => Ok(Self(value.to_owned())),
            _ => Err(InvalidAcmeUrl),
        }
    }

    /// Original string, without re-encoding CA resource URLs.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for AcmeUrl {
    type Error = InvalidAcmeUrl;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}
impl From<AcmeUrl> for String {
    fn from(value: AcmeUrl) -> Self {
        value.0
    }
}
