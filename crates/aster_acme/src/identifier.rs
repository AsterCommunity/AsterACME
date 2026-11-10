//! Validated DNS names and ACME identifier representations.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

/// Invalid caller input or unsupported wire identifier.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdentifierError {
    /// A DNS name violates label or total-length constraints.
    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),
    /// A certificate DNS identifier is an IP address or contains non-host labels.
    #[error("not a certificate DNS identifier: {0}")]
    InvalidDnsIdentifier(String),
    /// The wire identifier type is not supported by this client.
    #[error("unsupported identifier type: {0}")]
    UnsupportedType(String),
    /// ACME authorization identifiers must not contain a wildcard prefix.
    #[error("authorization identifier must contain the base DNS name")]
    WildcardAuthorizationValue,
}

/// Canonical DNS name without a trailing dot; underscores are allowed for TXT owners.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DnsName(String);

impl DnsName {
    /// Normalize case, a single trailing dot, and internationalized labels.
    ///
    /// # Errors
    /// Returns an error for malformed, empty, or oversized names and labels.
    pub fn new(value: &str) -> Result<Self, IdentifierError> {
        let invalid = || IdentifierError::InvalidDnsName(value.to_owned());
        let ascii = idna::domain_to_ascii(value).map_err(|_| invalid())?;
        let name = ascii
            .strip_suffix('.')
            .unwrap_or(&ascii)
            .to_ascii_lowercase();
        if name.is_empty() || name.len() > 253 {
            return Err(invalid());
        }
        for label in name.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            {
                return Err(invalid());
            }
        }
        Ok(Self(name))
    }

    /// The normalized ASCII name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DnsName {
    type Error = IdentifierError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<DnsName> for String {
    fn from(value: DnsName) -> Self {
        value.0
    }
}

/// Certificate DNS identifier with an optional leftmost wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DnsIdentifier {
    name: DnsName,
    wildcard: bool,
}

impl DnsIdentifier {
    /// Parse and normalize a DNS certificate identifier.
    ///
    /// # Errors
    /// Rejects IP addresses, underscores, malformed names and non-leftmost wildcards.
    pub fn new(value: &str) -> Result<Self, IdentifierError> {
        let (base, wildcard) = value
            .strip_prefix("*.")
            .map_or((value, false), |v| (v, true));
        let name = DnsName::new(base)?;
        if name.as_str().contains('_')
            || name.as_str().parse::<IpAddr>().is_ok()
            || (wildcard && name.as_str().len() > 251)
        {
            return Err(IdentifierError::InvalidDnsIdentifier(value.to_owned()));
        }
        Ok(Self { name, wildcard })
    }

    /// Base name, without `*.`.
    #[must_use]
    pub fn name(&self) -> &DnsName {
        &self.name
    }

    /// Whether the requested certificate covers a wildcard.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// Canonical ACME order identifier value.
    #[must_use]
    pub fn value(&self) -> String {
        if self.wildcard {
            format!("*.{}", self.name.as_str())
        } else {
            self.name.as_str().to_owned()
        }
    }
}

impl TryFrom<String> for DnsIdentifier {
    type Error = IdentifierError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<DnsIdentifier> for String {
    fn from(value: DnsIdentifier) -> Self {
        value.value()
    }
}

/// Identifiers supported for execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Identifier {
    /// DNS certificate identifier.
    Dns(DnsIdentifier),
}

/// Wire representation preserves unsupported types for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireIdentifier {
    /// ACME identifier type.
    #[serde(rename = "type")]
    pub kind: String,
    /// Unmodified wire value.
    pub value: String,
}

impl TryFrom<WireIdentifier> for Identifier {
    type Error = IdentifierError;
    fn try_from(value: WireIdentifier) -> Result<Self, Self::Error> {
        match value.kind.as_str() {
            "dns" => Ok(Self::Dns(DnsIdentifier::new(&value.value)?)),
            _ => Err(IdentifierError::UnsupportedType(value.kind)),
        }
    }
}

impl From<&Identifier> for WireIdentifier {
    fn from(value: &Identifier) -> Self {
        match value {
            Identifier::Dns(dns) => Self {
                kind: "dns".into(),
                value: dns.value(),
            },
        }
    }
}

/// Interpret RFC 8555 authorization `identifier` and its sibling `wildcard` flag.
///
/// # Errors
/// Rejects unsupported types and wildcard prefixes in authorization values.
pub fn authorization_identifier(
    wire: WireIdentifier,
    wildcard: bool,
) -> Result<Identifier, IdentifierError> {
    let Identifier::Dns(mut dns) = Identifier::try_from(wire)?;
    if dns.is_wildcard() {
        return Err(IdentifierError::WildcardAuthorizationValue);
    }
    dns.wildcard = wildcard;
    Ok(Identifier::Dns(dns))
}
