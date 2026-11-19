//! Validated DNS names, IP addresses and ACME identifier representations.

use aster_acme_protocol::order::WireIdentifier;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr as _;
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
    /// An IP identifier is not a bare IPv4 or IPv6 literal.
    #[error("invalid IP identifier: {0}")]
    InvalidIpAddress(String),
    /// The wire identifier type is not supported by this client.
    #[error("unsupported identifier type: {0}")]
    UnsupportedType(String),
    /// ACME authorization identifiers must not contain a wildcard prefix.
    #[error("authorization identifier must contain the base DNS name")]
    WildcardAuthorizationValue,
    /// RFC 8738 defines no wildcard concept for IP identifiers.
    #[error("IP identifiers do not support wildcard authorizations")]
    WildcardIpAuthorization,
}

/// Canonical DNS name without a trailing dot; underscores are allowed for TXT owners.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
///
/// "DNS identifier" is the RFC 8555 wire type `dns`: the domain name a
/// certificate is issued for, paired with [`IpIdentifier`] for wire type `ip`
/// (RFC 8738). It differs from [`DnsName`], which only validates syntax and
/// also accepts underscore TXT owners.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
            || matches!(
                url::Host::parse(name.as_str()),
                Ok(url::Host::Ipv4(_) | url::Host::Ipv6(_))
            )
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
    pub const fn is_wildcard(&self) -> bool {
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

/// Certificate IP identifier; the canonical RFC 5952 text is the wire value
/// (RFC 8738 section 3). Zone IDs and ports are not part of an IP identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IpIdentifier(IpAddr);

impl IpIdentifier {
    /// Parse a bare IPv4 or IPv6 literal and keep its canonical form.
    ///
    /// # Errors
    /// Rejects any input that is not a valid IP literal, including hosts,
    /// ports and IPv6 zone IDs.
    pub fn new(value: &str) -> Result<Self, IdentifierError> {
        let invalid = || IdentifierError::InvalidIpAddress(value.to_owned());
        IpAddr::from_str(value).map(Self).map_err(|_| invalid())
    }

    /// The parsed address; comparisons use this, never the input text.
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.0
    }

    /// Canonical ACME order identifier value.
    #[must_use]
    pub fn value(&self) -> String {
        self.0.to_string()
    }

    /// RFC 8738 section 6 SNI: the IN-ADDR.ARPA or IP6.ARPA reverse mapping.
    /// RFC 6066 forbids IP literals in the SNI host name field.
    #[must_use]
    pub fn reverse_name(&self) -> String {
        // One allocation: at most 32 hex nibbles, dots and the suffix.
        let mut name = String::with_capacity(64 + ".ip6.arpa".len());
        match self.0 {
            IpAddr::V4(address) => {
                let [a, b, c, d] = address.octets();
                let mut first = true;
                for octet in [d, c, b, a] {
                    if !first {
                        name.push('.');
                    }
                    first = false;
                    push_decimal(&mut name, octet);
                }
                name.push_str(".in-addr.arpa");
            }
            IpAddr::V6(address) => {
                let octets = address.octets();
                let mut first = true;
                for byte in octets.iter().rev() {
                    for nibble in [byte & 0x0f, byte >> 4] {
                        if !first {
                            name.push('.');
                        }
                        first = false;
                        name.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
                    }
                }
                name.push_str(".ip6.arpa");
            }
        }
        name
    }
}

impl TryFrom<String> for IpIdentifier {
    type Error = IdentifierError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<IpIdentifier> for String {
    fn from(value: IpIdentifier) -> Self {
        value.value()
    }
}

impl From<Ipv4Addr> for IpIdentifier {
    fn from(address: Ipv4Addr) -> Self {
        Self(IpAddr::V4(address))
    }
}

impl From<Ipv6Addr> for IpIdentifier {
    fn from(address: Ipv6Addr) -> Self {
        Self(IpAddr::V6(address))
    }
}

/// Append a byte in decimal form without an intermediate allocation.
fn push_decimal(out: &mut String, value: u8) {
    if value >= 100 {
        out.push(char::from_digit(u32::from(value / 100), 10).unwrap_or('0'));
    }
    if value >= 10 {
        out.push(char::from_digit(u32::from((value / 10) % 10), 10).unwrap_or('0'));
    }
    out.push(char::from_digit(u32::from(value % 10), 10).unwrap_or('0'));
}

/// Identifiers supported for execution: the certificate subjects an order can request.
///
/// [`Identifier::Dns`] covers RFC 8555 wire type `dns` (domain names,
/// optionally with a leftmost wildcard); [`Identifier::Ip`] covers RFC 8738
/// wire type `ip` (IPv4/IPv6 literals, never wildcarded). Use [`Identifier::new`]
/// to parse a stored string, or construct the variant directly when the kind
/// is known.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Identifier {
    /// DNS certificate identifier.
    Dns(DnsIdentifier),
    /// IP certificate identifier (RFC 8738).
    Ip(IpIdentifier),
}

impl Identifier {
    /// Parse a caller-supplied identifier: a bare IP literal becomes an IP
    /// identifier, anything else a DNS identifier. Only IP identifiers that
    /// parse as an exact IP literal take the IP path, so the mapping of a
    /// stored string back to its kind is unambiguous.
    ///
    /// # Errors
    /// Returns the DNS error when the value is neither an IP literal nor a
    /// valid DNS certificate identifier.
    pub fn new(value: &str) -> Result<Self, IdentifierError> {
        if let Ok(address) = IpIdentifier::new(value) {
            return Ok(Self::Ip(address));
        }
        DnsIdentifier::new(value).map(Self::Dns)
    }

    /// Canonical ACME order identifier value.
    #[must_use]
    pub fn value(&self) -> String {
        match self {
            Self::Dns(dns) => dns.value(),
            Self::Ip(ip) => ip.value(),
        }
    }

    /// Only DNS certificate identifiers carry a wildcard.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        matches!(self, Self::Dns(dns) if dns.is_wildcard())
    }

    /// The DNS identifier, if this is one.
    #[must_use]
    pub const fn as_dns(&self) -> Option<&DnsIdentifier> {
        match self {
            Self::Dns(dns) => Some(dns),
            Self::Ip(_) => None,
        }
    }

    /// The IP identifier, if this is one.
    #[must_use]
    pub const fn as_ip(&self) -> Option<&IpIdentifier> {
        match self {
            Self::Dns(_) => None,
            Self::Ip(ip) => Some(ip),
        }
    }
}

impl TryFrom<String> for Identifier {
    type Error = IdentifierError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<Identifier> for String {
    fn from(value: Identifier) -> Self {
        value.value()
    }
}

impl TryFrom<WireIdentifier> for Identifier {
    type Error = IdentifierError;
    fn try_from(value: WireIdentifier) -> Result<Self, Self::Error> {
        match value.kind.as_str() {
            "dns" => Ok(Self::Dns(DnsIdentifier::new(&value.value)?)),
            "ip" => Ok(Self::Ip(IpIdentifier::new(&value.value)?)),
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
                extensions: std::collections::BTreeMap::new(),
            },
            Identifier::Ip(ip) => Self {
                kind: "ip".into(),
                value: ip.value(),
                extensions: std::collections::BTreeMap::new(),
            },
        }
    }
}

/// Interpret RFC 8555 authorization `identifier` and its sibling `wildcard` flag.
///
/// # Errors
/// Rejects unsupported types and wildcard flags that the identifier kind cannot carry.
pub fn authorization_identifier(
    wire: WireIdentifier,
    wildcard: bool,
) -> Result<Identifier, IdentifierError> {
    let identifier = Identifier::try_from(wire)?;
    match identifier {
        Identifier::Dns(mut dns) => {
            if dns.is_wildcard() {
                return Err(IdentifierError::WildcardAuthorizationValue);
            }
            dns.wildcard = wildcard;
            Ok(Identifier::Dns(dns))
        }
        Identifier::Ip(ip) => {
            if wildcard {
                return Err(IdentifierError::WildcardIpAuthorization);
            }
            Ok(Identifier::Ip(ip))
        }
    }
}
