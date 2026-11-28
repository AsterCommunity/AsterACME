//! [RFC 8555 §7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)
//! alternate certificate chains: typed identities, preference matching, candidate
//! discovery and the product-owned selection contract.
//!
//! Candidate chains are only discoverable from the certificate download response
//! (`Link; rel="alternate"`); the ACME directory metadata never advertises them.

use crate::issuance::IssueError;
use aster_acme_protocol::url::AcmeUrl;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use x509_parser::{
    pem::parse_x509_pem,
    prelude::FromDer as _,
    x509::{AttributeTypeAndValue, X509Name},
};

/// Defensive ceiling on alternate chains fetched per download; every entry must be
/// server-provided, absolute and unique, so this bound only trips on hostile or
/// broken CA responses.
const MAX_ALTERNATE_CHAINS: usize = 8;

/// Chain-selection intent stored in an issuance journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChainSelection {
    /// Use the CA default chain for this operation.
    Default,
    /// Use a named chain and optionally retain it as a soft preference.
    Named {
        /// Requested chain-top identity.
        chain: ChainName,
        /// Retain this name for future renewals.
        remember: bool,
    },
}

impl ChainSelection {
    /// Return the requested chain name for a concrete selection.
    #[must_use]
    pub fn named(&self) -> Option<&ChainName> {
        match self {
            Self::Default => None,
            Self::Named { chain, .. } => Some(chain),
        }
    }

    /// Return the name to persist in the certificate definition.
    #[must_use]
    pub fn persisted(&self) -> Option<ChainName> {
        match self {
            Self::Named {
                chain,
                remember: true,
            } => Some(chain.clone()),
            Self::Default
            | Self::Named {
                remember: false, ..
            } => None,
        }
    }
}

/// A validated chain-top name an operator can pass verbatim: the RFC 4514
/// serialization of the top-most certificate's subject distinguished name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ChainName(String);

impl ChainName {
    /// Accept any nonempty printable name without control characters; the value
    /// is matched against derived candidate identities, never against paths.
    ///
    /// # Errors
    /// Rejects empty names, control characters and oversized input.
    pub fn new(value: &str) -> Result<Self, IssueError> {
        if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(IssueError::InvalidInput(
                "a preferred chain is a nonempty distinguished or common name without control characters",
            ));
        }
        Ok(Self(value.into()))
    }

    /// Stable user-facing name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ChainName {
    type Error = IssueError;
    fn try_from(value: String) -> Result<Self, IssueError> {
        Self::new(&value)
    }
}

impl From<ChainName> for String {
    fn from(name: ChainName) -> String {
        name.0
    }
}

/// Operator-visible identity of one validated candidate chain. Derived from the
/// top-most certificate; CAs never name chains, so clients must.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainIdentity {
    /// RFC 4514 distinguished name of the top-most certificate's subject,
    /// ASN.1 RDN order reversed per RFC 4514 §2.1.
    pub dn: String,
    /// The top-most certificate's common-name attribute value, when present.
    pub common_name: Option<String>,
    /// Lowercase hex SHA-256 of the top-most certificate DER.
    pub fingerprint_sha256: String,
}

impl ChainIdentity {
    /// Case-insensitive RFC 4514 distinguished-name equality, with the
    /// top-most common-name component as a fallback for operator convenience.
    #[must_use]
    pub fn matches(&self, name: &ChainName) -> bool {
        let wanted = name.as_str();
        self.dn.to_lowercase() == wanted.to_lowercase()
            || self
                .common_name
                .as_deref()
                .is_some_and(|common| common.trim().to_lowercase() == wanted.trim().to_lowercase())
    }
}

/// One validated candidate chain offered to the selector. Index 0 of a
/// candidate list is always the CA default chain.
#[derive(Debug, Clone)]
pub struct ChainCandidate {
    /// The chain the CA returned in the download response body.
    pub is_default: bool,
    /// Derived from the validated chain's top-most certificate.
    pub identity: ChainIdentity,
}

/// Product decision after candidate inspection. The issuance checkpoint stays
/// resumable regardless of the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainDecision {
    /// Keep the CA default chain.
    DefaultChain,
    /// Select a candidate and optionally retain its name as a soft preference.
    Selected {
        /// Candidate index in the offered list.
        index: usize,
        /// Whether this selection is a long-term soft preference.
        remember: bool,
    },
    /// Abandon the issuance; the operator decides what happens next.
    Abandon,
}

/// Product-owned interactive selection. Implementations must avoid panics and
/// excessive blocking; libraries without one fall back to the CA default chain.
pub trait ChainSelector: Send + Sync {
    /// Decide among fully validated candidates. `requested` is set only when an
    /// explicit preference could not be matched; implementations that skip
    /// interaction return [`ChainDecision::Abandon`] in that case.
    ///
    /// # Errors
    /// Propagate terminal or execution failures without selecting a chain. The
    /// selector must observe the context while waiting for input.
    fn select(
        &self,
        requested: Option<&ChainName>,
        candidates: &[ChainCandidate],
        execution: &crate::solver::ExecutionContext,
    ) -> Result<ChainDecision, IssueError>;
}

/// Derive a candidate identity from a complete PEM certificate chain. Callers
/// must validate the chain first. The identity describes the **top-most**
/// certificate (the last PEM block, closest to the trust anchor): every
/// candidate chain shares the same leaf, so only the issuer tail
/// distinguishes alternatives — this is also what operator-supplied
/// `--preferred-chain` names refer to.
///
/// # Errors
/// Rejects empty, non-certificate or malformed PEM data.
pub fn chain_identity(chain: &[u8]) -> Result<ChainIdentity, IssueError> {
    let invalid = || IssueError::InvalidInput("invalid certificate chain PEM");
    let mut tail_der = None;
    let mut remaining = chain;
    while remaining.iter().any(|byte| !u8::is_ascii_whitespace(byte)) {
        let (rest, pem) = parse_x509_pem(remaining).map_err(|_| invalid())?;
        if pem.label != "CERTIFICATE" {
            return Err(invalid());
        }
        x509_parser::certificate::X509Certificate::from_der(&pem.contents)
            .map_err(|_| invalid())
            .and_then(|(rest, _)| {
                if rest.is_empty() {
                    Ok(())
                } else {
                    Err(invalid())
                }
            })?;
        tail_der = Some(pem.contents);
        remaining = rest;
    }
    let tail_der = tail_der.ok_or_else(invalid)?;
    let (_, certificate) =
        x509_parser::certificate::X509Certificate::from_der(&tail_der).map_err(|_| invalid())?;
    let fingerprint = Sha256::digest(&tail_der);
    let mut hex = String::with_capacity(fingerprint.len() * 2);
    for byte in fingerprint {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(ChainIdentity {
        dn: rfc4514(certificate.subject()),
        common_name: common_name(certificate.subject()),
        fingerprint_sha256: hex,
    })
}

pub(crate) fn leaf_der(chain: &[u8]) -> Result<Vec<u8>, IssueError> {
    let (_, leaf) = parse_x509_pem(chain)
        .map_err(|_| IssueError::InvalidInput("invalid certificate chain PEM"))?;
    Ok(leaf.contents)
}

/// Extract [`Link`](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)
/// `rel="alternate"` certificate URLs from the download response headers.
/// URLs are consumed once per download and never persisted.
///
/// # Errors
/// Fails closed above the defensive ceiling of distinct usable URLs.
/// Malformed, duplicate, and self-referencing links are ignored.
pub fn parse_alternate_links(
    headers: &reqwest::header::HeaderMap,
    certificate_url: &AcmeUrl,
) -> Result<Vec<AcmeUrl>, IssueError> {
    let mut urls = Vec::new();
    for value in headers.get_all(reqwest::header::LINK) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        for field in split_link(raw, ',') {
            let Some(url) = alternate_url(field) else {
                continue;
            };
            let parsed = match url::Url::parse(url) {
                Ok(_) => AcmeUrl::new(url),
                Err(url::ParseError::RelativeUrlWithoutBase) => {
                    let Ok(base) = url::Url::parse(certificate_url.as_str()) else {
                        continue;
                    };
                    let Ok(resolved) = base.join(url) else {
                        continue;
                    };
                    AcmeUrl::new(resolved.as_str())
                }
                Err(_) => {
                    tracing::warn!("ignoring unparsable alternate chain URL");
                    Err(aster_acme_protocol::url::InvalidAcmeUrl)
                }
            };
            let Ok(parsed) = parsed else {
                // Unparsable or non-HTTPS entries are dropped: a broken hint
                // must not fail a download whose default chain is usable.
                tracing::warn!("ignoring unparsable alternate chain URL");
                continue;
            };
            if parsed == *certificate_url {
                // Relinking the certificate itself would loop the fetch.
                tracing::warn!("ignoring alternate chain URL equal to the certificate URL");
                continue;
            }
            if urls.contains(&parsed) {
                tracing::warn!("ignoring duplicate alternate chain URL");
                continue;
            }
            urls.push(parsed);
            if urls.len() > MAX_ALTERNATE_CHAINS {
                return Err(IssueError::InvalidInput(
                    "CA advertised an implausible number of alternate certificate chains",
                ));
            }
        }
    }
    Ok(urls)
}

// RFC 8288: delimiters inside <targets> and quoted parameters are data.
fn split_link(mut remaining: &str, separator: char) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        if remaining.is_empty() {
            return None;
        }
        let mut target = false;
        let mut quoted = false;
        let mut escaped = false;
        for (index, ch) in remaining.char_indices() {
            if target {
                target = ch != '>';
            } else if escaped {
                escaped = false;
            } else if quoted {
                match ch {
                    '\\' => escaped = true,
                    '"' => quoted = false,
                    _ => {}
                }
            } else if ch == separator {
                let (field, tail) = remaining.split_at(index);
                remaining = &tail[separator.len_utf8()..];
                return Some(field);
            } else {
                target = ch == '<';
                quoted = ch == '"';
            }
        }
        let field = std::mem::take(&mut remaining);
        (!target && !quoted).then_some(field)
    })
}

fn alternate_url(field: &str) -> Option<&str> {
    let mut parameters = split_link(field, ';');
    let url = parameters
        .next()?
        .trim()
        .strip_prefix('<')?
        .strip_suffix('>')?;
    let mut relation: Option<String> = None;
    for parameter in parameters {
        let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        let name = name.trim();
        // This client does not process a context override. RFC 8288 §3.2
        // requires ignoring the entire link if anchor is unsupported.
        if name.eq_ignore_ascii_case("anchor") {
            return None;
        }
        if name.eq_ignore_ascii_case("rel") && relation.is_none() {
            let value = value.trim();
            relation = Some(
                value
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .map_or_else(|| value.to_owned(), decode_quoted_pair),
            );
        }
    }
    relation?
        .split_ascii_whitespace()
        .any(|value| value.eq_ignore_ascii_case("alternate"))
        .then_some(url)
}

fn decode_quoted_pair(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character == '\\' {
            if let Some(escaped) = chars.next() {
                decoded.push(escaped);
            } else {
                decoded.push(character);
            }
        } else {
            decoded.push(character);
        }
    }
    decoded
}

/// RFC 4514 serialization of a subject/issuer name: reversed RDN sequence,
/// `+`-joined multi-valued RDNs, standard type abbreviations and §2.4 escaping.
fn rfc4514(name: &X509Name<'_>) -> String {
    name.iter_rdn()
        .collect::<Vec<_>>()
        .iter()
        .rev()
        .map(|rdn| {
            rdn.iter()
                .map(attribute_string)
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn attribute_text(attribute: &AttributeTypeAndValue<'_>) -> Option<String> {
    attribute.as_str().ok().map(str::to_owned).or_else(|| {
        attribute
            .attr_value()
            .as_bmpstring()
            .ok()
            .map(|value| value.string())
    })
}

fn attribute_string(attribute: &AttributeTypeAndValue<'_>) -> String {
    use x509_parser::asn1_rs::ToDer as _;
    let kind = attribute_abbreviation(attribute.attr_type().as_bytes());
    if !kind.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && let Some(value) = attribute_text(attribute)
    {
        return format!("{kind}={}", escape_rfc4514_value(&value));
    }
    // Preserve the complete ASN.1 encoding for values without a text form.
    let mut result = format!("{kind}=#");
    if let Ok(encoded) = attribute.attr_value().to_der_vec() {
        use std::fmt::Write as _;
        for byte in encoded {
            let _ = write!(result, "{byte:02X}");
        }
    }
    result
}

/// RFC 4514 §2.3 type abbreviations for the widely deployed attributes;
/// anything else serializes as its dotted OID form.
fn attribute_abbreviation(oid: &[u8]) -> String {
    match oid {
        [0x55, 0x04, 0x03] => "CN".into(),
        [0x55, 0x04, 0x04] => "SN".into(),
        [0x55, 0x04, 0x05] => "serialNumber".into(),
        [0x55, 0x04, 0x06] => "C".into(),
        [0x55, 0x04, 0x07] => "L".into(),
        [0x55, 0x04, 0x08] => "ST".into(),
        [0x55, 0x04, 0x09] => "street".into(),
        [0x55, 0x04, 0x0a] => "O".into(),
        [0x55, 0x04, 0x0b] => "OU".into(),
        [0x55, 0x04, 0x2a] => "GN".into(),
        other => dotted_oid(other),
    }
}

fn dotted_oid(bytes: &[u8]) -> String {
    // Keep each base-128 subidentifier as decimal digits, so unusual OIDs with
    // arcs larger than machine integers are still serialized without loss.
    let mut arcs = Vec::new();
    let mut value = vec![0_u8];
    let mut first = true;
    for byte in bytes.iter().copied() {
        let mut carry = u16::from(byte & 0x7f);
        for digit in &mut value {
            let next = u16::from(*digit) * 128 + carry;
            *digit = u8::try_from(next % 10).unwrap_or(0);
            carry = next / 10;
        }
        while carry > 0 {
            value.push(u8::try_from(carry % 10).unwrap_or(0));
            carry /= 10;
        }
        if byte & 0x80 == 0 {
            let decimal = value.iter().rev().map(u8::to_string).collect::<String>();
            if first {
                let (head, tail) = split_first_oid_arc(&decimal);
                arcs.push(head);
                arcs.push(tail);
                first = false;
            } else {
                arcs.push(decimal);
            }
            value = vec![0];
        }
    }
    arcs.join(".")
}

fn split_first_oid_arc(value: &str) -> (String, String) {
    let mut digits = value.bytes().map(|digit| digit - b'0').collect::<Vec<_>>();
    let (head, subtract) = if decimal_less_than(value, "40") {
        ("0", 0)
    } else if decimal_less_than(value, "80") {
        ("1", 40)
    } else {
        ("2", 80)
    };
    let mut borrow = subtract;
    for digit in digits.iter_mut().rev() {
        let amount = borrow % 10;
        borrow /= 10;
        if *digit >= amount {
            *digit -= amount;
        } else {
            *digit = *digit + 10 - amount;
            borrow += 1;
        }
    }
    while digits.len() > 1 && digits[0] == 0 {
        digits.remove(0);
    }
    (head.into(), digits.iter().map(u8::to_string).collect())
}

fn decimal_less_than(value: &str, limit: &str) -> bool {
    value.len() < limit.len() || (value.len() == limit.len() && value < limit)
}

/// RFC 4514 §2.4 value escaping.
fn escape_rfc4514_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for (index, character) in value.char_indices() {
        let leading_special = index == 0 && matches!(character, ' ' | '#');
        let trailing_special = character == ' ' && index + 1 == value.len();
        if leading_special
            || trailing_special
            || matches!(character, '"' | '+' | ',' | ';' | '<' | '>' | '\\' | '=')
        {
            escaped.push('\\');
            escaped.push(character);
        } else if character.is_ascii_graphic() || character == ' ' {
            escaped.push(character);
        } else {
            use std::fmt::Write as _;
            for byte in character.encode_utf8(&mut [0; 4]).as_bytes() {
                let _ = write!(escaped, "\\{byte:02X}");
            }
        }
    }
    escaped
}

fn common_name(name: &X509Name<'_>) -> Option<String> {
    name.iter_common_name().next().and_then(attribute_text)
}

#[cfg(test)]
mod tests;
