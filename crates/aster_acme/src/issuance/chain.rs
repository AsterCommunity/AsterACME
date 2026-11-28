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

/// Explicit operator statement about which chain a certificate must use.
/// A definition-level attribute: renewals inherit it from the certificate
/// definition, and it never changes the certificate's own identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ChainPreferenceInput", into = "ChainPreferenceInput")]
pub enum ChainPreference {
    /// Always use the chain the CA returns by default; never ask and never
    /// fetch alternates.
    CaDefault,
    /// Use the candidate whose top-most certificate matches this name
    /// (exact RFC 4514 distinguished name, case-insensitive, with the
    /// common-name component as a fallback).
    Named(ChainName),
}

#[derive(Serialize, Deserialize)]
enum ChainPreferenceInput {
    #[serde(rename = "ca-default")]
    CaDefault,
    #[serde(rename = "named")]
    Named(String),
}

impl From<ChainPreference> for ChainPreferenceInput {
    fn from(preference: ChainPreference) -> Self {
        match preference {
            ChainPreference::CaDefault => Self::CaDefault,
            ChainPreference::Named(name) => Self::Named(name.into_inner()),
        }
    }
}

impl TryFrom<ChainPreferenceInput> for ChainPreference {
    type Error = IssueError;
    fn try_from(input: ChainPreferenceInput) -> Result<Self, IssueError> {
        match input {
            ChainPreferenceInput::CaDefault => Ok(Self::CaDefault),
            ChainPreferenceInput::Named(name) => Ok(Self::Named(ChainName::new(&name)?)),
        }
    }
}

impl From<ChainPreference> for Option<String> {
    fn from(preference: ChainPreference) -> Option<String> {
        match preference {
            ChainPreference::CaDefault => None,
            ChainPreference::Named(name) => Some(name.into_inner()),
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

    fn into_inner(self) -> String {
        self.0
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
        let wanted = name.as_str().trim();
        self.dn.eq_ignore_ascii_case(wanted)
            || self
                .common_name
                .as_deref()
                .is_some_and(|common| common.trim().eq_ignore_ascii_case(wanted))
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
    /// Select the candidate at this zero-based index of the offered list.
    Selected(usize),
    /// Abandon the issuance; the operator decides what happens next.
    Abandon,
}

/// Product-owned interactive selection. Implementations must avoid panics and
/// excessive blocking; libraries without one fall back to the CA default chain.
pub trait ChainSelector: Send + Sync {
    /// Decide among fully validated candidates. `requested` is set only when an
    /// explicit preference could not be matched; implementations that skip
    /// interaction return [`ChainDecision::Abandon`] in that case.
    fn select(&self, requested: Option<&ChainName>, candidates: &[ChainCandidate])
    -> ChainDecision;
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

/// Extract [`Link`](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)
/// `rel="alternate"` certificate URLs from the download response headers.
/// URLs are consumed once per download and never persisted.
///
/// # Errors
/// Fails closed when the response advertises more candidates than the
/// defensive ceiling, a duplicate URL, or the certificate URL itself.
pub fn parse_alternate_links(
    headers: &reqwest::header::HeaderMap,
    certificate_url: &AcmeUrl,
) -> Result<Vec<AcmeUrl>, IssueError> {
    let mut urls = Vec::new();
    for value in headers.get_all(reqwest::header::LINK) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        for field in raw.split(',') {
            let Some(url) = alternate_url(field) else {
                continue;
            };
            let Ok(parsed) = AcmeUrl::new(&url) else {
                // Unparsable or non-HTTPS entries are dropped: a broken hint
                // must not fail a download whose default chain is usable.
                tracing::warn!(url = %url, "ignoring unparsable alternate chain URL");
                continue;
            };
            if parsed == *certificate_url {
                // Relinking the certificate itself would loop the fetch.
                tracing::warn!("ignoring alternate chain URL equal to the certificate URL");
                continue;
            }
            if urls.contains(&parsed) {
                tracing::warn!(url = %parsed.as_str(), "ignoring duplicate alternate chain URL");
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

/// One `,<field>`-split Link header entry: `<url>; rel="alternate"`.
fn alternate_url(field: &str) -> Option<String> {
    let mut parameters = field.split(';');
    let target = parameters.next()?.trim();
    let url = target
        .strip_prefix('<')?
        .strip_suffix('>')?
        .trim()
        .to_owned();
    if url.is_empty() {
        return None;
    }
    // The rel parameter must be exactly the alternate relation; everything else
    // in the header belongs to other mechanisms (for example rel="up").
    parameters
        .any(|parameter| {
            let parameter = parameter.trim();
            let Some((_, relation)) = parameter.split_once('=') else {
                return false;
            };
            let relation = relation.trim().trim_matches('"');
            relation.eq_ignore_ascii_case("alternate")
        })
        .then_some(url)
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

fn attribute_string(attribute: &AttributeTypeAndValue<'_>) -> String {
    // AttributeTypeAndValue::as_str dispatches on the ASN.1 string tag
    // (Printable/UTF8/IA5/Numeric); der_parser's `Any::as_str` does not.
    // Non-string values (rare BMPString subjects) fall back to lossy bytes
    // so the identity still displays instead of collapsing to an empty DN.
    let value = attribute.as_str().map_or_else(
        |_| String::from_utf8_lossy(attribute.attr_value().as_bytes()).into_owned(),
        str::to_owned,
    );
    format!(
        "{}={}",
        attribute_abbreviation(attribute.attr_type().as_bytes()),
        escape_rfc4514_value(&value)
    )
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
    // X.690 base-128 sub-identifiers; the first one packs 40*arc0 + arc1.
    let mut arcs = Vec::new();
    let mut value = 0_u128;
    let mut first = true;
    for byte in bytes.iter().copied() {
        value = (value << 7) | u128::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            if first {
                let (head, tail) = match value {
                    v if v < 40 => (0, v),
                    v if v < 80 => (1, v - 40),
                    v => (2, v - 80),
                };
                arcs.push(head);
                arcs.push(tail);
                first = false;
            } else {
                arcs.push(value);
            }
            value = 0;
        }
    }
    arcs.iter()
        .map(u128::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// RFC 4514 §2.4 value escaping.
fn escape_rfc4514_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for (index, character) in value.chars().enumerate() {
        let leading_special = index == 0 && matches!(character, ' ' | '#');
        let trailing_special = index == value.chars().count() - 1 && character == ' ';
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
    name.iter_common_name()
        .next()
        .and_then(|attribute| attribute.attr_value().as_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests;
