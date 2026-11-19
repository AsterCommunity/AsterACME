//! Issuance request contracts.
use crate::identifier::Identifier;
use crate::issuance::IssueError;
use serde::{Deserialize, Serialize};

/// Portable application-visible certificate name, independent of DNS wildcard syntax.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CertificateName(String);

impl CertificateName {
    /// Accept DNS-style names or explicit ASCII labels; reject path separators and traversal.
    ///
    /// # Errors
    /// Rejects names unsafe as a single private directory component.
    pub fn new(value: &str) -> Result<Self, IssueError> {
        // Reserve five bytes for the sibling lock file's .lock suffix.
        if value.len() > 250
            || !aster_acme_core::local_name::valid_component(value)
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(IssueError::InvalidInput("invalid certificate name"));
        }
        Ok(Self(value.into()))
    }
    /// Generate an independent management name; truncate only its display prefix,
    /// never the requested identifier. Callers retry typed allocation collisions.
    ///
    /// IP primaries produce an `ip-` label with colons replaced so the name
    /// stays one portable directory component; `2001:db8::1` becomes
    /// `ip-2001-db8--1`. DNS primaries keep the wildcard/`cert-` rules.
    ///
    /// # Errors
    /// Reports OS randomness failure or an unsafe generated component.
    pub fn generated(primary: &Identifier) -> Result<Self, IssueError> {
        let mut random = [0; 4];
        aws_lc_rs::rand::fill(&mut random).map_err(|_| crate::crypto::CryptoError::Randomness)?;
        let source = match primary {
            Identifier::Dns(dns) => {
                let domain = dns.value();
                if let Some(base) = domain.strip_prefix("*.") {
                    format!("wildcard-{base}")
                } else {
                    domain
                }
            }
            Identifier::Ip(ip) => format!("ip-{}", ip.value().replace(':', "-")),
        };
        let source = if aster_acme_core::local_name::valid_component(&source) {
            source
        } else {
            format!("cert-{source}")
        };
        let prefix = source.chars().take(241).collect::<String>();
        Self::new(&format!("{prefix}-{:08x}", u32::from_be_bytes(random)))
    }

    /// Stable user-facing name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CertificateName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for CertificateName {
    type Error = IssueError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<CertificateName> for String {
    fn from(value: CertificateName) -> Self {
        value.0
    }
}

/// A requested complete certificate, before creating the remote order.
#[derive(Clone)]
pub struct IssueRequest {
    /// Required protocol method; independent of a product implementation name.
    pub challenge: crate::challenge::ChallengeKind,
    /// Product-owned publication adapter ID.
    pub solver_id: String,
    /// Non-secret implementation configuration retained unchanged for resume/renew.
    pub solver_config: serde_json::Value,
    /// Defaults to the first normalized identifier in the CLI.
    pub name: CertificateName,
    /// Canonical, duplicate-free DNS and IP identifiers; first is the primary.
    pub identifiers: Vec<Identifier>,
    /// Certificate key choice, independent of the account signing key.
    pub key_algorithm: crate::crypto::key_algorithm::KeyAlgorithm,
    /// CA-advertised certificate profile selected by the operator
    /// (draft-ietf-acme-profiles <https://datatracker.ietf.org/doc/html/draft-ietf-acme-profiles>);
    /// `None`
    /// keeps the CA default. Fixed for the lifetime of this definition.
    pub profile: Option<String>,
    /// Stable local account name, never transmitted to the CA.
    pub account_name: String,
}

impl IssueRequest {
    /// Validate protocol input before storage allocates keys or the client contacts a CA.
    /// Product implementation IDs/configuration stay opaque to the ACME library.
    ///
    /// # Errors
    /// Rejects duplicate/empty identifiers, wildcard requests using non-DNS
    /// methods, and DNS methods combined with IP identifiers ([RFC 8738](https://datatracker.ietf.org/doc/html/rfc8738)).
    pub fn validate(&self) -> Result<(), IssueError> {
        if self.identifiers.is_empty()
            || self.identifiers.len() > 100
            || self
                .identifiers
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != self.identifiers.len()
            || self.solver_id.is_empty()
            || self.solver_id.len() > 128
            || self.solver_id.chars().any(char::is_control)
        {
            return Err(IssueError::InvalidInput(
                "issuance requires unique identifiers and a valid publication implementation",
            ));
        }
        if !self.challenge.supports_wildcards()
            && self.identifiers.iter().any(Identifier::is_wildcard)
        {
            return Err(crate::challenge::ChallengeError::WildcardMethod.into());
        }
        if !self
            .identifiers
            .iter()
            .all(|identifier| self.challenge.validates_identifier(identifier))
        {
            return Err(IssueError::InvalidInput(
                "DNS validation methods cannot validate IP identifiers; RFC 8738 allows HTTP-01 and TLS-ALPN-01 only",
            ));
        }
        if let Some(profile) = &self.profile
            && (profile.is_empty() || profile.len() > 64 || profile.chars().any(char::is_control))
        {
            return Err(IssueError::InvalidInput(
                "certificate profile must be a nonempty name of at most 64 bytes without control characters",
            ));
        }
        Ok(())
    }
}
