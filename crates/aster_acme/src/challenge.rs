//! Challenge selection and validated method-specific response materials.

use aster_acme_protocol::{
    directory::DirectoryMeta,
    order::{ChallengeObject, WireChallengeKind},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::identifier::{DnsIdentifier, IdentifierError};

pub mod dns01;
pub mod dns_persist;
pub mod http01;
pub mod tls_alpn01;

/// Known executable challenge methods; a solver must also be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeKind {
    /// HTTP-01 response.
    #[serde(rename = "http-01")]
    Http01,
    /// DNS-01 TXT response.
    #[serde(rename = "dns-01")]
    Dns01,
    /// Persistent DNS TXT response (draft-ietf-acme-dns-persist-02).
    #[serde(rename = "dns-persist-01")]
    DnsPersist01,
    /// TLS-ALPN-01 response (contract only until a solver is supplied).
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

impl ChallengeKind {
    /// Protocol name used in saved definitions and progress messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dns01 => "DNS-01",
            Self::DnsPersist01 => "DNS-PERSIST-01",
            Self::Http01 => "HTTP-01",
            Self::TlsAlpn01 => "TLS-ALPN-01",
        }
    }

    /// Whether this method can validate wildcard DNS identifiers.
    #[must_use]
    pub fn supports_wildcards(self) -> bool {
        match self {
            Self::Dns01 | Self::DnsPersist01 => true,
            Self::Http01 | Self::TlsAlpn01 => false,
        }
    }
}

/// Whether a publication is withdrawn at an issuance terminal state or retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationLifetime {
    /// Challenge-scoped material eligible for terminal cleanup.
    Temporary,
    /// Long-lived authorization retained for future issuance.
    Persistent,
}

/// Protocol proof required before handing material to a publication solver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicationAccountProof {
    NotRequired,
    ActiveAccount,
}

impl ChallengeKind {
    /// Validate required method metadata before a fresh order is submitted.
    pub(crate) fn validate_directory(self, meta: &DirectoryMeta) -> Result<(), ChallengeError> {
        match self {
            Self::DnsPersist01 => {
                dns_persist::account_uri::validate_prefix(meta)?;
            }
            Self::Dns01 | Self::Http01 | Self::TlsAlpn01 => {}
        }
        Ok(())
    }

    /// Publication lifetime belongs to the protocol method, independently of a solver.
    #[must_use]
    pub const fn publication_lifetime(self) -> PublicationLifetime {
        match self {
            Self::DnsPersist01 => PublicationLifetime::Persistent,
            Self::Dns01 | Self::Http01 | Self::TlsAlpn01 => PublicationLifetime::Temporary,
        }
    }

    pub(crate) const fn publication_account_proof(self) -> PublicationAccountProof {
        match self {
            Self::DnsPersist01 => PublicationAccountProof::ActiveAccount,
            Self::Dns01 | Self::Http01 | Self::TlsAlpn01 => PublicationAccountProof::NotRequired,
        }
    }

    /// Compare method-specific identity while allowing lifecycle fields to advance.
    pub(crate) fn matches_response(
        self,
        expected: &ChallengeObject,
        observed: &ChallengeObject,
    ) -> bool {
        expected.url == observed.url
            && known_method(&expected.kind) == Some(self)
            && known_method(&observed.kind) == Some(self)
            && match self {
                Self::DnsPersist01 => {
                    match (
                        expected.dns_persist_parameters(),
                        observed.dns_persist_parameters(),
                    ) {
                        (Ok(expected), Ok(observed)) => dns_persist::issuer::same_set(
                            &expected.issuer_domain_names,
                            &observed.issuer_domain_names,
                        ),
                        _ => false,
                    }
                }
                Self::Dns01 | Self::Http01 | Self::TlsAlpn01 => {
                    observed.parameters.get("token") == expected.parameters.get("token")
                }
            }
    }
}

/// Explicit method selection, not a retry or fallback-after-failure policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengePolicy {
    /// Only this method may be used.
    Require(ChallengeKind),
    /// Select the first compatible method from a nonempty ordered preference list.
    Prefer(ChallengePreferences),
}

/// Nonempty, duplicate-free preference list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengePreferences(Vec<ChallengeKind>);

/// Invalid policy, challenge input, or lack of a compatible solver.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChallengeError {
    /// Preferences must contain at least one method and no duplicates.
    #[error("challenge preferences must be nonempty and contain no duplicates")]
    InvalidPreferences,
    /// No offered method satisfies the caller policy and local capabilities.
    #[error("no compatible challenge offered by the CA and supported by a local solver")]
    NoCompatibleChallenge,
    /// Token must use the base64url alphabet and be long enough for 128 bits.
    #[error("invalid challenge token")]
    InvalidToken,
    /// RFC 7638 SHA-256 JWK thumbprints must decode to 32 bytes.
    #[error("invalid SHA-256 JWK thumbprint")]
    InvalidThumbprint,
    /// Wildcards require a supported DNS validation method.
    #[error("wildcard identifiers require DNS-01 or DNS-PERSIST-01")]
    WildcardMethod,
    /// The selected persistent challenge or its directory metadata is malformed.
    #[error("invalid dns-persist-01 parameters: {0}")]
    InvalidDnsPersist(&'static str),
    /// Derived DNS record name is invalid.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
}

impl ChallengePreferences {
    /// Construct ordered preferences.
    ///
    /// # Errors
    /// Rejects empty lists and duplicate methods.
    pub fn new(methods: Vec<ChallengeKind>) -> Result<Self, ChallengeError> {
        if methods.is_empty()
            || methods
                .iter()
                .enumerate()
                .any(|(i, m)| methods[..i].contains(m))
        {
            return Err(ChallengeError::InvalidPreferences);
        }
        Ok(Self(methods))
    }

    /// Methods in priority order.
    #[must_use]
    pub fn methods(&self) -> &[ChallengeKind] {
        &self.0
    }
}

impl ChallengePolicy {
    /// Select a method from the intersection of CA offers and local solver capabilities.
    ///
    /// # Errors
    /// Returns an error when no candidate meets the policy and identifier constraints.
    pub fn select(
        &self,
        identifier: &DnsIdentifier,
        offered: &[WireChallengeKind],
        supported: &[ChallengeKind],
    ) -> Result<ChallengeKind, ChallengeError> {
        let candidates = match self {
            Self::Require(kind) => std::slice::from_ref(kind),
            Self::Prefer(preferences) => preferences.methods(),
        };
        candidates
            .iter()
            .copied()
            .find(|kind| {
                (!identifier.is_wildcard() || kind.supports_wildcards())
                    && supported.contains(kind)
                    && offered.iter().any(|wire| known_method(wire) == Some(*kind))
            })
            .ok_or(ChallengeError::NoCompatibleChallenge)
    }
}

/// URL-safe challenge token, validated before using it as an HTTP path segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeToken(String);

impl ChallengeToken {
    /// Validate opaque token syntax and minimum length (entropy cannot be measured).
    ///
    /// # Errors
    /// Rejects non-base64url characters, padding, and tokens shorter than 22 characters.
    /// Tokens are opaque strings, not necessarily canonical base64 encodings.
    pub fn new(value: &str) -> Result<Self, ChallengeError> {
        if value.len() < 22
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(ChallengeError::InvalidToken);
        }
        Ok(Self(value.to_owned()))
    }

    /// Validated token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Token bound to the current account's SHA-256 JWK thumbprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAuthorization(String);

impl KeyAuthorization {
    /// Build the RFC 8555 key authorization.
    ///
    /// # Errors
    /// Rejects thumbprints that are not canonical unpadded base64url SHA-256 values.
    pub fn new(token: &ChallengeToken, jwk_thumbprint: &str) -> Result<Self, ChallengeError> {
        if URL_SAFE_NO_PAD
            .decode(jwk_thumbprint)
            .map_or(true, |bytes| bytes.len() != 32)
        {
            return Err(ChallengeError::InvalidThumbprint);
        }
        Ok(Self(format!("{}.{jwk_thumbprint}", token.as_str())))
    }

    /// SHA-256 binding shared by DNS-01 and TLS-ALPN-01.
    #[must_use]
    pub fn sha256_digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }

    /// Token and thumbprint joined by a dot.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Method-specific response materials. No account private key is passed to a solver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeMaterial {
    /// Temporary DNS TXT publication.
    Dns01(dns01::Dns01Record),
    /// Long-lived DNS authorization, retained across renewal.
    DnsPersist01(dns_persist::DnsPersistRecord),
    /// Exact HTTP token response.
    Http01(http01::Http01Response),
    /// Inputs for a dedicated ALPN validation certificate.
    TlsAlpn01(tls_alpn01::TlsAlpn01Response),
}

impl ChallengeMaterial {
    /// Method represented by this payload.
    #[must_use]
    pub const fn kind(&self) -> ChallengeKind {
        match self {
            Self::Dns01(_) => ChallengeKind::Dns01,
            Self::DnsPersist01(_) => ChallengeKind::DnsPersist01,
            Self::Http01(_) => ChallengeKind::Http01,
            Self::TlsAlpn01(_) => ChallengeKind::TlsAlpn01,
        }
    }
}

/// Map only supported wire methods; extensions are never executed.
pub(crate) fn known_method(kind: &WireChallengeKind) -> Option<ChallengeKind> {
    match kind {
        WireChallengeKind::Http01 => Some(ChallengeKind::Http01),
        WireChallengeKind::Dns01 => Some(ChallengeKind::Dns01),
        WireChallengeKind::DnsPersist01 => Some(ChallengeKind::DnsPersist01),
        WireChallengeKind::TlsAlpn01 => Some(ChallengeKind::TlsAlpn01),
        WireChallengeKind::Unknown(_) => None,
    }
}

#[cfg(test)]
mod tests;
