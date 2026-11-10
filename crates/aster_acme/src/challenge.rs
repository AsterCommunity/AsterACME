//! Challenge selection and validated method-specific response materials.

use aster_acme_protocol::order::WireChallengeKind;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::identifier::{DnsIdentifier, DnsName, IdentifierError};
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
    /// TLS-ALPN-01 response (contract only until a solver is supplied).
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

impl ChallengeKind {
    /// Whether this method can validate wildcard DNS identifiers.
    #[must_use]
    pub fn supports_wildcards(self) -> bool {
        match self {
            Self::Dns01 => true,
            Self::Http01 | Self::TlsAlpn01 => false,
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
    /// Wildcards only support DNS-01 among the methods defined here.
    #[error("wildcard identifiers require DNS-01")]
    WildcardMethod,
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

    /// Token and thumbprint joined by a dot.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Method-specific response materials. No account private key is passed to a solver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeMaterial {
    /// Publish the expected TXT value at this owner name.
    Dns01 {
        /// Owner name (including `_acme-challenge`).
        record_name: DnsName,
        /// Base64url-encoded SHA-256 key authorization digest.
        txt_value: String,
    },
    /// Publish an exact token response for this hostname.
    Http01 {
        /// Non-wildcard certificate identifier.
        identifier: DnsIdentifier,
        /// Validated path segment.
        token: ChallengeToken,
        /// Response body.
        key_authorization: KeyAuthorization,
    },
    /// Present an ALPN validation certificate for this hostname.
    TlsAlpn01 {
        /// Non-wildcard certificate identifier.
        identifier: DnsIdentifier,
        /// Digest for the critical acmeIdentifier extension.
        authorization_digest: [u8; 32],
    },
}

impl ChallengeMaterial {
    /// Derive material from a CA token and the active account's JWK thumbprint.
    ///
    /// # Errors
    /// Rejects invalid thumbprints, unsupported wildcard methods, and oversized TXT owners.
    pub fn derive(
        kind: ChallengeKind,
        identifier: &DnsIdentifier,
        token: &ChallengeToken,
        jwk_thumbprint: &str,
    ) -> Result<Self, ChallengeError> {
        if identifier.is_wildcard() && !kind.supports_wildcards() {
            return Err(ChallengeError::WildcardMethod);
        }
        let key_authorization = KeyAuthorization::new(token, jwk_thumbprint)?;
        let digest: [u8; 32] = Sha256::digest(key_authorization.as_str().as_bytes()).into();
        Ok(match kind {
            ChallengeKind::Dns01 => Self::Dns01 {
                record_name: DnsName::new(&format!(
                    "_acme-challenge.{}",
                    identifier.name().as_str()
                ))?,
                txt_value: URL_SAFE_NO_PAD.encode(digest),
            },
            ChallengeKind::Http01 => Self::Http01 {
                identifier: identifier.clone(),
                token: token.clone(),
                key_authorization,
            },
            ChallengeKind::TlsAlpn01 => Self::TlsAlpn01 {
                identifier: identifier.clone(),
                authorization_digest: digest,
            },
        })
    }

    /// Method represented by this payload.
    #[must_use]
    pub fn kind(&self) -> ChallengeKind {
        match self {
            Self::Dns01 { .. } => ChallengeKind::Dns01,
            Self::Http01 { .. } => ChallengeKind::Http01,
            Self::TlsAlpn01 { .. } => ChallengeKind::TlsAlpn01,
        }
    }
}

/// Map only supported wire methods; extensions are never executed.
pub(crate) fn known_method(kind: &WireChallengeKind) -> Option<ChallengeKind> {
    match kind {
        WireChallengeKind::Http01 => Some(ChallengeKind::Http01),
        WireChallengeKind::Dns01 => Some(ChallengeKind::Dns01),
        WireChallengeKind::TlsAlpn01 => Some(ChallengeKind::TlsAlpn01),
        WireChallengeKind::Unknown(_) => None,
    }
}
