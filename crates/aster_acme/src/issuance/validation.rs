//! Issuance validation contracts.
use aster_acme_core::workflow::SubmissionState;
use aster_acme_protocol::{order::AuthorizationObject, url::AcmeUrl};
use serde::{Deserialize, Serialize};

/// Durable public validation instructions, independent of publication implementation.
/// A method enum belongs to ACME; CLI implementations decide how to publish it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum ValidationRequirement {
    /// Long-lived authorization; never returned as temporary cleanup instructions.
    #[serde(rename = "dns-persist-01")]
    DnsPersist01 {
        /// Exact persistent TXT publication, independent of a challenge token.
        #[serde(flatten)]
        record: crate::challenge::dns_persist::DnsPersistRecord,
    },
    /// All TXT values at a shared owner must coexist.
    #[serde(rename = "dns-01")]
    Dns01 {
        /// TXT owner including `_acme-challenge`.
        name: String,
        /// Exact TXT value without presentation quotes.
        value: String,
    },
    /// Serve the exact key authorization at the HTTP-01 URL on public port 80.
    #[serde(rename = "http-01")]
    Http01 {
        /// Public URL constructed from the requested identifier, never a CA URL.
        url: String,
        /// Absolute HTTP request path, also the relative path below webroot.
        path: String,
        /// Unhashed key authorization; no account private key is exposed.
        content: String,
    },
    /// TLS-ALPN material is defined even when the product has no executable solver.
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01 {
        /// Exact non-wildcard identifier for SNI/SAN selection.
        identifier: String,
        /// SHA-256 key authorization digest for the critical acmeIdentifier extension.
        digest: [u8; 32],
    },
}

impl ValidationRequirement {
    /// Method used by this material.
    #[must_use]
    pub const fn kind(&self) -> crate::challenge::ChallengeKind {
        use crate::challenge::ChallengeKind;
        match self {
            Self::Dns01 { .. } => ChallengeKind::Dns01,
            Self::DnsPersist01 { .. } => ChallengeKind::DnsPersist01,
            Self::Http01 { .. } => ChallengeKind::Http01,
            Self::TlsAlpn01 { .. } => ChallengeKind::TlsAlpn01,
        }
    }

    pub(crate) fn same_publication_scope(&self, other: &Self) -> bool {
        match self {
            Self::DnsPersist01 { record } => match other {
                Self::DnsPersist01 { record: other } => record.same_scope(other),
                Self::Dns01 { .. } | Self::Http01 { .. } | Self::TlsAlpn01 { .. } => false,
            },
            Self::Dns01 { .. } | Self::Http01 { .. } | Self::TlsAlpn01 { .. } => false,
        }
    }

    pub(super) fn from_material(material: crate::challenge::ChallengeMaterial) -> Self {
        use crate::challenge::ChallengeMaterial;
        match material {
            ChallengeMaterial::DnsPersist01(record) => Self::DnsPersist01 { record },
            ChallengeMaterial::Dns01(record) => Self::Dns01 {
                name: record.record_name.as_str().into(),
                value: record.txt_value,
            },
            ChallengeMaterial::Http01(response) => {
                let path = format!("/.well-known/acme-challenge/{}", response.token.as_str());
                Self::Http01 {
                    url: format!("http://{}{path}", response.host()),
                    path,
                    content: response.key_authorization.as_str().into(),
                }
            }
            ChallengeMaterial::TlsAlpn01(response) => Self::TlsAlpn01 {
                identifier: response.identifier.value(),
                digest: response.authorization_digest,
            },
        }
    }
}

/// Saved authorization observation and local publication receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRecord {
    /// Exact discovered authorization URL.
    pub url: AcmeUrl,
    /// Most recent authoritative resource.
    pub resource: AuthorizationObject,
    /// Chosen challenge, kept stable across resume.
    pub challenge_url: Option<AcmeUrl>,
    /// Persisted public material; publication must not change on recovery.
    pub validation_requirement: Option<ValidationRequirement>,
    /// Stable idempotency identity saved before invoking a publication solver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_id: Option<String>,
    /// Exact provider receipt; never contains credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_receipt: Option<aster_acme_dns::PublicationReceipt>,
    /// Exact DNS route saved before any provider mutation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_plan: Option<aster_acme_dns::DnsRecord>,
    /// Provider retry lower bound, preserved through process restart.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub publication_retry_at: Option<time::OffsetDateTime>,
    /// Whether publication cleanup is still pending after CA validation ends.
    pub cleanup_pending: bool,
    /// Persisted before acknowledging the CA.
    pub acknowledgement: SubmissionState,
}
