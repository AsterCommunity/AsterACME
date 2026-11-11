//! Persisted issuance contracts. Protocol effects belong to the service, files to adapters.
use crate::{
    account::{AccountRecord, AccountStoreError},
    crypto::AccountSigner,
    identifier::DnsIdentifier,
    solver::ExecutionContext,
};
use aster_acme_core::workflow::{IssuancePhase, SubmissionState};
use aster_acme_protocol::{
    order::{AuthorizationObject, OrderObject},
    url::AcmeUrl,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use thiserror::Error;

pub mod certificate;

pub mod progress;
pub mod service;

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
        if !aster_acme_core::local_name::valid_component(value)
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(IssueError::InvalidInput("invalid certificate name"));
        }
        Ok(Self(value.into()))
    }
    /// Generate an independent management name; truncate only its display prefix,
    /// never the requested DNS identifier. Callers retry typed allocation collisions.
    ///
    /// # Errors
    /// Reports OS randomness failure or an unsafe generated component.
    pub fn generated(primary: &DnsIdentifier) -> Result<Self, IssueError> {
        let mut random = [0; 4];
        aws_lc_rs::rand::fill(&mut random).map_err(|_| crate::crypto::CryptoError::Randomness)?;
        let domain = primary.value();
        let source = if let Some(base) = domain.strip_prefix("*.") {
            format!("wildcard-{base}")
        } else {
            domain
        };
        let source = if aster_acme_core::local_name::valid_component(&source) {
            source
        } else {
            format!("cert-{source}")
        };
        let prefix = source.chars().take(244).collect::<String>();
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
    /// Defaults to the first normalized DNS identifier in the CLI.
    pub name: CertificateName,
    /// Canonical, duplicate-free domains; first is the primary domain.
    pub identifiers: Vec<DnsIdentifier>,
    /// Certificate key choice, independent of the account signing key.
    pub key_algorithm: crate::crypto::key_algorithm::KeyAlgorithm,
    /// Stable local account name, never transmitted to the CA.
    pub account_name: String,
}

/// DNS requirements are grouped for display; multiple values at one owner must coexist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRequirement {
    /// TXT owner including `_acme-challenge`.
    pub name: String,
    /// Exact TXT value, without presentation quotes.
    pub value: String,
}

/// Saved authorization observation and local publication receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRecord {
    /// Exact discovered authorization URL.
    pub url: AcmeUrl,
    /// Most recent authoritative resource.
    pub resource: AuthorizationObject,
    /// Chosen DNS challenge, kept stable across resume.
    pub challenge_url: Option<AcmeUrl>,
    /// Material shown to the user; manual publication is always borrowed.
    pub dns: Option<DnsRequirement>,
    /// Whether the user still needs removal instructions after CA validation ends.
    pub cleanup_pending: bool,
    /// Persisted before acknowledging the CA.
    pub acknowledgement: SubmissionState,
}

/// Immutable predecessor linking a renewal generation to its original `in_use` certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalPredecessor {
    /// Exact previous local generation, not a DNS name or CA order identifier.
    pub operation_id: String,
    /// RFC 9773 identifier, absent when the certificate cannot provide one.
    pub certificate_id: Option<String>,
}

/// A generation and its remote order, with no private keys or provider credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueRecord {
    /// Adapter-provided `in_use` selection snapshot; never persisted in the journal.
    #[serde(skip)]
    pub is_in_use: bool,
    /// Previous `in_use` generation; retained across retries and restart.
    #[serde(default)]
    pub renewal_of: Option<RenewalPredecessor>,
    /// Publication adapter identity, retained so resume never selects a different method.
    pub solver_id: String,
    /// Internal opaque unique ID, selectable explicitly for scripts.
    pub operation_id: String,
    /// Long-lived certificate name.
    pub name: CertificateName,
    /// UTC local request creation time, not the CA's timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    /// Fixed account binding; rename/replacement must not silently retarget recovery.
    pub account_name: String,
    /// Account's stable identity.
    pub account_id: String,
    /// Directory bound at creation.
    pub directory: AcmeUrl,
    /// Original kid; invariant through this generation.
    pub account_url: AcmeUrl,
    /// Thumbprint used to derive the outstanding key authorizations.
    pub account_thumbprint: String,
    /// Immutable certificate key choice used by this generation.
    pub key_algorithm: crate::crypto::key_algorithm::KeyAlgorithm,
    /// Ordered canonical DNS identifiers.
    pub identifiers: Vec<DnsIdentifier>,
    /// Local execution stage, independent of order status.
    pub phase: IssuancePhase,
    /// Saved before newOrder; missing URL afterwards is an uncertain creation.
    pub creation_submitted: bool,
    /// Actual RFC 9773 replaces value selected before newOrder; a refreshed directory
    /// cannot change the submitted request identity during recovery.
    #[serde(default)]
    pub submitted_replaces: Option<String>,
    /// Exact Location returned by newOrder.
    pub order_url: Option<AcmeUrl>,
    /// Most recent CA snapshot.
    pub order: Option<OrderObject>,
    /// Authorizations and publication checkpoints.
    pub authorizations: Vec<AuthorizationRecord>,
    /// Saved before finalize; the same CSR is never regenerated or silently replaced.
    pub finalize_submitted: SubmissionState,
    /// Explicit CA rejection of this fixed CSR. Later changes to a reused order
    /// cannot turn this generation into a different certificate/key identity.
    #[serde(default)]
    pub finalize_rejection: Option<aster_acme_protocol::problem::Problem>,
    /// Earliest next query, respecting CA Retry-After across process restart.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub next_poll_at: Option<time::OffsetDateTime>,
    /// Certificate revocation is independent of issuance completion.
    #[serde(default)]
    pub revocation: crate::revocation::RevocationRecord,
    /// Durable renewal schedule, available only after certificate validation.
    #[serde(default)]
    pub renewal: Option<crate::renewal::RenewalPlan>,
    /// Leaf certificate expiry, distinct from order and authorization expiry.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub certificate_not_after: Option<time::OffsetDateTime>,
}
impl IssueRecord {
    /// Human-readable immutable directory name: UTC request time plus random ID prefix.
    #[must_use]
    pub fn generation_name(&self) -> String {
        let at = self.created_at.to_offset(time::UtcOffset::UTC);
        let suffix = self.operation_id.chars().take(8).collect::<String>();
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z-{suffix}",
            at.year(),
            u8::from(at.month()),
            at.day(),
            at.hour(),
            at.minute(),
            at.second()
        )
    }

    /// Pending operations can be selected for recovery; expiry is reported separately.
    #[must_use]
    pub fn unfinished(&self) -> bool {
        !matches!(self.phase, IssuancePhase::Completed)
    }
    /// Local observation of expiry; a valid issued order can still be downloaded.
    #[must_use]
    pub fn expired(&self, now: time::OffsetDateTime) -> bool {
        self.order.as_ref().is_some_and(|order| {
            !matches!(order.status, aster_acme_core::protocol::OrderStatus::Valid)
                && order.expires.is_some_and(|expires| expires <= now)
        })
    }
}

/// Readiness is an adapter: implementations may query DNS or ask the caller for publication.
/// The service owns CA notification and never accesses a terminal itself.
#[async_trait]
pub trait DnsReadiness: Send + Sync {
    /// All required values must coexist, including wildcard/base-domain authorization pairs.
    /// Return false to yield `action_required`; `skip_dns_check` bypasses only local DNS lookup.
    ///
    /// # Errors
    /// Reports cancellation, deadline and sanitized resolver/adapter failures.
    async fn ready(
        &self,
        records: &[DnsRequirement],
        skip_dns_check: bool,
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError>;
}

/// Locked recoverable generation. Blocking persistence must retain its lease on cancellation.
#[async_trait]
pub trait IssueSession: Send + Sync {
    /// Latest durable snapshot under the generation/certificate lease, including prior calls.
    ///
    /// # Errors
    /// Reports journal, identity and pending persistence failures.
    async fn record(&self) -> Result<IssueRecord, IssueError>;
    /// Persist the next checkpoint before performing an external mutation.
    ///
    /// # Errors
    /// Reports identity, journal and durability failures.
    async fn save(&self, record: &IssueRecord) -> Result<(), IssueError>;
    /// Load the fixed DER CSR; never generate a replacement on read failure.
    ///
    /// # Errors
    /// Missing, unsafe or corrupt CSR is an error.
    async fn csr(&self) -> Result<Vec<u8>, IssueError>;
    /// Read the issued leaf as DER; no private key is exposed to revocation orchestration.
    ///
    /// # Errors
    /// Rejects missing, corrupt or unsafe certificate artifacts.
    async fn certificate_der(&self) -> Result<Vec<u8>, IssueError>;
    /// Persist a validated chain then atomically select this generation. Populate the
    /// returned record's `renewal` with `RenewalPlan::from_certificate` before promotion
    /// so every adapter durably establishes a fallback independently of ARI availability.
    ///
    /// # Errors
    /// Failure must retain the previous `in_use` generation and recoverable checkpoint.
    async fn complete(&self, record: &IssueRecord, chain: &[u8])
    -> Result<IssueRecord, IssueError>;
}

/// Object-safe generation storage contract for files, databases and embedded services.
#[async_trait]
pub trait IssueStore: Send + Sync {
    /// Create a new managed certificate and its first fixed key/CSR generation.
    /// Existing managed names are rejected atomically; this never appends a version.
    ///
    /// # Errors
    /// Rejects unsafe names, storage errors and incomplete local initialization.
    async fn create(
        &self,
        request: &IssueRequest,
        account: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError>;
    /// Prepare another generation using the existing certificate's immutable definition.
    /// This is storage groundwork for renewal, not a CA request or a scheduler.
    ///
    /// # Errors
    /// Rejects missing definitions, changed account bindings and persistence failures.
    async fn renew(
        &self,
        name: &CertificateName,
        account: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError>;
    /// Open one exact generation and acquire an exclusive execution lease.
    ///
    /// # Errors
    /// Rejects missing, mismatched, unsafe or contended generations.
    async fn open(
        &self,
        name: &CertificateName,
        operation_id: &str,
    ) -> Result<Box<dyn IssueSession>, IssueError>;
    /// Enumerate local snapshots only; never load private keys or contact a CA.
    ///
    /// # Errors
    /// Rejects unsafe, oversized or corrupt journals.
    async fn list(&self) -> Result<Vec<IssueRecord>, IssueError>;
}

/// Protocol/service failures without private key material.
#[derive(Debug, Error)]
pub enum IssueError {
    /// Input invariant or CA resource mismatch.
    #[error("{0}")]
    InvalidInput(&'static str),
    /// A managed certificate already owns this name; only automatic names may be retried.
    #[error("a managed certificate named '{0}' already exists")]
    NameAlreadyExists(CertificateName),
    /// Remote order creation may already have happened; never create another automatically.
    #[error(
        "order creation outcome is uncertain; no saved Location URL is available; inspect this operation before creating a new request"
    )]
    CreationUncertain,
    /// The saved mutation cannot safely be repeated.
    #[error(
        "{0}; query again later or consult the CA; this operation will not be replayed automatically"
    )]
    MutationUncertain(&'static str),
    /// A revocation request may have taken effect; explicit retry retains certificate/reason.
    #[error("certificate revocation outcome is unconfirmed: {0}")]
    RevocationUncertain(#[source] crate::transport::TransportError),
    /// Order/authorization expiry prevents further validation/finalization.
    #[error("the order or required authorization has expired; start a new issuance explicitly")]
    Expired,
    /// Execution deadline or cancellation; checkpoint remains available.
    #[error("issuance interrupted or execution deadline exceeded; resume the saved certificate")]
    Interrupted,
    /// Typed transport error.
    #[error(transparent)]
    Transport(#[from] crate::transport::TransportError),
    /// Storage failure.
    #[error(transparent)]
    Store(#[from] AccountStoreError),
    /// Invalid identifier.
    #[error(transparent)]
    Identifier(#[from] crate::identifier::IdentifierError),
    /// State-machine refusal.
    #[error(transparent)]
    State(#[from] aster_acme_core::machine::StateError),
    /// Material derivation failure.
    #[error(transparent)]
    Challenge(#[from] crate::challenge::ChallengeError),
    /// Key/signature failure.
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
}

/// One invocation's controls; deadlines are monotonic and never persisted as Instants.
pub struct IssueExecution {
    /// Cancellation and overall execution budget.
    pub context: ExecutionContext,
    /// Bypass only local DNS visibility checks, never CA validation or expiry.
    pub skip_dns_check: bool,
    /// Default polling delay when the CA omits Retry-After.
    pub poll_interval: Duration,
}

/// A foreground invocation can finish or yield durable manual action without an error.
/// The owned snapshot is boxed to avoid inlining the full journal into each async result.
pub enum IssueOutcome {
    /// User must publish these TXT records then resume the named certificate.
    ActionRequired {
        record: Box<IssueRecord>,
        records: Vec<DnsRequirement>,
    },
    /// Persisted certificate and independent manual cleanup instructions.
    Completed {
        record: Box<IssueRecord>,
        cleanup: Vec<DnsRequirement>,
    },
}

/// An account binding used by a service invocation, verified against the saved generation.
pub struct IssueIdentity {
    /// Account's latest persisted registration metadata.
    pub account: AccountRecord,
    /// Signing boundary; may be backed by an HSM or remote service.
    pub signer: Arc<dyn AccountSigner>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_management_names_keep_a_bounded_prefix_and_lowercase_random_suffix() {
        let long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        for value in ["example.com", "*.example.com", long.as_str()] {
            let domain = DnsIdentifier::new(value).unwrap();
            let name = CertificateName::generated(&domain).unwrap();
            let (prefix, suffix) = name.as_str().rsplit_once('-').unwrap();
            assert_eq!(suffix.len(), 8);
            assert!(
                suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            let expected = if let Some(base) = value.strip_prefix("*.") {
                format!("wildcard-{base}")
            } else {
                value.to_owned()
            };
            assert!(expected.starts_with(prefix));
            assert!(name.as_str().len() <= 253);
            assert_eq!(domain.value(), value);
        }
    }
}
