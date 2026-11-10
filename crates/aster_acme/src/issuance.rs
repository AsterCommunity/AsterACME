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

/// Stable application-visible certificate name; primary wildcard names remain distinct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CertificateName(String);
impl CertificateName {
    /// Accept DNS-style names or explicit ASCII labels; reject path separators and traversal.
    ///
    /// # Errors
    /// Rejects names unsafe as a single private directory component.
    pub fn new(value: &str) -> Result<Self, IssueError> {
        if value.is_empty()
            || value.len() > 253
            || value == "."
            || value == ".."
            || !value.bytes().all(|c| {
                c.is_ascii_lowercase()
                    || c.is_ascii_digit()
                    || matches!(c, b'.' | b'-' | b'_' | b'*')
            })
            || (value.contains('*') && (!value.starts_with("*.") || value[2..].contains('*')))
        {
            return Err(IssueError::InvalidInput("invalid certificate name"));
        }
        Ok(Self(value.into()))
    }
    /// Stable user-facing name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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

/// A generation and its remote order, with no private keys or provider credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueRecord {
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
    /// Ordered canonical DNS identifiers.
    pub identifiers: Vec<DnsIdentifier>,
    /// Local execution stage, independent of order status.
    pub phase: IssuancePhase,
    /// Saved before newOrder; missing URL afterwards is an uncertain creation.
    pub creation_submitted: bool,
    /// Exact Location returned by newOrder.
    pub order_url: Option<AcmeUrl>,
    /// Most recent CA snapshot.
    pub order: Option<OrderObject>,
    /// Authorizations and publication checkpoints.
    pub authorizations: Vec<AuthorizationRecord>,
    /// Saved before finalize; the same CSR is never regenerated or silently replaced.
    pub finalize_submitted: SubmissionState,
    /// Earliest next query, respecting CA Retry-After across process restart.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub next_poll_at: Option<time::OffsetDateTime>,
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
    /// Return false to yield `action_required`; force bypasses only local DNS lookup.
    ///
    /// # Errors
    /// Reports cancellation, deadline and sanitized resolver/adapter failures.
    async fn ready(
        &self,
        records: &[DnsRequirement],
        force: bool,
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
    /// Persist a validated chain then atomically select this generation.
    ///
    /// # Errors
    /// Failure must retain the previous current generation and recoverable checkpoint.
    async fn complete(&self, record: &IssueRecord, chain: &[u8])
    -> Result<IssueRecord, IssueError>;
}

/// Object-safe generation storage contract for files, databases and embedded services.
#[async_trait]
pub trait IssueStore: Send + Sync {
    /// Create a unique generation and fixed key/CSR durably before network side effects.
    ///
    /// # Errors
    /// Rejects unsafe names, storage errors and incomplete local initialization.
    async fn create(
        &self,
        request: &IssueRequest,
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
    pub force: bool,
    /// Default polling delay when the CA omits Retry-After.
    pub poll_interval: Duration,
}

/// A foreground invocation can finish or yield durable manual action without an error.
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
