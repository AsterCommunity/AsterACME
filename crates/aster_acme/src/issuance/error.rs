//! Issuance error contracts.
use crate::issuance::CertificateName;
use crate::storage::account::AccountStoreError;
use thiserror::Error;

/// Protocol/service failures without private key material.
#[derive(Debug, Error)]
pub enum IssueError {
    /// Another process owns the execution lease; this is not a failed CA attempt.
    #[error("{0} execution lock is unavailable: {1}")]
    LeaseUnavailable(&'static str, String),
    /// Authorization or selected challenge reached a terminal failure independently of order status.
    #[error("CA authorization/challenge failed (authorization status: {status:?})")]
    AuthorizationFailed {
        /// Actual observed authorization status, never synthesized as order invalid.
        status: aster_acme_core::protocol::AuthorizationStatus,
        /// The CA's selected challenge explanation when provided.
        problem: Option<Box<aster_acme_protocol::problem::Problem>>,
    },
    /// Input invariant or CA resource mismatch.
    #[error("{0}")]
    InvalidInput(&'static str),
    /// Sanitized application publication failure; never include credentials or keys.
    #[error("validation publication failed: {0}")]
    Publication(String),
    /// Structured DNS provider or external process failure.
    #[error(transparent)]
    DnsProvider(#[from] aster_acme_dns::ProviderFailure),
    /// DNS route resolution/policy failure with resolver causes preserved.
    #[error(transparent)]
    DnsRouting(#[from] aster_acme_dns::routing::RouteError),
    /// Expected TXT values were not observed under the propagation policy.
    #[error(transparent)]
    DnsPropagation(#[from] aster_acme_dns::propagation::PropagationError),
    /// A saved provider rate limit forbids another invocation before this time.
    #[error("DNS provider rate limited; retry no earlier than {0}")]
    DnsRetryAt(time::OffsetDateTime),
    /// A managed certificate already owns this name; only automatic names may be retried.
    #[error("a managed certificate named '{0}' already exists")]
    NameAlreadyExists(CertificateName),
    /// Invalid revocation material, authority or checkpoint; has no issuance recovery action.
    #[error("{0}")]
    RevocationInput(&'static str),
    /// Revocation cancellation/deadline; its checkpoint determines whether submission was uncertain.
    #[error(
        "revocation interrupted; inspect its saved state before explicitly retrying the same certificate and reason"
    )]
    RevocationInterrupted,
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
    /// This invocation reached its configured order-poll budget.
    #[error("CA polling limit reached ({completed}/{limit}); resume the saved request to continue")]
    PollLimit { completed: u32, limit: u32 },
    /// The CA made this order terminal; embedded problems remain available offline.
    #[error("CA order is invalid; start a new request after correcting validation")]
    InvalidOrder {
        problem: Option<Box<aster_acme_protocol::problem::Problem>>,
    },
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
