//! Typed issuance progress for embedded applications and CLI presentation.
use aster_acme_core::protocol::{AuthorizationStatus, OrderStatus};
use aster_acme_protocol::url::AcmeUrl;
use std::time::Duration;

/// Observations and execution stages, excluding private keys, signed bodies and TXT values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueEvent {
    /// Durable intent exists and newOrder is about to be sent.
    CreatingOrder {
        /// Challenge method the order will use for validation.
        method: crate::challenge::ChallengeKind,
        /// Configured solver that will satisfy the challenge.
        solver_id: String,
    },
    /// The CA's Location is durably recorded.
    OrderCreated {
        /// Authoritative order URL returned by the CA.
        url: AcmeUrl,
    },
    /// Latest authoritative order state.
    OrderObserved {
        /// Order status as last reported by the CA.
        status: OrderStatus,
    },
    /// Latest authorization state for a requested DNS identifier.
    AuthorizationObserved {
        /// DNS identifier the authorization covers.
        identifier: String,
        /// Authorization status as last reported by the CA.
        status: AuthorizationStatus,
    },
    /// All outstanding manual publication requirements have been persisted.
    PublicationRequired {
        /// Challenge method requiring the manual publications.
        method: crate::challenge::ChallengeKind,
        /// Number of outstanding manual publication requirements.
        count: usize,
    },
    /// Local publication readiness was established or explicitly bypassed.
    PublicationReady {
        /// Challenge method whose publications are ready.
        method: crate::challenge::ChallengeKind,
    },
    /// A terminal protocol outcome is saved but publication cleanup remains incomplete.
    CleanupPending,
    /// A challenge acknowledgement received a valid matching response.
    ValidationSubmitted {
        /// DNS identifier whose challenge was submitted for validation.
        identifier: String,
    },
    /// One bounded order query; authorizations within this round are not separate polls.
    Polling {
        /// One-based number of this order query.
        attempt: u32,
        /// Maximum number of order queries before the run gives up.
        limit: u32,
    },
    /// A bounded delay is about to be observed before another CA query.
    Waiting {
        /// Delay before the next CA query.
        delay: Duration,
        /// One-based number of the order query that will follow the delay.
        attempt: u32,
        /// Maximum number of order queries before the run gives up.
        limit: u32,
        /// Why the delay applies (retry-after header, configured cadence, ...).
        source: crate::issuance::PollWaitSource,
    },
    /// The fixed CSR is about to be submitted.
    Finalizing,
    /// The issued certificate is being downloaded and inspected.
    Downloading,
    /// Artifact validation, persistence and `in_use`-generation promotion finished.
    CertificateSaved {
        /// Stable managed certificate name, independent of its domains and generation.
        name: crate::issuance::CertificateName,
    },
}

/// Product-owned progress sink. Implementations must avoid panics and excessive blocking.
/// No terminal or global logger is assumed by the service.
pub trait IssueObserver: Send + Sync {
    /// Consume one event without changing protocol or persistence state.
    fn observe(&self, event: &IssueEvent);
}
