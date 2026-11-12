//! Typed issuance progress for embedded applications and CLI presentation.
use aster_acme_core::protocol::{AuthorizationStatus, OrderStatus};
use aster_acme_protocol::url::AcmeUrl;
use std::time::Duration;

/// Observations and execution stages, excluding private keys, signed bodies and TXT values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueEvent {
    /// Durable intent exists and newOrder is about to be sent.
    CreatingOrder {
        method: crate::challenge::ChallengeKind,
        solver_id: String,
    },
    /// The CA's Location is durably recorded.
    OrderCreated { url: AcmeUrl },
    /// Latest authoritative order state.
    OrderObserved { status: OrderStatus },
    /// Latest authorization state for a requested DNS identifier.
    AuthorizationObserved {
        identifier: String,
        status: AuthorizationStatus,
    },
    /// All outstanding manual publication requirements have been persisted.
    PublicationRequired {
        method: crate::challenge::ChallengeKind,
        count: usize,
    },
    /// Local publication readiness was established or explicitly bypassed.
    PublicationReady {
        method: crate::challenge::ChallengeKind,
    },
    /// A terminal protocol outcome is saved but publication cleanup remains incomplete.
    CleanupPending,
    /// A challenge acknowledgement received a valid matching response.
    ValidationSubmitted { identifier: String },
    /// One bounded order query; authorizations within this round are not separate polls.
    Polling { attempt: u32, limit: u32 },
    /// A bounded delay is about to be observed before another CA query.
    Waiting {
        delay: Duration,
        attempt: u32,
        limit: u32,
        source: super::PollWaitSource,
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
