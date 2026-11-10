//! Typed issuance progress for embedded applications and CLI presentation.
use aster_acme_core::protocol::{AuthorizationStatus, OrderStatus};
use aster_acme_protocol::url::AcmeUrl;
use std::time::Duration;

/// Observations and execution stages, excluding private keys, signed bodies and TXT values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueEvent {
    /// Durable intent exists and newOrder is about to be sent.
    CreatingOrder,
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
    PublicationRequired { count: usize },
    /// Local publication readiness was established or explicitly bypassed.
    DnsReady { forced: bool },
    /// A challenge acknowledgement received a valid matching response.
    ValidationSubmitted { identifier: String },
    /// A bounded delay is about to be observed before another CA query.
    Waiting { delay: Duration },
    /// The fixed CSR is about to be submitted.
    Finalizing,
    /// The issued certificate is being downloaded and inspected.
    Downloading,
    /// Artifact validation, persistence and `in_use`-generation promotion finished.
    CertificateSaved,
}

/// Product-owned progress sink. Implementations must avoid panics and excessive blocking.
/// No terminal or global logger is assumed by the service.
pub trait IssueObserver: Send + Sync {
    /// Consume one event without changing protocol or persistence state.
    fn observe(&self, event: &IssueEvent);
}
