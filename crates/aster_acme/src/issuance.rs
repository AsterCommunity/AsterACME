//! Persisted issuance contracts. Protocol effects belong to the service, files to adapters.

use crate::{account::AccountRecord, crypto::JwsSigner, solver::ExecutionContext};
use std::{sync::Arc, time::Duration};

mod authorization;
pub mod certificate;
pub mod chain;

pub mod progress;
pub mod publication;
pub mod service;
pub mod workflow;

mod error;
mod record;
mod request;
mod retry;
mod validation;

pub use chain::{
    ChainCandidate, ChainDecision, ChainIdentity, ChainName, ChainPreference, ChainSelector,
};
pub use error::IssueError;
pub use record::IssueRecord;
pub use request::{CertificateName, IssueRequest};
pub use retry::{PollWaitSource, RenewalPredecessor, RenewalRetryState, RequestFailure};
pub use validation::{AuthorizationRecord, ValidationRequirement};

/// One invocation's controls; deadlines are monotonic and never persisted as Instants.
pub struct IssueExecution {
    /// Maximum order-poll rounds in this invocation; excludes discovery and mutations.
    pub max_polls: u32,
    /// Cancellation and overall execution budget.
    pub context: ExecutionContext,

    /// Default polling delay when the CA omits Retry-After.
    pub poll_interval: Duration,
}

/// A foreground invocation can finish or yield durable manual action without an error.
/// The owned snapshot is boxed to avoid inlining the full journal into each async result.
pub enum IssueOutcome {
    /// Caller must publish the method-specific requirements then resume.
    ActionRequired {
        /// Durable issuance record to resume once publications are in place.
        record: Box<IssueRecord>,
        /// Outstanding manual publication requirements, one per required record.
        records: Vec<ValidationRequirement>,
    },
    /// Persisted certificate and independent manual cleanup instructions.
    Completed {
        /// Durable issuance record holding the saved certificate.
        record: Box<IssueRecord>,
        /// Manual cleanup instructions the caller may apply independently.
        cleanup: Vec<ValidationRequirement>,
    },
}

/// An account binding used by a service invocation, verified against the saved generation.
pub struct IssueIdentity {
    /// Account's latest persisted registration metadata.
    pub account: AccountRecord,
    /// Signing boundary; may be backed by an HSM or remote service.
    pub signer: Arc<dyn JwsSigner>,
}

#[cfg(test)]
mod tests;
