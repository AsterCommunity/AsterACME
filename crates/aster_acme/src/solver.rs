//! Runtime contracts for independently implemented challenge solvers.

use std::time::Instant;

use async_trait::async_trait;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::challenge::ChallengeKind;

/// One authorization publication with its stable retry identity and saved receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengePublication {
    /// Stable ID persisted before invoking any external provider.
    pub publication_id: String,
    /// Exact ACME-derived public validation material.
    pub requirement: crate::issuance::ValidationRequirement,
    /// Provider receipt saved from an earlier successful present operation.
    pub receipt: Option<aster_acme_dns::PublicationReceipt>,
    /// DNS route saved before the first provider side effect.
    pub plan: Option<aster_acme_dns::DnsRecord>,
}

/// DNS route update returned by read-only preparation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationPlanUpdate {
    /// Publication identity supplied by the caller.
    pub publication_id: String,
    /// Exact route and record persisted before provider invocation.
    pub plan: aster_acme_dns::DnsRecord,
}

/// Receipt update produced by a successful provider present operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationReceiptUpdate {
    /// Publication ID from the invocation.
    pub publication_id: String,
    /// Exact provider record identity and ownership.
    pub receipt: aster_acme_dns::PublicationReceipt,
}

/// Restore may reconcile durable publication and return newly observed receipts.
#[derive(Debug, Default)]
pub struct RestoreResult {
    /// Receipts that must be saved before the caller continues.
    pub receipts: Vec<PublicationReceiptUpdate>,
    /// Sanitized failure after any successful receipts have been reported.
    pub failure: Option<crate::issuance::IssueError>,
    /// Earliest permitted retry after a provider rate limit.
    pub retry_at: Option<time::OffsetDateTime>,
}

/// Publication outcome separates readiness from partial receipt checkpointing.
#[derive(Debug, Default)]
pub struct ReadyResult {
    /// False means the caller must retain action-required state and not acknowledge.
    pub ready: bool,
    /// Successful receipts that must be saved before the caller continues.
    pub receipts: Vec<PublicationReceiptUpdate>,
    /// Sanitized per-record/provider failure, if any.
    pub failure: Option<crate::issuance::IssueError>,
    /// Earliest permitted retry after a provider rate limit.
    pub retry_at: Option<time::OffsetDateTime>,
}

/// Cleanup outcome reports exact records safe to clear from the journal.
#[derive(Debug, Default)]
pub struct CleanupResult {
    /// Publication IDs whose cleanup is complete, including preexisting values retained.
    pub completed: Vec<String>,
    /// Sanitized failure while other cleanup work may have completed.
    pub failure: Option<crate::issuance::IssueError>,
    /// Earliest permitted retry after a provider rate limit.
    pub retry_at: Option<time::OffsetDateTime>,
}

/// Bounded execution scope, provided separately for preparation, readiness, and cleanup.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Cooperative cancellation signal; solvers must observe it during I/O and waits.
    pub cancellation: CancellationToken,
    /// Absolute monotonic deadline for this invocation (not a persisted timestamp).
    pub deadline: Instant,
}

impl ExecutionContext {
    /// Check cancellation and deadline before executing a side effect.
    ///
    /// # Errors
    /// Returns cancellation or deadline expiry; solvers must also enforce these during I/O.
    pub fn check(&self) -> Result<(), SolverError> {
        if self.cancellation.is_cancelled() {
            return Err(SolverError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(SolverError::DeadlineExceeded);
        }
        Ok(())
    }
}

/// Solver failure; whether to retry is decided using the operation's side effects.
#[derive(Debug, Error)]
pub enum SolverError {
    /// Cooperative cancellation, without implying that cleanup has completed.
    #[error("solver invocation cancelled")]
    Cancelled,
    /// The invocation's execution budget expired.
    #[error("solver invocation deadline exceeded")]
    DeadlineExceeded,
}

/// Application publication boundary. ACME persists requirements before calling it,
/// then owns CA acknowledgement/polling. Implementations must reconcile publication
/// with the same saved operation identity; they never send an ACME request themselves.
#[async_trait]
pub trait ChallengeSolver: Send + Sync {
    /// Protocol method implemented by this adapter; checked before network mutations.
    fn kind(&self) -> ChallengeKind;

    /// Require a durable DNS receipt before CA acknowledgement.
    fn requires_receipt(&self) -> bool {
        false
    }

    /// Plan publication without mutating DNS. Returned routes are persisted before ready.
    async fn prepare(
        &self,
        _publications: &[ChallengePublication],
        _execution: &ExecutionContext,
    ) -> Result<Vec<PublicationPlanUpdate>, crate::issuance::IssueError> {
        Ok(Vec::new())
    }

    /// Restore invocation-local services without re-acknowledging the CA.
    async fn restore(
        &self,
        _publications: &[ChallengePublication],
        _execution: &ExecutionContext,
    ) -> Result<RestoreResult, crate::issuance::IssueError> {
        Ok(RestoreResult::default())
    }

    /// Stop invocation-local services and finish owned child-process shutdown.
    async fn shutdown(&self) {}

    /// Publish material. Receipts are saved even if another publication fails.
    async fn ready(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<ReadyResult, crate::issuance::IssueError>;

    /// Read-only readiness policy, run after successful receipts are persisted.
    async fn wait_ready(
        &self,
        _publications: &[ChallengePublication],
        _execution: &ExecutionContext,
    ) -> Result<(), crate::issuance::IssueError> {
        Ok(())
    }

    /// Remove only owned publication after a terminal CA outcome.
    async fn cleanup(
        &self,
        _publications: &[ChallengePublication],
        _execution: &ExecutionContext,
    ) -> Result<CleanupResult, crate::issuance::IssueError> {
        Ok(CleanupResult::default())
    }
}
