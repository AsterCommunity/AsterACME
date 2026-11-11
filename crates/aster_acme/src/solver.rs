//! Runtime contracts for independently implemented challenge solvers.

use std::time::Instant;

use async_trait::async_trait;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::challenge::ChallengeKind;

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

    /// Publish or ask for publication, and establish local readiness. False yields
    /// durable `action_required`. Publication policy is owned by the implementation.
    ///
    /// # Errors
    /// Reports sanitized adapter failure, cancellation or deadline expiry.
    async fn ready(
        &self,
        requirements: &[crate::issuance::ValidationRequirement],

        execution: &ExecutionContext,
    ) -> Result<bool, crate::issuance::IssueError>;

    /// Remove only owned unchanged publication after issuance succeeds or the CA
    /// marks the order invalid. Cancellation and uncertain outcomes retain it. Manual
    /// implementations return false so their independent cleanup instructions remain.
    ///
    /// # Errors
    /// A cleanup failure never replaces the saved CA outcome; material stays pending.
    async fn cleanup(
        &self,
        _requirements: &[crate::issuance::ValidationRequirement],
        _execution: &ExecutionContext,
    ) -> Result<bool, crate::issuance::IssueError> {
        Ok(false)
    }
}
