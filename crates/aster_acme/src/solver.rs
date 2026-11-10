//! Runtime contracts for independently implemented challenge solvers.

use std::{num::NonZeroU32, time::Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::challenge::{ChallengeKind, ChallengeMaterial};

/// Stable identity used to reconcile publication after a crash.
#[derive(Debug, Clone)]
pub struct OperationContext {
    /// Persistent operation identifier, assigned by the caller.
    pub operation_id: String,
    /// Persistent preparation identifier, unchanged across retries of this publication.
    pub preparation_id: String,
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

/// Whether this preparation owns a published resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceOwnership {
    /// Created by this operation; cleanup must verify ownership before deletion.
    Created,
    /// Preexisting resource, which cleanup must not delete.
    Borrowed,
}

/// Durable receipt used for readiness checks, recovery and cleanup.
///
/// `state` must contain resource identifiers and reconciliation data, never credentials.
/// The storage adapter must treat this entire record as sensitive operation metadata.
#[derive(Clone, Serialize, Deserialize)]
pub struct PreparedChallenge {
    /// Method of the publication.
    pub kind: ChallengeKind,
    /// Stable solver implementation identifier used to restore the correct implementation.
    pub solver_id: String,
    /// Configuration reference, not the raw provider credential.
    pub config_ref: String,
    /// Receipt schema version understood by that solver.
    pub schema_version: NonZeroU32,
    /// Identity used by this publication.
    pub operation_id: String,
    /// Stable reconciliation key persisted before calling prepare.
    pub preparation_id: String,
    /// Whether the preparation created the resource.
    pub ownership: ResourceOwnership,
    /// Solver-specific versioned resource handle, interpreted only by its solver.
    pub state: Value,
}

impl std::fmt::Debug for PreparedChallenge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedChallenge")
            .field("kind", &self.kind)
            .field("schema_version", &self.schema_version)
            .field("ownership", &self.ownership)
            .finish_non_exhaustive()
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
    /// Material does not match this implementation's method.
    #[error("challenge method is not supported by this solver")]
    UnsupportedMethod,
    /// A receipt cannot be interpreted by this implementation or configuration.
    #[error("challenge receipt is incompatible with this solver")]
    IncompatibleReceipt,
    /// The remote outcome or ownership cannot be safely established.
    #[error("publication requires reconciliation before retry or cleanup")]
    ReconciliationRequired,
    /// Adapter-specific failure; message must be sanitized by the implementation.
    #[error("solver adapter failure: {message}")]
    Adapter {
        /// Credential-free description suitable for diagnostics.
        message: String,
    },
}

/// Injectable challenge publication interface; CA acknowledgement and polling stay upstream.
///
/// The caller persists the intent and stable preparation ID before `prepare`, then
/// persists its receipt before notifying the CA. Implementations must reconcile retries
/// with the same preparation ID, including a crash between publication and receipt storage.
/// Uncertain ownership must not be guessed. No method here may acknowledge an ACME challenge.
#[async_trait]
pub trait ChallengeSolver: Send + Sync {
    /// Method actually implemented by this solver.
    fn kind(&self) -> ChallengeKind;

    /// Publish or reconcile the challenge material.
    ///
    /// # Errors
    /// May fail after partial publication; the caller must retain the intent for recovery.
    async fn prepare(
        &self,
        material: &ChallengeMaterial,
        operation: &OperationContext,
        execution: &ExecutionContext,
    ) -> Result<PreparedChallenge, SolverError>;

    /// Wait until publication meets local readiness policy; does not guarantee CA access.
    ///
    /// # Errors
    /// Returns publication, cancellation, timeout, or incompatible-receipt failures.
    async fn wait_ready(
        &self,
        prepared: &PreparedChallenge,
        execution: &ExecutionContext,
    ) -> Result<(), SolverError>;

    /// Idempotently remove only owned resources; missing or borrowed resources are a no-op.
    ///
    /// The caller reconciles CA state before withdrawing active validation material.
    ///
    /// # Errors
    /// Failure leaves cleanup pending and must not erase an issued certificate result.
    async fn cleanup(
        &self,
        prepared: &PreparedChallenge,
        execution: &ExecutionContext,
    ) -> Result<(), SolverError>;
}
