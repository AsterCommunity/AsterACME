//! Deployment admission and state transitions, independent of files and processes.
use crate::{
    deployment::{DeploymentIntent, DeploymentPhase},
    issuance::IssueError,
};
use time::OffsetDateTime;

/// Complete execution state; adapters map this to their own persisted schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentCheckpoint {
    /// Generation last attempted by this binding.
    pub generation: Option<String>,
    /// Issued generation still waiting for publication.
    pub pending_generation: Option<String>,
    /// Last observed execution phase.
    pub phase: DeploymentPhase,
    /// Reload invocations for the attempted generation.
    pub attempts: u8,
    /// Consecutive failures for the attempted generation.
    pub retry_failures: u32,
    /// Minimum time before another automatic attempt.
    pub retry_at: Option<OffsetDateTime>,
    /// Host diagnostic, excluding captured process output.
    pub last_error: Option<String>,
}

impl DeploymentCheckpoint {
    /// No pending publication remains after a confirmed deployment.
    #[must_use]
    pub fn is_deployed(&self) -> bool {
        self.phase == DeploymentPhase::Deployed && self.pending_generation.is_none()
    }

    /// Inventory predicate; callers must repeat admission under their object lease.
    #[must_use]
    pub fn due(&self, current: &str, now: OffsetDateTime) -> bool {
        if self.pending_generation.as_deref() == Some(current) {
            return !self.phase.reload_uncertain() && self.retry_at.is_none_or(|at| at <= now);
        }
        super::DeploymentRetryState {
            generation: self.generation.as_deref(),
            phase: self.phase,
            retry_at: self.retry_at,
        }
        .due(current, now)
    }

    /// Admission after the adapter has compared the complete configuration snapshot.
    #[must_use]
    pub fn admits<Snapshot>(
        &self,
        current: &str,
        intent: DeploymentIntent<'_, Snapshot>,
        snapshot_matches: bool,
        now: OffsetDateTime,
    ) -> bool {
        match intent {
            DeploymentIntent::Explicit => true,
            DeploymentIntent::AfterIssuance { generation } => {
                generation == current
                    && super::admits_after_issuance(
                        super::DeploymentRetryState {
                            generation: self.generation.as_deref(),
                            phase: self.phase,
                            retry_at: self.retry_at,
                        },
                        current,
                        now,
                    )
            }
            DeploymentIntent::Retry { generation, .. } => {
                generation == current && snapshot_matches && self.due(current, now)
            }
        }
    }

    /// Apply a known host observation, consuming the pending publication intent.
    #[must_use]
    pub fn observed(
        &self,
        generation: &str,
        phase: DeploymentPhase,
        attempts: u8,
        error: Option<String>,
    ) -> Self {
        let reset =
            self.generation.as_deref() != Some(generation) || phase == DeploymentPhase::Deployed;
        Self {
            generation: Some(generation.into()),
            pending_generation: None,
            phase,
            attempts,
            last_error: error,
            retry_failures: if reset { 0 } else { self.retry_failures },
            retry_at: if reset { None } else { self.retry_at },
        }
    }

    /// Retain an issued generation without claiming publication started.
    ///
    /// # Errors
    /// Uncertain reload effects require explicit reconciliation first.
    pub fn pending(&self, generation: &str) -> Result<Self, IssueError> {
        if self.phase.reload_uncertain() {
            return Err(IssueError::InvalidInput(
                "uncertain reload outcome blocks automatic deployment",
            ));
        }
        let mut next = self.clone();
        next.pending_generation = Some(generation.into());
        next.retry_at = None;
        Ok(next)
    }

    /// Make published files eligible for their first reload without counting a failure.
    ///
    /// # Errors
    /// Only a confirmed publication whose reload has not started can be scheduled.
    pub fn schedule(&self, now: OffsetDateTime) -> Result<Self, IssueError> {
        if self.phase != DeploymentPhase::PublicationComplete {
            return Err(IssueError::InvalidInput(
                "deployment phase is not eligible for retry scheduling",
            ));
        }
        let mut next = self.clone();
        next.retry_at = Some(now);
        Ok(next)
    }

    /// Advance a known failure using the shared retry sequence and checked arithmetic.
    ///
    /// # Errors
    /// Rejects uncertainty, nonfailure phases and unrepresentable retry deadlines.
    pub fn failed(
        &self,
        phase: DeploymentPhase,
        attempts: u8,
        error: String,
        now: OffsetDateTime,
    ) -> Result<Self, IssueError> {
        if !matches!(
            phase,
            DeploymentPhase::PublishFailed | DeploymentPhase::ReloadFailed
        ) {
            return Err(IssueError::InvalidInput(
                "deployment failure phase is not retryable",
            ));
        }
        if self.phase.reload_uncertain() {
            return Err(IssueError::InvalidInput(
                "uncertain reload outcomes cannot be auto-retried",
            ));
        }
        let mut next = self.clone();
        next.phase = phase;
        next.attempts = attempts;
        next.last_error = Some(error);
        next.retry_failures = next.retry_failures.saturating_add(1);
        next.retry_at = Some(
            now.checked_add(time::Duration::seconds(
                aster_acme_core::renewal::renewal_retry_delay_seconds(next.retry_failures),
            ))
            .ok_or(IssueError::InvalidInput(
                "deployment retry deadline overflow",
            ))?,
        );
        Ok(next)
    }

    /// Configuration edits never resolve a previous unknown reload outcome.
    #[must_use]
    pub fn reconfigured(&self) -> Self {
        if self.phase.reload_uncertain() {
            return self.clone();
        }
        let mut next = self.clone();
        next.phase = DeploymentPhase::Configured;
        next.generation = None;
        next.pending_generation = None;
        next.attempts = 0;
        next.last_error = None;
        next
    }
}
