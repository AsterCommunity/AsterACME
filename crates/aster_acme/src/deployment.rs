//! Deployment retry admission policy shared by hosts and storage adapters.

/// Durable deployment phase, independent from issuance and CA order state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPhase {
    /// Configured but not published for a generation.
    Configured,
    /// File publication has begun and may need reconciliation.
    Publishing,
    /// File publication failed before it completed.
    PublishFailed,
    /// Files are published and reload has not started.
    PublicationComplete,
    /// Reload was started; its external effect may be unknown after interruption.
    Reloading,
    /// Reload returned a known failure.
    ReloadFailed,
    /// Reload outcome could not be confirmed and must not be replayed automatically.
    ReloadUncertain,
    /// Publication and configured reload completed.
    Deployed,
}

/// Why a host requests deployment execution. A retry carries its observed storage
/// snapshot generically so the adapter can compare the complete binding under lease.
pub enum DeploymentIntent<'a, Snapshot> {
    /// Operator explicitly requested publication/reload, including reconciliation.
    Explicit,
    /// Deploy this exact generation after a successful issuance.
    AfterIssuance { generation: &'a str },
    /// Retry one inventory snapshot after rechecking it under the object lease.
    Retry {
        generation: &'a str,
        snapshot: &'a Snapshot,
    },
}

impl<Snapshot> Copy for DeploymentIntent<'_, Snapshot> {}

impl<Snapshot> Clone for DeploymentIntent<'_, Snapshot> {
    fn clone(&self) -> Self {
        *self
    }
}

impl DeploymentPhase {
    /// A previous reload may have affected a service and requires explicit reconciliation.
    #[must_use]
    pub const fn reload_uncertain(self) -> bool {
        matches!(self, Self::Reloading | Self::ReloadUncertain)
    }

    /// Whether this saved phase represents a failure safe for automatic retry.
    #[must_use]
    pub const fn automatically_retryable(self) -> bool {
        matches!(
            self,
            Self::Publishing | Self::PublishFailed | Self::PublicationComplete | Self::ReloadFailed
        )
    }
}

/// Minimal saved state used to decide whether a retry snapshot is still admissible.
#[derive(Debug, Clone, Copy)]
pub struct DeploymentRetryState<'a> {
    /// Generation on which this binding last attempted deployment.
    pub generation: Option<&'a str>,
    /// Durable execution phase.
    pub phase: DeploymentPhase,
    /// Earliest automatic retry deadline.
    pub retry_at: Option<time::OffsetDateTime>,
}

impl DeploymentRetryState<'_> {
    /// A known retryable failure is due only for the still-current generation.
    #[must_use]
    pub fn due(self, current_generation: &str, now: time::OffsetDateTime) -> bool {
        self.generation == Some(current_generation)
            && self.phase.automatically_retryable()
            && self.retry_at.is_none_or(|deadline| deadline <= now)
    }
}

/// Decide whether a fresh issuance may deploy this generation automatically.
#[must_use]
pub fn admits_after_issuance(
    state: DeploymentRetryState<'_>,
    current_generation: &str,
    now: time::OffsetDateTime,
) -> bool {
    !state.phase.reload_uncertain()
        && (state.generation != Some(current_generation)
            || (state.phase != DeploymentPhase::Deployed
                && state.retry_at.is_none_or(|deadline| deadline <= now)))
}

#[cfg(test)]
mod tests {
    use crate::deployment::{DeploymentPhase, DeploymentRetryState, admits_after_issuance};

    #[test]
    fn retry_admission_requires_current_generation_known_failure_and_elapsed_deadline() {
        let now = time::OffsetDateTime::from_unix_timestamp(100).unwrap();
        let due = DeploymentRetryState {
            generation: Some("current"),
            phase: DeploymentPhase::ReloadFailed,
            retry_at: Some(now),
        };
        assert!(due.due("current", now));
        assert!(!due.due("current", now - time::Duration::nanoseconds(1)));
        assert!(!due.due("previous", now));

        for phase in [
            DeploymentPhase::Configured,
            DeploymentPhase::Reloading,
            DeploymentPhase::ReloadUncertain,
            DeploymentPhase::Deployed,
        ] {
            assert!(
                !DeploymentRetryState {
                    generation: Some("current"),
                    phase,
                    retry_at: None,
                }
                .due("current", now),
                "{phase:?} must not be retried automatically"
            );
        }
    }

    #[test]
    fn after_issuance_allows_new_generation_but_respects_same_generation_barriers() {
        let now = time::OffsetDateTime::from_unix_timestamp(100).unwrap();
        let state = |generation, phase, retry_at| DeploymentRetryState {
            generation,
            phase,
            retry_at,
        };
        assert!(admits_after_issuance(
            state(Some("old"), DeploymentPhase::Deployed, None),
            "new",
            now,
        ));
        assert!(admits_after_issuance(
            state(Some("new"), DeploymentPhase::ReloadFailed, Some(now)),
            "new",
            now,
        ));
        assert!(!admits_after_issuance(
            state(
                Some("new"),
                DeploymentPhase::ReloadFailed,
                Some(now + time::Duration::nanoseconds(1)),
            ),
            "new",
            now,
        ));
        for phase in [DeploymentPhase::Reloading, DeploymentPhase::ReloadUncertain] {
            assert!(!admits_after_issuance(
                state(Some("new"), phase, None),
                "new",
                now
            ));
        }
        assert!(!admits_after_issuance(
            state(Some("new"), DeploymentPhase::Deployed, None),
            "new",
            now,
        ));
    }
}
