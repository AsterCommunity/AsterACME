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
    AfterIssuance {
        /// Generation identifier of the newly issued certificate.
        generation: &'a str,
    },
    /// Retry one inventory snapshot after rechecking it under the object lease.
    Retry {
        /// Generation identifier the snapshot was captured under.
        generation: &'a str,
        /// Observed storage snapshot the adapter rechecks before executing.
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

mod checkpoint;
pub use checkpoint::DeploymentCheckpoint;

#[cfg(test)]
mod tests;
