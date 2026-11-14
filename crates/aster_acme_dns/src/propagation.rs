//! AsterACME-owned propagation policy, separate from provider mutation.
use crate::{
    DnsRecord, ProviderExecution,
    routing::{DnsLookup, LookupError},
};
use std::time::Duration;
use thiserror::Error;

/// Read-only TXT propagation policy.
#[derive(Debug, Clone, Copy)]
pub struct PropagationPolicy {
    /// Delay between recursive observations, never a CA validation claim.
    pub interval: Duration,
    /// Maximum wait, bounded again by the operation deadline.
    pub timeout: Duration,
}
impl Default for PropagationPolicy {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(120),
        }
    }
}
impl PropagationPolicy {
    /// Wait until every expected value is observed at its original challenge owner.
    /// # Errors
    /// Returns interruption, invalid policy, or unavailable/mismatching DNS at expiry.
    pub async fn wait(
        &self,
        lookup: &dyn DnsLookup,
        records: &[DnsRecord],
        execution: &ProviderExecution,
    ) -> Result<(), PropagationError> {
        if self.interval.is_zero() || self.timeout.is_zero() {
            return Err(PropagationError::InvalidPolicy);
        }
        let deadline = (std::time::Instant::now() + self.timeout).min(execution.deadline);
        let mut last_error = None;
        loop {
            if execution.cancellation.is_cancelled() {
                return Err(PropagationError::Interrupted);
            }
            if std::time::Instant::now() >= deadline {
                return Err(
                    last_error.map_or(PropagationError::NotVisible, PropagationError::Lookup)
                );
            }
            let mut all = true;
            let mut groups = std::collections::BTreeMap::<&str, Vec<&[u8]>>::new();
            for record in records {
                groups
                    .entry(&record.challenge_name)
                    .or_default()
                    .push(record.value.as_bytes());
            }
            for (owner, expected_values) in groups {
                let result = tokio::select! {
                    biased;
                    () = execution.cancellation.cancelled() => return Err(PropagationError::Interrupted),
                    result = tokio::time::timeout_at(deadline.into(), lookup.txt(owner)) => result,
                };
                match result {
                    Ok(Ok(values))
                        if expected_values.iter().all(|expected| {
                            values.iter().any(|value| value.as_slice() == *expected)
                        }) => {}
                    Ok(Err(error)) => {
                        last_error = Some(error);
                        all = false;
                    }
                    _ => {
                        all = false;
                    }
                }
            }
            if all {
                return Ok(());
            }
            tokio::select! {
                biased;
                () = execution.cancellation.cancelled() => return Err(PropagationError::Interrupted),
                () = tokio::time::sleep(self.interval.min(deadline.saturating_duration_since(std::time::Instant::now()))) => {},
            }
        }
    }
}

/// Propagation failure leaves publication in place and never acknowledges the CA.
#[derive(Debug, Error)]
pub enum PropagationError {
    /// Read-only propagation was cancelled.
    #[error("DNS propagation interrupted")]
    Interrupted,
    /// Values were not all observed before the deadline.
    #[error("expected TXT values were not visible before the propagation deadline")]
    NotVisible,
    /// Preserve resolver diagnostic after unsuccessful observations.
    #[error(transparent)]
    Lookup(#[from] LookupError),
    /// A zero wait/interval is not allowed.
    #[error("invalid DNS propagation policy")]
    InvalidPolicy,
}
