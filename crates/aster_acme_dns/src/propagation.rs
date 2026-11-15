//! Advisory DNS observations and bounded publication delays shared by provider adapters.
use crate::{DnsRecord, ProviderExecution, routing::DnsLookup};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Read-only advice before asking the CA to validate provider-published TXT records.
#[derive(Debug, Clone, Copy)]
pub struct PropagationPolicy {
    /// Delay after receipts are saved, before the first and only local observation.
    pub initial_delay: Duration,
    /// Additional delay when local DNS cannot confirm every expected value.
    pub fallback_delay: Duration,
    /// Maximum budget for the local observation, within the operation deadline.
    pub timeout: Duration,
}
impl Default for PropagationPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(5),
            fallback_delay: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Progress contains no TXT values, credentials, or provider responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationEvent {
    /// Allow newly published records to settle before observing local DNS.
    WaitingToCheck(Duration),
    /// Local DNS did not confirm all values; wait once before proceeding to the CA.
    WaitingForCa(Duration),
}

impl PropagationPolicy {
    /// Observe each original challenge owner once, requiring all its expected values
    /// in the same answer. Missing values, resolver errors and probe timeout are
    /// advisory: wait the fallback delay, then let the CA make its own decision.
    /// Returns whether local DNS confirmed every value.
    /// # Errors
    /// Returns interruption for cancellation/operation expiry, or an invalid policy.
    pub async fn wait(
        &self,
        lookup: &dyn DnsLookup,
        records: &[DnsRecord],
        execution: &ProviderExecution,
        observe: impl Fn(PropagationEvent) + Send + Sync,
    ) -> Result<bool, PropagationError> {
        if self.timeout.is_zero() {
            return Err(PropagationError::InvalidPolicy);
        }
        check_execution(execution)?;
        if records.is_empty() {
            return Ok(true);
        }
        observe(PropagationEvent::WaitingToCheck(self.initial_delay));
        delay(self.initial_delay, execution).await?;
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(PropagationError::InvalidPolicy)?
            .min(execution.deadline);
        let mut groups = std::collections::BTreeMap::<&str, Vec<&[u8]>>::new();
        for record in records {
            groups
                .entry(&record.challenge_name)
                .or_default()
                .push(record.value.as_bytes());
        }
        let check = async {
            for (owner, expected_values) in groups {
                let Ok(values) = lookup.txt(owner).await else {
                    return false;
                };
                if !expected_values
                    .iter()
                    .all(|expected| values.iter().any(|value| value.as_slice() == *expected))
                {
                    return false;
                }
            }
            true
        };
        let visible = tokio::select! {
            biased;
            () = execution.cancellation.cancelled() => return Err(PropagationError::Interrupted),
            result = tokio::time::timeout_at(deadline.into(), check) => result.unwrap_or(false),
        };
        check_execution(execution)?;
        if !visible {
            observe(PropagationEvent::WaitingForCa(self.fallback_delay));
            delay(self.fallback_delay, execution).await?;
        }
        Ok(visible)
    }
}

async fn delay(duration: Duration, execution: &ProviderExecution) -> Result<(), PropagationError> {
    check_execution(execution)?;
    let until = Instant::now()
        .checked_add(duration)
        .ok_or(PropagationError::InvalidPolicy)?;
    tokio::select! {
        biased;
        () = execution.cancellation.cancelled() => return Err(PropagationError::Interrupted),
        () = tokio::time::sleep_until(execution.deadline.into()) => return Err(PropagationError::Interrupted),
        () = tokio::time::sleep_until(until.into()) => {},
    }
    check_execution(execution)
}

fn check_execution(execution: &ProviderExecution) -> Result<(), PropagationError> {
    if execution.cancellation.is_cancelled() || Instant::now() >= execution.deadline {
        Err(PropagationError::Interrupted)
    } else {
        Ok(())
    }
}

/// Local DNS failure is advisory; execution cancellation and invalid policy are not.
#[derive(Debug, Error)]
pub enum PropagationError {
    /// Cancelled or the overall operation budget expired.
    #[error("DNS propagation interrupted")]
    Interrupted,
    /// The local observation requires a nonzero budget.
    #[error("invalid DNS propagation policy")]
    InvalidPolicy,
}
