//! Opt-in advisory observations, independent of issuance and publication.
//! Reports never authorize or prohibit issuance; only cancellation/overall
//! execution expiry interrupts the caller. No network runs without an explicit call.
use crate::solver::ExecutionContext;
use async_trait::async_trait;
use std::{
    future::Future,
    time::{Duration, Instant},
};

#[cfg(feature = "precheck-http")]
pub mod http;

pub mod order;

/// Ordinary observation failure, not an ACME or issuance failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    /// Resolver or other checker configuration is unavailable.
    #[error("precheck configuration unavailable")]
    Unavailable,
    /// Lookup/request failed; absence of evidence is not a matching result.
    #[error("precheck lookup failed")]
    LookupFailed,
    /// The checker cannot inspect this input.
    #[error("unsupported precheck input")]
    UnsupportedInput,
    /// The shared stage budget expired while inspecting this input.
    #[error("precheck stage timed out")]
    TimedOut,
    /// Stage budget was exhausted before this input was inspected.
    #[error("input was not checked before the stage budget expired")]
    NotChecked,
}

/// Inject an observer, including external/custom resolvers and transports.
#[async_trait]
pub trait Check: Send + Sync {
    /// A domain, challenge requirement or other borrowed inspection target.
    type Input: Sync;
    /// Checker-specific structured evidence; no required human log text.
    type Output: Send;
    /// Observe one input without changing issuance state or publication resources.
    /// # Errors
    /// Returns ordinary observation failures; the runner owns cancellation and budgets.
    async fn observe(
        &self,
        input: &Self::Input,
        execution: &ExecutionContext,
    ) -> Result<Self::Output, Failure>;
}

/// Evidence for an input at this position in the original request.
#[derive(Debug)]
pub struct Observation<T> {
    /// Stable index into the caller's input slice.
    pub index: usize,
    /// A negative checker result can still be a successful observation.
    pub result: Result<T, Failure>,
}

/// Complete stage evidence, including inputs left unchecked after a local timeout.
#[derive(Debug)]
pub struct Report<T> {
    /// One observation per input, in request order; partial results are retained.
    pub observations: Vec<Observation<T>>,
}

/// Only runner misuse or overall interruption uses the outer error channel.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// A budget must be nonzero and representable as an execution deadline.
    #[error("invalid precheck budget")]
    InvalidBudget,
    /// Caller cancellation or overall execution expiry, distinct from local timeout.
    #[error("precheck execution interrupted")]
    Interrupted,
}

/// A shared budget for all inputs in one stage. Default is five seconds.
#[derive(Debug, Clone, Copy)]
pub struct Runner {
    timeout: Duration,
}
impl Default for Runner {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }
}
impl Runner {
    /// Set an embedding-specific stage budget without changing ACME request limits.
    /// # Errors
    /// Rejects zero or unrepresentable budgets.
    pub fn new(timeout: Duration) -> Result<Self, Error> {
        if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
            return Err(Error::InvalidBudget);
        }
        Ok(Self { timeout })
    }
    /// Budget used by this runner; the caller's earlier overall deadline still wins.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Run a checker explicitly. Failures and local timeout become report entries.
    /// # Errors
    /// Returns interruption on user cancellation/overall expiry, or an invalid deadline.
    pub async fn run<C: Check + ?Sized>(
        &self,
        check: &C,
        inputs: &[C::Input],
        execution: &ExecutionContext,
    ) -> Result<Report<C::Output>, Error> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(Error::InvalidBudget)?;
        let mut observations = Vec::with_capacity(inputs.len());
        execution.check().map_err(|_| Error::Interrupted)?;
        for (index, input) in inputs.iter().enumerate() {
            if let Some(result) = wait(check.observe(input, execution), deadline, execution).await?
            {
                observations.push(Observation { index, result });
            } else {
                observations.push(Observation {
                    index,
                    result: Err(Failure::TimedOut),
                });
                observations.extend((index + 1..inputs.len()).map(|index| Observation {
                    index,
                    result: Err(Failure::NotChecked),
                }));
                break;
            }
        }
        Ok(Report { observations })
    }
}

async fn wait<T>(
    future: impl Future<Output = T>,
    deadline: Instant,
    execution: &ExecutionContext,
) -> Result<Option<T>, Error> {
    execution.check().map_err(|_| Error::Interrupted)?;
    if Instant::now() >= deadline {
        return Ok(None);
    }
    let result = tokio::select! {
        biased;
        () = execution.cancellation.cancelled() => return Err(Error::Interrupted),
        result = tokio::time::timeout_at(deadline.min(execution.deadline).into(), future) => result.ok(),
    };
    execution.check().map_err(|_| Error::Interrupted)?;
    Ok(result)
}

#[cfg(test)]
mod tests;
