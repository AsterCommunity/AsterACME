//! Optional typed pre-order advice injected into the composed issuance workflow.
use crate::{
    issuance::{IssueError, IssueRecord},
    precheck::{Error, Report},
    solver::ExecutionContext,
};
use aster_acme_protocol::directory::Directory;
use async_trait::async_trait;

/// A stage returns evidence, never a local allow/deny decision for issuance.
#[async_trait]
pub trait BeforeOrder: Send + Sync {
    /// Checker-owned structured evidence consumed by the application's observer.
    type Output: Send + Sync;
    /// Inspect the discovered CA and saved request without mutating either.
    /// # Errors
    /// Only interruption or invalid local configuration uses the error channel;
    /// DNS failures, mismatch and local timeout must be retained in the report.
    async fn check(
        &self,
        directory: &Directory,
        record: &IssueRecord,
        execution: &ExecutionContext,
    ) -> Result<Report<Self::Output>, Error>;
}

/// Presentation/collection boundary used immediately before issuance continues.
pub trait Observer<T>: Send + Sync {
    /// Stage started; implementations should avoid blocking.
    fn starting(&self) {}
    /// Consume every finding, including negative and unknown results.
    fn observed(&self, report: &Report<T>);
}

/// Explicitly selected checker and an optional product-owned report observer.
pub struct Stage<'a, C: BeforeOrder + ?Sized> {
    check: &'a C,
    observer: Option<&'a dyn Observer<C::Output>>,
}
impl<'a, C: BeforeOrder + ?Sized> Stage<'a, C> {
    /// Select this check; construction performs no IO.
    #[must_use]
    pub const fn new(check: &'a C) -> Self {
        Self {
            check,
            observer: None,
        }
    }
    /// Attach reporting without making CLI/logging a dependency of the checker.
    #[must_use]
    pub fn with_observer(mut self, observer: &'a dyn Observer<C::Output>) -> Self {
        self.observer = Some(observer);
        self
    }
    pub(crate) async fn run(
        &self,
        directory: &Directory,
        record: &IssueRecord,
        execution: &ExecutionContext,
    ) -> Result<(), IssueError> {
        if let Some(observer) = self.observer {
            observer.starting();
        }
        let report = self
            .check
            .check(directory, record, execution)
            .await
            .map_err(|error| match error {
                Error::Interrupted => IssueError::Interrupted,
                Error::InvalidBudget => IssueError::InvalidInput("invalid precheck budget"),
            })?;
        if let Some(observer) = self.observer {
            observer.observed(&report);
        }
        Ok(())
    }
}
