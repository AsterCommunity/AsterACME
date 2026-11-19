//! Cancellation and operation deadline boundaries.
use crate::issuance::{IssueError, IssueExecution};
use crate::solver::{ExecutionContext, SolverError};

pub(super) fn check(execution: &IssueExecution) -> Result<(), IssueError> {
    execution.context.check().map_err(IssueError::from)
}

pub(super) async fn bounded<T>(
    execution: &IssueExecution,
    future: impl std::future::Future<Output = Result<T, IssueError>>,
) -> Result<T, IssueError> {
    bounded_context(&execution.context, future).await
}

pub(super) async fn bounded_context<T>(
    context: &ExecutionContext,
    future: impl std::future::Future<Output = Result<T, IssueError>>,
) -> Result<T, IssueError> {
    context.check().map_err(IssueError::from)?;
    tokio::select! {
        biased;
        ()=context.cancellation.cancelled()=>Err(IssueError::Cancelled),
        result=tokio::time::timeout_at(tokio::time::Instant::from_std(context.deadline),future)=>result.map_err(|_|IssueError::TimedOut)?,
    }
}

impl From<SolverError> for IssueError {
    fn from(error: SolverError) -> Self {
        match error {
            SolverError::Cancelled => Self::Cancelled,
            SolverError::DeadlineExceeded => Self::TimedOut,
        }
    }
}
