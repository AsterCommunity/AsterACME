//! Cancellation and operation deadline boundaries.
use crate::issuance::{IssueError, IssueExecution};

pub(super) fn check(execution: &IssueExecution) -> Result<(), IssueError> {
    execution
        .context
        .check()
        .map_err(|_| IssueError::Interrupted)
}

pub(super) async fn bounded<T>(
    execution: &IssueExecution,
    future: impl std::future::Future<Output = Result<T, IssueError>>,
) -> Result<T, IssueError> {
    check(execution)?;
    tokio::select! {
        biased;
        ()=execution.context.cancellation.cancelled()=>Err(IssueError::Interrupted),
        result=tokio::time::timeout_at(tokio::time::Instant::from_std(execution.context.deadline),future)=>result.map_err(|_|IssueError::Interrupted)?,
    }
}
