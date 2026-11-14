//! Renewal-owned directory discovery and ARI refresh for one finite cycle.
use crate::{
    issuance::{IssueError, IssueRecord},
    renewal::{RefreshAttempt, RenewalService, refresh_due},
    solver::ExecutionContext,
    storage::issuance::IssueSession,
    transport::{AcmeClient, HttpPool, TransportOptions},
};
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;

/// Successful refresh disposition, distinct from transport/storage errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshStatus {
    /// Applied valid advice and server retry guidance.
    Refreshed,
    /// Retained a plan with the conservative retry schedule.
    RetryScheduled,
    /// The discovered directory does not advertise ARI.
    Unavailable,
    /// No longer eligible or due under the caller's lease.
    Skipped,
}

/// Result and durable record, avoiding redundant reads after successful refreshes.
pub struct RefreshResult {
    /// Observation made by this invocation.
    pub status: RefreshStatus,
    /// Latest saved record, or unchanged record when no write was needed.
    pub record: IssueRecord,
}

/// Invocation-owned directory cache and refresh policy, reusable by any scheduler.
/// No global state, timer or account identity is needed for unsigned ARI GETs.
pub struct RefreshCycle<'a> {
    pool: &'a HttpPool,
    options: TransportOptions,
    clients: HashMap<String, Arc<AcmeClient>>,
}

impl<'a> RefreshCycle<'a> {
    /// Share the host's HTTP pool and cache successful discoveries for this cycle.
    #[must_use]
    pub fn new(pool: &'a HttpPool, options: TransportOptions) -> Self {
        Self {
            pool,
            options,
            clients: HashMap::new(),
        }
    }

    /// Recheck eligibility, discover the CA as needed, and refresh its ARI plan.
    /// The caller must retain the certificate lease throughout this call.
    /// Discovery failures/unavailability defer the next check without claiming
    /// an ARI GET occurred. Existing plans and actual query times are retained.
    ///
    /// # Errors
    /// Returns discovery, cancellation/deadline or persistence failures. A retry
    /// intent may already be durable; reread the session before reporting errors.
    pub async fn refresh(
        &mut self,
        session: &mut dyn IssueSession,
        execution: &ExecutionContext,
    ) -> Result<RefreshResult, IssueError> {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        let mut record = session.record().await?;
        if !refresh_due(&record, OffsetDateTime::now_utc()) {
            return Ok(RefreshResult {
                status: RefreshStatus::Skipped,
                record,
            });
        }
        let key = record.directory.as_str();
        let client = if let Some(client) = self.clients.get(key) {
            client.clone()
        } else {
            let result = tokio::select! {
                biased;
                () = execution.cancellation.cancelled() => Err(IssueError::Interrupted),
                result = tokio::time::timeout_at(execution.deadline.into(), self.pool.discover(record.directory.clone(), self.options.clone())) => match result {
                    Ok(result) => result.map_err(IssueError::from),
                    Err(_) => Err(IssueError::Interrupted),
                },
            };
            let client = match result {
                Ok(client) => Arc::new(client),
                Err(error) => {
                    defer_discovery(session, &mut record, true).await?;
                    return Err(error);
                }
            };
            self.clients.insert(key.into(), client.clone());
            client
        };
        // Discovery may consume enough time to cross certificate expiry. The
        // lease prevents competing writers, but cannot freeze wall-clock time.
        if !refresh_due(&record, OffsetDateTime::now_utc()) {
            return Ok(RefreshResult {
                status: RefreshStatus::Skipped,
                record,
            });
        }
        if client.directory().renewal_info.is_none() {
            defer_discovery(session, &mut record, false).await?;
            return Ok(RefreshResult {
                status: RefreshStatus::Unavailable,
                record,
            });
        }
        let record = RenewalService::new(client)
            .refresh_due_record(session, record, execution)
            .await?;
        let status = if record
            .renewal
            .as_ref()
            .is_some_and(|plan| plan.last_query_failed)
        {
            RefreshStatus::RetryScheduled
        } else {
            RefreshStatus::Refreshed
        };
        Ok(RefreshResult { status, record })
    }
}

async fn defer_discovery(
    session: &dyn IssueSession,
    record: &mut IssueRecord,
    failed: bool,
) -> Result<(), IssueError> {
    if let Some(plan) = &mut record.renewal {
        plan.defer(
            OffsetDateTime::now_utc(),
            RefreshAttempt::Discovery { failed },
        );
    }
    session.save(record).await
}
