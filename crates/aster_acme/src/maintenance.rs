//! One finite maintenance cycle for external schedulers and future daemon loops.
//! Refreshes due ARI advice only; certificate issuance and deployment are host-owned stages.
use crate::{
    issuance::{CertificateName, IssueError, IssueRecord},
    renewal::refresh::{RefreshCycle, RefreshStatus},
    solver::ExecutionContext,
    storage::{issuance::IssueStore, query::IssueQuery},
    transport::{HttpPool, TransportOptions},
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Execution settings independent of the external scheduler's invocation frequency.
#[derive(Clone)]
pub struct Options {
    /// Per-request timeout and HTTP identity. ARI is unsigned, no account key is loaded.
    pub transport: TransportOptions,
    /// One budget per selected certificate, including discovery and retries.
    pub certificate_timeout: Duration,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            transport: TransportOptions::default(),
            certificate_timeout: Duration::from_secs(600),
        }
    }
}

/// Outcome of one due inventory item; negative observations are never hidden as success.
#[derive(Debug)]
pub enum Outcome {
    /// A CA response updated/preserved the chosen plan and normal recheck schedule.
    Refreshed,
    /// ARI failure or missing/invalid retry guidance retained a plan and fallback recheck.
    RetryScheduled,
    /// Discovered CA does not advertise ARI; the existing fallback is retained.
    Unavailable,
    /// Snapshot eligibility changed while waiting for the certificate lease.
    Skipped,
    /// Storage/discovery or per-certificate execution failed; continue other certificates.
    Failed(IssueError),
    /// User cancellation stopped work; any persisted refresh intent is retained.
    Cancelled,
    /// Cancellation stopped the cycle before opening this item.
    NotStarted,
}

/// Per-certificate result without private material or account signing data.
#[derive(Debug)]
pub struct Entry {
    /// Stable certificate management name.
    pub name: CertificateName,
    /// Exact generation this observation selected.
    pub operation_id: String,
    /// Result classification for this invocation.
    pub outcome: Outcome,
    /// Selected renewal time, when a durable plan was observed.
    pub renew_at: Option<time::OffsetDateTime>,
    /// Persisted next ARI query time, independent of `renew_at`.
    pub next_check_at: Option<time::OffsetDateTime>,
}

/// One finite cycle report; already completed entries survive cancellation.
#[derive(Debug, Default)]
pub struct Report {
    /// Results in deterministic storage order.
    pub entries: Vec<Entry>,
    /// True only for caller cancellation, not an individual certificate timeout.
    pub cancelled: bool,
}

/// Nonblocking product-owned progress sink, used by CLI or embedded hosts.
pub trait Observer: Send + Sync {
    /// Called only when the snapshot contains work, before the first item starts.
    fn started(&self, _items: usize) {}
    /// Called after this entry is complete; final rendering remains caller-owned.
    fn observed(&self, entry: &Entry);
}

/// Refresh due ARI suggestions once. Safe to invoke from cron or another runtime.
/// A query snapshot is revalidated under the same lease used by issue/renew/revoke.
/// Only ARI GETs and directory discovery occur; private account keys are unnecessary.
/// # Errors
/// Returns invalid settings or inventory failures. Per-item failures remain in the report.
/// Each certificate has its own budget; cancellation stops subsequent work while
/// awaiting started storage IO. This function never starts a resident scheduler or installs signal handlers.
pub async fn run_once(
    store: &dyn IssueStore,
    pool: &HttpPool,
    options: &Options,
    cancellation: &CancellationToken,
    observer: Option<&dyn Observer>,
) -> Result<Report, IssueError> {
    options.transport.validate()?;
    if options.certificate_timeout.is_zero()
        || Instant::now()
            .checked_add(options.certificate_timeout)
            .is_none()
    {
        return Err(IssueError::InvalidInput(
            "invalid maintenance certificate timeout",
        ));
    }
    let mut records = store
        .query(IssueQuery {
            in_use: Some(true),
            ari_due_at: Some(time::OffsetDateTime::now_utc()),
            ..IssueQuery::default()
        })
        .await?;
    records.sort_by(|a, b| {
        a.name
            .as_str()
            .cmp(b.name.as_str())
            .then(a.operation_id.cmp(&b.operation_id))
    });
    if let Some(observer) = observer
        && !records.is_empty()
        && !cancellation.is_cancelled()
    {
        observer.started(records.len());
    }
    let mut report = Report {
        cancelled: cancellation.is_cancelled(),
        ..Report::default()
    };
    let mut refresh = RefreshCycle::new(pool, options.transport.clone());
    for record in records {
        let mut entry = Entry {
            name: record.name.clone(),
            operation_id: record.operation_id.clone(),
            outcome: Outcome::NotStarted,
            renew_at: record.renewal.as_ref().map(|p| p.renew_at),
            next_check_at: record.renewal.as_ref().and_then(|p| p.next_check_at),
        };
        if cancellation.is_cancelled() {
            report.cancelled = true;
        } else {
            let context = ExecutionContext {
                cancellation: cancellation.clone(),
                deadline: Instant::now() + options.certificate_timeout,
            };
            let result = refresh_one(store, &record, &mut refresh, &context).await;
            match result {
                Ok((outcome, saved)) => {
                    report.cancelled |= matches!(outcome, Outcome::Cancelled);
                    entry.outcome = outcome;
                    entry.renew_at = saved.renewal.as_ref().map(|p| p.renew_at);
                    entry.next_check_at = saved.renewal.as_ref().and_then(|p| p.next_check_at);
                }
                Err(IssueError::Interrupted) if cancellation.is_cancelled() => {
                    entry.outcome = Outcome::Cancelled;
                    report.cancelled = true;
                }
                Err(error) => entry.outcome = Outcome::Failed(error),
            }
        }
        if let Some(observer) = observer {
            observer.observed(&entry);
        }
        report.entries.push(entry);
    }
    report.cancelled |= cancellation.is_cancelled();
    Ok(report)
}

async fn refresh_one(
    store: &dyn IssueStore,
    snapshot: &IssueRecord,
    refresh: &mut RefreshCycle<'_>,
    execution: &ExecutionContext,
) -> Result<(Outcome, IssueRecord), IssueError> {
    // Do not drop a pending storage future at cancellation: it may own blocking
    // IO. Store lock acquisition is independently bounded; recheck immediately after.
    let mut session = store
        .open_observation(&snapshot.name, &snapshot.operation_id)
        .await?;
    let result = refresh.refresh(session.as_mut(), execution).await;
    let error = match result {
        Ok(result) => {
            let outcome = match result.status {
                RefreshStatus::Refreshed => Outcome::Refreshed,
                RefreshStatus::RetryScheduled => Outcome::RetryScheduled,
                RefreshStatus::Unavailable => Outcome::Unavailable,
                RefreshStatus::Skipped => Outcome::Skipped,
            };
            return Ok((outcome, result.record));
        }
        Err(error) => error,
    };
    // The refresh may have saved retry intent before cancellation. Read durable
    // state while still holding the lease, including on a network/deadline error.
    let saved = session.record().await?;
    let outcome = match error {
        IssueError::Interrupted if execution.cancellation.is_cancelled() => Outcome::Cancelled,
        error => Outcome::Failed(error),
    };
    Ok((outcome, saved))
}
