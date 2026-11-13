//! One finite maintenance cycle for external schedulers and future daemon loops.
use crate::{
    issuance::{CertificateName, IssueError, IssueRecord},
    renewal::refresh::{RefreshCycle, RefreshStatus},
    solver::ExecutionContext,
    storage::{
        issuance::IssueStore,
        query::{IssueQuery, IssueView},
    },
    transport::{HttpPool, TransportOptions},
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Host-owned certificate operations invoked after the library selects stable candidates.
/// Implementations perform protocol-specific issuance and host-specific deployment effects;
/// storage sessions remain responsible for lease acquisition and under-lease revalidation.
#[async_trait::async_trait(?Send)]
pub trait AutomaticTasks {
    /// Result type rendered by the embedding host for one renewal batch.
    type Renewals;
    /// Result type rendered by the embedding host for deployment retries.
    type Deployments;

    /// Renew the supplied due snapshot. Per-certificate eligibility may depend on host solvers.
    async fn renew(
        &self,
        candidates: Vec<IssueRecord>,
        cancellation: &CancellationToken,
    ) -> Self::Renewals;

    /// Retry deployments for certificates with configured deployment bindings.
    async fn deploy(
        &self,
        candidates: Vec<IssueRecord>,
        cancellation: &CancellationToken,
    ) -> Self::Deployments;
}

/// A maintenance stage skipped because an earlier stage was cancelled.
#[derive(Debug)]
pub enum Stage<T> {
    /// Stage was not started.
    NotRun,
    /// Stage completed and produced the host's report.
    Completed(T),
}

/// Ordered ARI, renewal and deployment results for one external-scheduler invocation.
pub struct CycleReport<R, D> {
    /// ARI refresh outcomes.
    pub ari: Report,
    /// Automatic renewal outcomes.
    pub renewals: Stage<R>,
    /// Known deployment retry outcomes.
    pub deployments: Stage<D>,
}

/// Run ARI refresh, due automatic renewals, then retries for configured deployments.
/// Candidate inventories are queried by the library between stages, so a successful
/// renewal is visible to the deployment stage. Host callbacks execute effects only.
/// # Errors
/// Returns invalid settings or inventory query failures; per-item results remain in reports.
pub async fn run_cycle<T: AutomaticTasks>(
    store: &dyn IssueStore,
    pool: &HttpPool,
    options: &Options,
    cancellation: &CancellationToken,
    observer: Option<&dyn Observer>,
    tasks: &T,
) -> Result<CycleReport<T::Renewals, T::Deployments>, IssueError> {
    let ari = run_once(store, pool, options, cancellation, observer).await?;
    if cancellation.is_cancelled() {
        return Ok(CycleReport {
            ari,
            renewals: Stage::NotRun,
            deployments: Stage::NotRun,
        });
    }

    let mut renewals = store
        .query(IssueQuery {
            in_use: Some(true),
            renewal_due_at: Some(time::OffsetDateTime::now_utc()),
            ..IssueQuery::default()
        })
        .await?;
    renewals.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
    let renewal_results = tasks.renew(renewals, cancellation).await;
    if cancellation.is_cancelled() {
        return Ok(CycleReport {
            ari,
            renewals: Stage::Completed(renewal_results),
            deployments: Stage::NotRun,
        });
    }

    let mut deployments = store
        .query(IssueQuery {
            view: IssueView::Managed,
            in_use: Some(true),
            ..IssueQuery::default()
        })
        .await?;
    deployments.retain(|record| record.deployment_count.is_some_and(|count| count > 0));
    deployments.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
    let deployment_results = tasks.deploy(deployments, cancellation).await;
    Ok(CycleReport {
        ari,
        renewals: Stage::Completed(renewal_results),
        deployments: Stage::Completed(deployment_results),
    })
}

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

#[cfg(test)]
mod tests {
    use crate::{
        account::AccountRecord,
        issuance::{CertificateName, IssueError, IssueRecord, IssueRequest},
        maintenance::{AutomaticTasks, Options, Stage, run_cycle},
        storage::{
            issuance::{IssueSession, IssueStore},
            query::IssueQuery,
        },
        transport::HttpPool,
    };
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};
    use tokio_util::sync::CancellationToken;

    struct Store(Mutex<Vec<&'static str>>);

    #[async_trait]
    impl IssueStore for Store {
        async fn create(
            &self,
            _: &IssueRequest,
            _: &AccountRecord,
        ) -> Result<Box<dyn IssueSession>, IssueError> {
            Err(IssueError::InvalidInput("unused test operation"))
        }

        async fn renew(
            &self,
            _: &CertificateName,
            _: &AccountRecord,
        ) -> Result<Box<dyn IssueSession>, IssueError> {
            Err(IssueError::InvalidInput("unused test operation"))
        }

        async fn open(
            &self,
            _: &CertificateName,
            _: &str,
        ) -> Result<Box<dyn IssueSession>, IssueError> {
            Err(IssueError::InvalidInput("unused test operation"))
        }

        async fn open_observation(
            &self,
            _: &CertificateName,
            _: &str,
        ) -> Result<Box<dyn IssueSession>, IssueError> {
            Err(IssueError::InvalidInput("unused test operation"))
        }

        async fn query(&self, query: IssueQuery) -> Result<Vec<IssueRecord>, IssueError> {
            let stage = if query.ari_due_at.is_some() {
                "ari-query"
            } else if query.renewal_due_at.is_some() {
                "renewal-query"
            } else {
                "deployment-query"
            };
            self.0.lock().unwrap().push(stage);
            Ok(Vec::new())
        }
    }

    struct Tasks {
        events: Arc<Mutex<Vec<&'static str>>>,
        cancellation: CancellationToken,
        cancel_after_renewal: bool,
    }

    #[async_trait(?Send)]
    impl AutomaticTasks for Tasks {
        type Renewals = ();
        type Deployments = ();

        async fn renew(&self, _: Vec<IssueRecord>, _: &CancellationToken) {
            self.events.lock().unwrap().push("renew");
            if self.cancel_after_renewal {
                self.cancellation.cancel();
            }
        }

        async fn deploy(&self, _: Vec<IssueRecord>, _: &CancellationToken) {
            self.events.lock().unwrap().push("deploy");
        }
    }

    #[tokio::test]
    async fn cycle_owns_stage_order_and_requeries_deployment_candidates_after_renewal() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let store = Store(Mutex::new(Vec::new()));
        let cancellation = CancellationToken::new();
        let tasks = Tasks {
            events: Arc::clone(&calls),
            cancellation: cancellation.clone(),
            cancel_after_renewal: false,
        };
        let report = run_cycle(
            &store,
            &HttpPool::default(),
            &Options::default(),
            &cancellation,
            None,
            &tasks,
        )
        .await
        .unwrap();
        assert!(matches!(report.renewals, Stage::Completed(())));
        assert!(matches!(report.deployments, Stage::Completed(())));
        assert_eq!(
            *store.0.lock().unwrap(),
            ["ari-query", "renewal-query", "deployment-query"]
        );
        assert_eq!(*calls.lock().unwrap(), ["renew", "deploy"]);
    }

    #[tokio::test]
    async fn cancellation_between_stages_never_starts_deployment_retry() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let store = Store(Mutex::new(Vec::new()));
        let cancellation = CancellationToken::new();
        let tasks = Tasks {
            events: Arc::clone(&calls),
            cancellation: cancellation.clone(),
            cancel_after_renewal: true,
        };
        let report = run_cycle(
            &store,
            &HttpPool::default(),
            &Options::default(),
            &cancellation,
            None,
            &tasks,
        )
        .await
        .unwrap();
        assert!(matches!(report.deployments, Stage::NotRun));
        assert_eq!(*store.0.lock().unwrap(), ["ari-query", "renewal-query"]);
        assert_eq!(*calls.lock().unwrap(), ["renew"]);
    }
}
