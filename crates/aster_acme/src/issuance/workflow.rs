//! One invocation owns recovery checks, discovery, optional advice and issuance.
use crate::{
    issuance::{
        IssueError, IssueExecution, IssueIdentity, IssueOutcome, IssueRecord,
        progress::IssueObserver, service::IssueService,
    },
    solver::ChallengeSolver,
    storage::issuance::IssueSession,
    transport::{HttpPool, TransportOptions},
};
use aster_acme_protocol::{directory::Directory, url::AcmeUrl};
use std::sync::Arc;

/// Product-owned discovery and protocol presentation. No global logger is installed.
pub trait WorkflowObserver: IssueObserver {
    /// Discovery is about to perform a read-only directory request.
    fn discovering(&self) {}
    /// Validated directory and saved request, before optional advice/newOrder.
    fn discovered(&self, _directory: &Directory, _record: &IssueRecord) {}
}

/// Composed issuance entry point. Construction and configuration perform no IO.
/// Low-level `HttpPool::discover` and `IssueService` remain independently usable.
pub struct Workflow {
    pool: HttpPool,
    directory: AcmeUrl,
    transport: TransportOptions,
    observer: Option<Arc<dyn WorkflowObserver>>,
}
impl Workflow {
    /// Configure the CA and connection pool; existing registration is supplied at run time.
    /// # Errors
    /// Reports invalid request options without contacting the CA.
    pub fn new(
        pool: HttpPool,
        directory: AcmeUrl,
        transport: TransportOptions,
    ) -> Result<Self, IssueError> {
        transport.validate()?;
        Ok(Self {
            pool,
            directory,
            transport,
            observer: None,
        })
    }
    /// Use one observer for discovery and protocol events.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn WorkflowObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Discover then run issuance, with no implicit local prechecks.
    /// Shutdown is awaited even when recovery/discovery fails or is interrupted.
    /// # Errors
    /// Preserves recovery, transport and issuance errors; cancellation never permits replay.
    pub async fn run(
        &self,
        identity: IssueIdentity,
        session: &mut dyn IssueSession,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) -> Result<IssueOutcome, IssueError> {
        // Keep the invocation's large discovery/protocol state off every
        // embedding caller's async frame; one allocation owns the whole lifecycle.
        let result =
            Box::pin(self.drive(identity, session, solver, execution, async |_, _, _| Ok(())))
                .await;
        solver.shutdown().await;
        result
    }

    /// Explicitly compose a typed advisory check before a new order.
    /// Existing/submitted orders skip this stage, preserving recovery semantics.
    /// # Errors
    /// Returns protocol failures, interruption or invalid checker configuration.
    /// Ordinary negative/failed/timed-out observations remain report entries.
    #[cfg(feature = "precheck")]
    pub async fn run_with_precheck<C: crate::precheck::order::BeforeOrder + ?Sized>(
        &self,
        identity: IssueIdentity,
        session: &mut dyn IssueSession,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
        precheck: &crate::precheck::order::Stage<'_, C>,
    ) -> Result<IssueOutcome, IssueError> {
        // Keep the invocation's large discovery/protocol state off every
        // embedding caller's async frame; one allocation owns the whole lifecycle.
        let result = Box::pin(self.drive(
            identity,
            session,
            solver,
            execution,
            async |directory, record, context| precheck.run(directory, record, context).await,
        ))
        .await;
        solver.shutdown().await;
        result
    }

    async fn drive(
        &self,
        identity: IssueIdentity,
        session: &mut dyn IssueSession,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
        before_order: impl AsyncFnOnce(
            &Directory,
            &IssueRecord,
            &crate::solver::ExecutionContext,
        ) -> Result<(), IssueError>,
    ) -> Result<IssueOutcome, IssueError> {
        let saved = session.record().await?;
        tracing::debug!(operation_id = %saved.operation_id, phase = ?saved.phase, new_order_intent_saved = saved.new_order_intent_saved, has_order_url = saved.order_url.is_some(), "Checking saved request before CA discovery");
        saved.check_recovery(time::OffsetDateTime::now_utc())?;
        execution
            .context
            .check()
            .map_err(|_| IssueError::Interrupted)?;
        if saved.challenge != solver.kind() {
            return Err(IssueError::InvalidInput(
                "challenge solver method does not match saved request",
            ));
        }
        if let Some(observer) = &self.observer {
            observer.discovering();
        }
        let client = tokio::select! {
            biased;
            () = execution.context.cancellation.cancelled() => return Err(IssueError::Interrupted),
            result = tokio::time::timeout_at(execution.context.deadline.into(), self.pool.discover(self.directory.clone(), self.transport.clone())) => Arc::new(result.map_err(|_| IssueError::Interrupted)??),
        };
        let mut service = IssueService::new(client.clone(), identity)?;
        service.check_execution(&saved, solver, execution)?;
        if let Some(observer) = &self.observer {
            observer.discovered(client.directory(), &saved);
            service = service.with_observer(observer.clone());
        }
        // A previously submitted newOrder is not a new request. Do not add DNS
        // dependencies or rerun advice when reconciling its remote outcome.
        if !saved.new_order_intent_saved && saved.order_url.is_none() {
            tokio::select! {
                biased;
                () = execution.context.cancellation.cancelled() => return Err(IssueError::Interrupted),
                result = tokio::time::timeout_at(execution.context.deadline.into(), before_order(client.directory(), &saved, &execution.context)) => result.map_err(|_| IssueError::Interrupted)??,
            };
        }
        execution
            .context
            .check()
            .map_err(|_| IssueError::Interrupted)?;
        service.run_active(session, solver, execution).await
    }
}

#[cfg(test)]
mod tests;
