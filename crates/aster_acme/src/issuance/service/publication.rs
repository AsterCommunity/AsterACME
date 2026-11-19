//! Issuance publication stage.

use crate::challenge::PublicationLifetime;
use crate::issuance::progress::IssueEvent;
use crate::issuance::publication::{checkpoint, cleanup_saved, publication};
use crate::issuance::service::{IssueService, execution::bounded};
use crate::issuance::{IssueError, IssueExecution, IssueOutcome, IssueRecord};
use crate::solver::ChallengeSolver;
use crate::storage::issuance::IssueSession;
use aster_acme_core::protocol::{AuthorizationStatus, OrderStatus};

impl IssueService {
    /// Restart ephemeral publication before the first resumed poll. Ready/valid
    /// orders no longer need a listener, and acknowledged challenges are not acked again.
    pub(super) async fn restore_publication(
        &self,
        session: &dyn IssueSession,
        record: &mut IssueRecord,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) -> Result<(), IssueError> {
        if !record
            .order
            .as_ref()
            .is_some_and(|order| order.status == OrderStatus::Pending)
        {
            return Ok(());
        }
        crate::issuance::publication::prepare(session, record, solver, &execution.context).await?;
        let pending = record
            .authorizations
            .iter()
            .filter(|auth| matches!(auth.resource.status, AuthorizationStatus::Pending))
            .filter(|auth| {
                auth.validation_requirement
                    .as_ref()
                    .is_some_and(|requirement| {
                        requirement.kind().publication_lifetime() == PublicationLifetime::Temporary
                    })
            })
            .map(publication)
            .collect::<Result<Vec<_>, _>>()?;
        if !pending.is_empty()
            && record
                .order
                .as_ref()
                .is_some_and(|order| matches!(order.status, OrderStatus::Pending))
        {
            let result = solver.restore(&pending, &execution.context).await?;
            if checkpoint(record, &result.receipts, result.retry_at)? {
                session.save(record).await?;
            }
            if let Some(error) = result.failure {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Enrich a terminal resource without executing publication or mutations.
    /// The invalid order was already saved; failed detail queries cannot revive it.
    pub(super) async fn invalid_order(
        &self,
        session: &dyn IssueSession,
        record: &mut IssueRecord,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) -> Result<IssueError, IssueError> {
        let order = record
            .order
            .clone()
            .ok_or(IssueError::InvalidInput("missing invalid order"))?;
        if order.error.is_none() {
            for url in &order.authorizations {
                if let Err(error) = bounded(execution, self.authorization(record, url)).await {
                    tracing::debug!("Could not enrich invalid order authorization details");
                    if matches!(error, IssueError::Cancelled | IssueError::TimedOut) {
                        break;
                    }
                }
            }
            session.save(record).await?;
        }
        // The saved invalid order is terminal: no later validation/finalization
        // can succeed, so owned publication can now be withdrawn. Cancellation
        // or cleanup failure must never replace the original CA problem.
        self.cleanup_publication(session, record, solver, execution)
            .await;
        Ok(IssueError::InvalidOrder {
            problem: record.failure_problem().cloned().map(Box::new),
        })
    }

    pub(super) async fn completed(
        &self,
        session: &dyn IssueSession,
        mut record: IssueRecord,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) -> Result<IssueOutcome, IssueError> {
        self.cleanup_publication(session, &mut record, solver, execution)
            .await;
        Ok(crate::issuance::service::response::completed(record))
    }

    /// Shared success/terminal-failure cleanup. Uncertain failures never call this
    /// boundary. Clear pending state only after the adapter and checkpoint save
    /// succeed; otherwise retain recovery evidence and the primary outcome.
    pub(super) async fn cleanup_publication(
        &self,
        session: &dyn IssueSession,
        record: &mut IssueRecord,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) {
        if cleanup_saved(session, record, solver, &execution.context)
            .await
            .is_err()
        {
            self.observe(&IssueEvent::CleanupPending);
        }
    }
}
