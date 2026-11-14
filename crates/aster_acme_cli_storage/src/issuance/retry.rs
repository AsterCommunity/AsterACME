//! Compare-and-update renewal failure checkpoints for errors before a generation opens.
use crate::issuance::{CliIssueStore, IssueError, IssueRecord, failure, query, write_journal};
use aster_acme::issuance::RenewalRetryState;
use aster_acme::storage::query::IssueQuery;

impl CliIssueStore {
    /// Record a preparation failure only if the selected generation and retry
    /// snapshot are unchanged. A concurrent success/failure wins over this stale
    /// result; no key or CSR is read and no CA request is sent.
    ///
    /// # Errors
    /// Returns lock, catalog or persistence errors. `None` means no update was due.
    pub async fn record_renewal_preparation_failure(
        &self,
        snapshot: &IssueRecord,
        immediate: bool,
        now: time::OffsetDateTime,
    ) -> Result<Option<RenewalRetryState>, IssueError> {
        let lease = self.lease(&snapshot.name).await?;
        let slot = self.slot(&snapshot.name);
        let root = self.root.join("certs");
        let snapshot = snapshot.clone();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let Some(mut current) = query::read(
                &root,
                &IssueQuery {
                    name: Some(snapshot.name.clone()),
                    in_use: Some(true),
                    ..IssueQuery::default()
                },
            )?
            .pop() else {
                return Ok(None);
            };
            // Compare under the same lease as issue/renew. Do not count the
            // same failed invocation twice or overwrite another worker's result.
            if current.operation_id != snapshot.operation_id
                || current.renewal_retry != snapshot.renewal_retry
                || !current.deployment_eligible()
                || current
                    .renewal
                    .as_ref()
                    .is_none_or(|plan| !immediate && plan.renew_at > now)
                || current.renewal_retry.as_ref().is_some_and(|state| {
                    state.blocked_reason.is_some()
                        || state.ca_retry_at.is_some_and(|at| at > now)
                        || (!immediate && state.retry_at.is_some_and(|at| at > now))
                })
            {
                return Ok(None);
            }
            let state =
                RenewalRetryState::after_failure(current.renewal_retry.as_ref(), now, None, None);
            current.renewal_retry = Some(state.clone());
            write_journal(
                &slot.join(current.generation_name()).join("operation.toml"),
                &current,
            )?;
            Ok(Some(state))
        })
        .await
        .map_err(|_| failure("renewal preparation retry worker failed"))?
    }
}
