//! Deployment checkpoint: leased file operations, not business policy.
use crate::issuance::deployment::{DeploymentBinding, DeploymentSession};
use crate::issuance::{
    CertificateName, CliIssueStore, IssueError, failure, selection, write_selection,
};
use aster_acme::deployment::DeploymentPhase;

impl CliIssueStore {
    /// Retain the current issued generation for later deployment without loading secrets.
    /// Password or artifact preparation failures therefore cannot erase pending work.
    ///
    /// # Errors
    /// Rejects stale/ineligible generations, uncertain reloads, missing bindings and IO failures.
    pub async fn queue_deployment(
        &self,
        name: &CertificateName,
        id: &str,
        generation: &str,
    ) -> Result<DeploymentBinding, IssueError> {
        crate::issuance::deployment::validate_id(id)?;
        let slot = self.slot(name);
        let lease = self.lease(name).await?;
        let name = name.clone();
        let id = id.to_owned();
        let generation = generation.to_owned();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let mut config = selection(&slot)?;
            let record = crate::issuance::deployment::session::selected_record(&slot, &name)?;
            if config.cert.name != name
                || !record.deployment_eligible()
                || record.generation_name() != generation
            {
                return Err(failure(
                    "in_use changed before deployment intent could be saved",
                ));
            }
            let binding = config
                .cert
                .deployments
                .iter_mut()
                .find(|item| item.id == id)
                .ok_or_else(|| {
                    failure("deployment binding removed before intent could be saved")
                })?;
            crate::issuance::deployment::configuration::validate_binding(binding)?;
            let mut updated = binding.clone();
            updated.apply_checkpoint(binding.checkpoint().pending(&generation)?);
            if updated != *binding {
                *binding = updated.clone();
                write_selection(&slot, &config)?;
            }
            Ok(updated)
        })
        .await
        .map_err(|_| failure("deployment intent worker failed"))?
    }
}

impl DeploymentSession {
    /// Persist the phase before/after each side effect while still holding the lease.
    ///
    /// # Errors
    /// Returns an error if the selected generation changed, the binding disappeared,
    /// or durable state cannot be written.
    pub async fn save_state(
        &mut self,
        phase: DeploymentPhase,
        attempts: u8,
        error: Option<String>,
    ) -> Result<(), IssueError> {
        let mut updated = self.definition.clone();
        updated.apply_checkpoint(self.definition.checkpoint().observed(
            &self.artifacts.generation,
            phase,
            attempts,
            error,
        ));
        self.persist_binding(updated).await
    }

    /// Save that an issued generation needs deployment, without claiming it was tried.
    ///
    /// # Errors
    /// Rejects uncertain reloads and stale bindings or persistence failures.
    pub async fn save_pending_generation(&mut self, generation: &str) -> Result<(), IssueError> {
        let mut updated = self.definition.clone();
        updated.apply_checkpoint(self.definition.checkpoint().pending(generation)?);
        if updated != self.definition {
            self.persist_binding(updated).await?;
        }
        Ok(())
    }

    /// Restore the complete checkpoint when a recorded intent never started.
    /// The caller must establish that no publication or reload side effect began.
    /// Unlike `save_state`, this retains the original generation and retry state.
    ///
    /// # Errors
    /// Rejects a snapshot with different configuration, stale selection or persistence failure.
    pub async fn restore_checkpoint(
        &mut self,
        previous: &DeploymentBinding,
    ) -> Result<(), IssueError> {
        let mut configuration = previous.clone();
        configuration
            .generation
            .clone_from(&self.definition.generation);
        configuration
            .pending_generation
            .clone_from(&self.definition.pending_generation);
        configuration.phase = self.definition.phase;
        configuration.attempts = self.definition.attempts;
        configuration.retry_failures = self.definition.retry_failures;
        configuration.retry_at = self.definition.retry_at;
        configuration
            .last_error
            .clone_from(&self.definition.last_error);
        if configuration != self.definition {
            return Err(failure(
                "deployment checkpoint configuration does not match this session",
            ));
        }
        self.persist_binding(previous.clone()).await
    }

    pub(super) async fn persist_binding(
        &mut self,
        updated: DeploymentBinding,
    ) -> Result<(), IssueError> {
        let slot = self.slot.clone();
        let name = self.name.clone();
        let id = self.definition.id.clone();
        let operation = self.record.operation_id.clone();
        let expected = self.definition.clone();
        let stored = updated.clone();
        let lease = self.lease.clone();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let mut config = selection(&slot)?;
            if config.cert.name != name || config.cert.in_use.as_deref() != Some(operation.as_str())
            {
                return Err(failure("in_use changed during deployment"));
            }
            let binding = config
                .cert
                .deployments
                .iter_mut()
                .find(|item| item.id == id)
                .ok_or_else(|| failure("deployment binding removed during execution"))?;
            if *binding != expected {
                return Err(failure("deployment checkpoint changed during execution"));
            }
            *binding = stored;
            write_selection(&slot, &config)
        })
        .await
        .map_err(|_| failure("deployment state worker failed"))??;
        self.definition = updated;
        Ok(())
    }

    /// Make a published generation eligible when reload was never started.
    /// This is not a failure and does not increase the retry count.
    ///
    /// # Errors
    /// Returns an error if the selected generation or binding changed, or state cannot persist.
    pub async fn schedule_retry(
        &mut self,
        now: time::OffsetDateTime,
    ) -> Result<DeploymentBinding, IssueError> {
        self.check_attempted_generation()?;
        let mut updated = self.definition.clone();
        updated.apply_checkpoint(self.definition.checkpoint().schedule(now)?);
        self.persist_binding(updated.clone()).await?;
        Ok(updated)
    }

    /// Persist a known deployment failure and its next retry deadline atomically.
    ///
    /// # Errors
    /// Rejects uncertain/nonfailure phases, stale selection and persistence failures.
    pub async fn record_failure(
        &mut self,
        phase: DeploymentPhase,
        attempts: u8,
        error: String,
        now: time::OffsetDateTime,
    ) -> Result<DeploymentBinding, IssueError> {
        self.check_attempted_generation()?;
        let mut updated = self.definition.clone();
        updated.apply_checkpoint(
            self.definition
                .checkpoint()
                .failed(phase, attempts, error, now)?,
        );
        self.persist_binding(updated.clone()).await?;
        Ok(updated)
    }

    fn check_attempted_generation(&self) -> Result<(), IssueError> {
        if self.definition.generation.as_deref() != Some(self.artifacts.generation.as_str()) {
            return Err(failure(
                "deployment checkpoint does not match the selected generation",
            ));
        }
        Ok(())
    }
}
