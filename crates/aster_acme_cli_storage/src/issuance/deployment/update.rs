//! Atomic patch of binding configuration; updates never publish files or execute reload.
use crate::issuance::deployment::{
    DeploymentBinding, DeploymentPatch, DeploymentPhase, targets, validate_binding, validate_id,
};
use crate::issuance::{
    CertificateName, CliIssueStore, IssueError, failure, selection, write_selection,
};

impl CliIssueStore {
    /// Update selected configuration fields under certificate and destination ownership leases.
    ///
    /// # Errors
    /// Rejects missing bindings, unsafe/conflicting destinations, invalid options and persistence failures.
    pub async fn update_deployment(
        &self,
        name: &CertificateName,
        id: &str,
        patch: DeploymentPatch,
    ) -> Result<DeploymentBinding, IssueError> {
        validate_id(id)?;
        let ownership = self.deployment_config_lease().await?;
        let lease = self.lease(name).await?;
        let slot = self.slot(name);
        let root = self.root.clone();
        let name = name.clone();
        let id = id.to_owned();
        tokio::task::spawn_blocking(move || {
            let _ownership = ownership;
            let _lease = lease;
            let mut config = selection(&slot)?;
            let binding = config
                .cert
                .deployments
                .iter_mut()
                .find(|item| item.id == id)
                .ok_or_else(|| failure("deployment name not found"))?;
            let old = binding.clone();
            if let Some(target) = patch.target {
                binding.target = target;
            }
            if let Some(command) = patch.reload_command {
                binding.reload_command = command;
            }
            if let Some(timeout) = patch.timeout_seconds {
                binding.timeout_seconds = timeout;
            }
            if let Some(retries) = patch.max_retries {
                binding.max_retries = retries;
            }
            if let Some(mode) = patch.permissions.file_mode {
                binding.permissions.file_mode = Some(mode);
            }
            if let Some(mode) = patch.permissions.key_mode {
                binding.permissions.key_mode = Some(mode);
            }
            validate_binding(binding)?;
            targets::check_conflicts(&root, &name, binding)?;
            if *binding != old {
                binding.phase = DeploymentPhase::Configured;
                binding.generation = None;
                binding.attempts = 0;
                binding.last_error = None;
            }
            let updated = binding.clone();
            write_selection(&slot, &config)?;
            Ok(updated)
        })
        .await
        .map_err(|_| failure("deployment update worker failed"))?
    }
}
