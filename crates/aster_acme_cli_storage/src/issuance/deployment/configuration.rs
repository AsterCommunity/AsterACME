//! Deployment configuration: leased file operations, not business policy.
use crate::issuance::deployment::session::selected_record;
use crate::issuance::deployment::{
    DeploymentBinding, DeploymentDefinition, DeploymentTarget, permissions, targets, validate_id,
};
use crate::issuance::{
    CertificateName, CliIssueStore, IssueError, failure, selection, write_selection,
};
use aster_acme::deployment::DeploymentPhase;

const MAX_DEPLOYMENTS: usize = 32;
const MAX_RELOAD_WORDS: usize = 64;
impl CliIssueStore {
    /// Persist a deployment binding before its first file or process side effect.
    ///
    /// # Errors
    /// Returns an error for invalid bindings, missing in-use certificates, duplicates,
    /// catalog failures or persistence errors.
    pub async fn add_deployment(
        &self,
        name: &CertificateName,
        definition: DeploymentDefinition,
    ) -> Result<DeploymentBinding, IssueError> {
        let config_lease = self.deployment_config_lease().await?;
        let slot = self.slot(name);
        let lease = self.lease(name).await?;
        let name = name.clone();
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let _config_lease = config_lease;
            let _lease = lease;
            let mut config = selection(&slot)?;
            let current = selected_record(&slot, &name)?;
            if config.cert.name != name || !current.deployment_eligible() {
                return Err(failure(
                    "adding a deployment requires a completed, non-revoked in-use certificate",
                ));
            }
            if config.cert.deployments.len() >= MAX_DEPLOYMENTS {
                return Err(failure("certificate deployment limit reached"));
            }
            let id = allocate_name(definition.name, &config.cert.deployments, || {
                let random = crate::issuance::new_operation_id()?;
                Ok(format!("deploy-{}", &random[..12]))
            })?;
            let binding = DeploymentBinding {
                permissions: definition.permissions,
                id,
                target: definition.target,
                reload_command: definition.reload_command,
                timeout_seconds: definition.timeout_seconds,
                max_retries: definition.max_retries,
                generation: None,
                pending_generation: None,
                phase: DeploymentPhase::Configured,
                attempts: 0,
                retry_failures: 0,
                retry_at: None,
                last_error: None,
            };
            validate_binding(&binding)?;
            targets::check_conflicts(&root, &name, &binding)?;
            config.cert.deployments.push(binding.clone());
            write_selection(&slot, &config)?;
            Ok(binding)
        })
        .await
        .map_err(|_| failure("deployment configuration worker failed"))?
    }

    /// List deployment bindings without reading certificate keys or executing commands.
    ///
    /// # Errors
    /// Returns an error if the certificate lease, catalog or worker fails.
    pub async fn deployments(
        &self,
        name: &CertificateName,
    ) -> Result<Vec<DeploymentBinding>, IssueError> {
        let slot = self.slot(name);
        let _lease = self.lease(name).await?;
        tokio::task::spawn_blocking(move || Ok(selection(&slot)?.cert.deployments))
            .await
            .map_err(|_| failure("deployment listing worker failed"))?
    }

    /// Read one exact binding's local configuration and saved state, without key reads or reload.
    ///
    /// # Errors
    /// Rejects invalid/missing names, unsafe catalogs or lock/worker failures.
    pub async fn deployment(
        &self,
        name: &CertificateName,
        id: &str,
    ) -> Result<DeploymentBinding, IssueError> {
        validate_id(id)?;
        let id = id.to_owned();
        let slot = self.slot(name);
        let lease = self.lease(name).await?;
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            selection(&slot)?
                .cert
                .deployments
                .into_iter()
                .find(|binding| binding.id == id)
                .ok_or_else(|| failure("deployment name not found"))
        })
        .await
        .map_err(|_| failure("deployment lookup worker failed"))?
    }

    /// Remove a binding but leave files it published untouched.
    ///
    /// # Errors
    /// Returns an error if the ID is invalid or missing, or persistence fails.
    pub async fn remove_deployment(
        &self,
        name: &CertificateName,
        id: &str,
    ) -> Result<(), IssueError> {
        validate_id(id)?;
        let id = id.to_owned();
        let slot = self.slot(name);
        let lease = self.lease(name).await?;
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let mut config = selection(&slot)?;
            let count = config.cert.deployments.len();
            config.cert.deployments.retain(|item| item.id != id);
            if count == config.cert.deployments.len() {
                return Err(failure("deployment ID not found"));
            }
            write_selection(&slot, &config)
        })
        .await
        .map_err(|_| failure("deployment removal worker failed"))??;
        Ok(())
    }
}

pub(super) fn validate_binding(binding: &DeploymentBinding) -> Result<(), IssueError> {
    validate_id(&binding.id)?;
    permissions::validate(&binding.permissions)?;
    if binding.reload_command.len() > MAX_RELOAD_WORDS
        || binding.reload_command.first().is_some_and(String::is_empty)
        || binding
            .reload_command
            .iter()
            .any(|word| word.contains('\0') || word.len() > 4096)
    {
        return Err(failure(
            "reload command must contain a program and bounded arguments",
        ));
    }
    if binding.timeout_seconds == 0 || binding.timeout_seconds > 3600 || binding.max_retries > 10 {
        return Err(failure("deployment timeout or retry limit is out of range"));
    }
    match &binding.target {
        DeploymentTarget::Directory { path } if !path.is_absolute() => {
            return Err(failure("deployment directory must be absolute"));
        }
        DeploymentTarget::Files {
            certificate,
            fullchain,
            ca_chain,
            private_key,
            pkcs12,
            pkcs12_password_env,
            pkcs12_password_file,
        } => {
            if certificate.is_none()
                && fullchain.is_none()
                && ca_chain.is_none()
                && private_key.is_none()
                && pkcs12.is_none()
            {
                return Err(failure(
                    "exact deployment needs at least one file destination",
                ));
            }
            let mut seen = std::collections::HashSet::new();
            for path in private_key
                .iter()
                .chain(certificate.iter())
                .chain(fullchain.iter())
                .chain(ca_chain.iter())
                .chain(pkcs12.iter())
            {
                if !path.is_absolute() || !seen.insert(path) {
                    return Err(failure(
                        "deployment destinations must be distinct absolute paths",
                    ));
                }
            }
            if pkcs12.is_none() && (pkcs12_password_env.is_some() || pkcs12_password_file.is_some())
            {
                return Err(failure(
                    "PKCS#12 password sources require a PKCS#12 destination",
                ));
            }
            match (pkcs12_password_env, pkcs12_password_file) {
                (Some(name), None) => {
                    if name.is_empty()
                        || name.len() > super::pkcs12::MAX_PASSWORD_ENV
                        || !name.is_ascii()
                        || name
                            .bytes()
                            .any(|byte| byte.is_ascii_control() || byte == b'=')
                    {
                        return Err(failure(
                            "invalid PKCS#12 password environment variable name",
                        ));
                    }
                }
                (None, Some(path)) => {
                    if !path.is_absolute() {
                        return Err(failure("PKCS#12 password file must be absolute"));
                    }
                }
                (Some(_), Some(_)) => {
                    return Err(failure(
                        "choose one PKCS#12 password source, not both env and file",
                    ));
                }
                (None, None) => {}
            }
        }
        DeploymentTarget::Directory { .. } => {}
    }
    Ok(())
}

pub(super) fn allocate_name(
    explicit: Option<String>,
    existing: &[DeploymentBinding],
    mut generate: impl FnMut() -> Result<String, IssueError>,
) -> Result<String, IssueError> {
    if let Some(id) = explicit {
        validate_id(&id)?;
        if existing.iter().any(|entry| entry.id == id) {
            return Err(failure(
                "deployment name already exists for this certificate",
            ));
        }
        return Ok(id);
    }
    for _ in 0..16 {
        let id = generate()?;
        validate_id(&id)?;
        if !existing.iter().any(|entry| entry.id == id) {
            return Ok(id);
        }
    }
    Err(failure(
        "deployment name allocation exceeded its collision budget",
    ))
}
