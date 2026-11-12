//! CLI-owned deployment bindings, artifact publication and reload checkpoints.
use crate::issuance::{
    CertificateName, CliIssueStore, IssueError, IssueRecord, ensure_real_dir, failure, selection,
    write_selection,
};
use crate::toml_file::{FileLease, read_private};
use aster_acme::issuance::certificate;
use aster_acme::storage::query::IssueQuery;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

mod permissions;
mod targets;
mod update;

const MAX_DEPLOYMENTS: usize = 32;
const MAX_RELOAD_WORDS: usize = 64;

/// Destination strategy selected through the CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeploymentTarget {
    /// Publish fullchain.pem, cert.pem, ca.pem and private-key.pem in this directory.
    Directory { path: PathBuf },
    /// Publish only the selected artifact paths; every artifact destination is optional.
    Files {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        certificate: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fullchain: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca_chain: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        private_key: Option<PathBuf>,
    },
}

/// Durable deployment phase, independent from issuance and CA order state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPhase {
    Configured,
    Publishing,
    PublishFailed,
    Reloading,
    ReloadFailed,
    ReloadUncertain,
    Deployed,
}

/// Unix permission overrides; absent fields retain the private 0600 default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentPermissions {
    /// Certificate, CA and fullchain mode, restricted to ordinary rwx bits.
    pub file_mode: Option<u32>,
    /// Private-key mode, restricted to ordinary rwx bits.
    pub key_mode: Option<u32>,
}

/// Partial binding update. None preserves each existing setting.
#[derive(Debug, Clone, Default)]
pub struct DeploymentPatch {
    /// Replace the complete destination strategy.
    pub target: Option<DeploymentTarget>,
    /// Replace executable/argv; Some(empty) disables reload.
    pub reload_command: Option<Vec<String>>,
    /// Replace the per-attempt timeout.
    pub timeout_seconds: Option<u64>,
    /// Replace additional reload attempts.
    pub max_retries: Option<u8>,
    /// Optional new permission overrides.
    pub permissions: DeploymentPermissions,
}

/// Configuration input; absent names are allocated under the certificate lease.
#[derive(Debug, Clone)]
pub struct DeploymentDefinition {
    /// Artifact file permission policy.
    pub permissions: DeploymentPermissions,
    /// Optional operator-supplied name, unique within this certificate.
    pub name: Option<String>,
    /// Artifact destination.
    pub target: DeploymentTarget,
    /// Executable and arguments; empty means publication without reload.
    pub reload_command: Vec<String>,
    /// Per-attempt reload timeout.
    pub timeout_seconds: u64,
    /// Additional attempts after a reload failure.
    pub max_retries: u8,
}

/// Per-certificate target. Reload is an executable plus argv; no shell is invoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentBinding {
    /// Artifact file permission policy.
    #[serde(default)]
    pub permissions: DeploymentPermissions,
    /// Operator-chosen unique ID within this certificate.
    pub id: String,
    /// File publication destination.
    pub target: DeploymentTarget,
    /// Executable and arguments; an empty vector means publication without reload.
    pub reload_command: Vec<String>,
    /// Reload process timeout.
    pub timeout_seconds: u64,
    /// Additional attempts after a nonzero exit status.
    pub max_retries: u8,
    /// Last operation generation this target attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    /// Last durable deployment phase.
    #[serde(default = "configured")]
    pub phase: DeploymentPhase,
    /// Process invocations for the last operation generation.
    #[serde(default)]
    pub attempts: u8,
    /// Failure context (including paths/OS or exit status); never contains process output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

fn configured() -> DeploymentPhase {
    DeploymentPhase::Configured
}

/// Certificate artifact snapshot held only while its generation lease is owned.
pub struct DeploymentArtifacts {
    /// Selected operation generation.
    pub generation: String,
    pub fullchain: Vec<u8>,
    pub certificate: Vec<u8>,
    pub ca_chain: Vec<u8>,
    pub private_key: Zeroizing<Vec<u8>>,
}

/// Exclusive deployment operation. The lease serializes renew, remove and deploy.
pub struct DeploymentSession {
    slot: PathBuf,
    name: CertificateName,
    definition: DeploymentBinding,
    record: IssueRecord,
    artifacts: Arc<DeploymentArtifacts>,
    lease: Arc<FileLease>,
}

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
                phase: DeploymentPhase::Configured,
                attempts: 0,
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

    /// Open the current `in_use` generation and hold its certificate lease through reload.
    ///
    /// # Errors
    /// Returns an error if the binding, selected generation or required certificate material
    /// is unavailable or unsafe.
    pub async fn open_deployment(
        &self,
        name: &CertificateName,
        id: &str,
    ) -> Result<DeploymentSession, IssueError> {
        validate_id(id)?;
        let id = id.to_owned();
        let config_lease = self.deployment_config_lease().await?;
        let root = self.root.clone();
        let slot = self.slot(name);
        let lease = self.lease(name).await?;
        let name = name.clone();
        tokio::task::spawn_blocking(move || {
            let _config_lease = config_lease;
            let config = selection(&slot)?;
            let definition = config
                .cert
                .deployments
                .iter()
                .find(|item| item.id == id)
                .cloned()
                .ok_or_else(|| failure("deployment ID not found"))?;
            validate_binding(&definition)?;
            targets::check_conflicts(&root, &name, &definition)?;
            let record = selected_record(&slot, &name)?;
            if !record.deployment_eligible() {
                return Err(failure(
                    "cannot deploy an unfinished or revoked certificate",
                ));
            }
            let generation = record.generation_name();
            let path = slot.join(&generation);
            let fullchain = read_private(&path.join("fullchain.pem"), 1024 * 1024)
                .map_err(|_| failure("fullchain unavailable"))?;
            let private_key = Zeroizing::new(
                read_private(&path.join("private-key.pem"), 128 * 1024)
                    .map_err(|_| failure("private key unavailable"))?,
            );
            let der = Zeroizing::new(
                read_private(&path.join("private-key.pk8"), 64 * 1024)
                    .map_err(|_| failure("certificate key unavailable"))?,
            );
            let artifacts = certificate::artifacts(&fullchain, &der)?;
            Ok(DeploymentSession {
                slot,
                name,
                definition,
                record,
                artifacts: Arc::new(DeploymentArtifacts {
                    generation,
                    fullchain,
                    certificate: artifacts.certificate.into_bytes(),
                    ca_chain: artifacts.ca_chain.into_bytes(),
                    private_key,
                }),
                lease,
            })
        })
        .await
        .map_err(|_| failure("deployment open worker failed"))?
    }
}

impl DeploymentSession {
    #[must_use]
    pub fn definition(&self) -> &DeploymentBinding {
        &self.definition
    }
    #[must_use]
    pub fn artifacts(&self) -> &DeploymentArtifacts {
        &self.artifacts
    }

    /// Publish each artifact by sibling temp file and atomic replacement. A crash
    /// mid-set leaves a durable Publishing phase, so retry rewrites the same version.
    ///
    /// # Errors
    /// Returns an error if a destination is unsafe or any staged file cannot be published.
    pub async fn publish(&self) -> Result<(), IssueError> {
        let target = self.definition.target.clone();
        let permissions = self.definition.permissions.clone();
        let lease = self.lease.clone();
        let artifacts = Arc::clone(&self.artifacts);
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            publish_files(&target, &artifacts, &permissions)
        })
        .await
        .map_err(|_| failure("deployment file worker failed"))?
    }

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
        let slot = self.slot.clone();
        let name = self.name.clone();
        let id = self.definition.id.clone();
        let operation = self.record.operation_id.clone();
        let generation = self.artifacts.generation.clone();
        let mut updated = self.definition.clone();
        updated.generation = Some(generation);
        updated.phase = phase;
        updated.attempts = attempts;
        updated.last_error = error;
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
            *binding = stored;
            write_selection(&slot, &config)
        })
        .await
        .map_err(|_| failure("deployment state worker failed"))??;
        self.definition = updated;
        Ok(())
    }
}

fn publish_files(
    target: &DeploymentTarget,
    bytes: &DeploymentArtifacts,
    permissions: &DeploymentPermissions,
) -> Result<(), IssueError> {
    let key_path = match target {
        DeploymentTarget::Directory { path } => Some(path.join("private-key.pem")),
        DeploymentTarget::Files { private_key, .. } => private_key.clone(),
    };
    let files = match target {
        DeploymentTarget::Directory { path } => {
            ensure_real_dir(path)
                .map_err(|_| failure("deployment target must be an existing real directory"))?;
            vec![
                (path.join("fullchain.pem"), bytes.fullchain.as_slice()),
                (path.join("cert.pem"), bytes.certificate.as_slice()),
                (path.join("ca.pem"), bytes.ca_chain.as_slice()),
                (path.join("private-key.pem"), bytes.private_key.as_slice()),
            ]
        }
        DeploymentTarget::Files {
            certificate,
            fullchain,
            ca_chain,
            private_key,
        } => {
            let mut files = Vec::new();
            for (path, contents) in [
                (private_key, bytes.private_key.as_slice()),
                (certificate, bytes.certificate.as_slice()),
                (fullchain, bytes.fullchain.as_slice()),
                (ca_chain, bytes.ca_chain.as_slice()),
            ] {
                if let Some(path) = path {
                    files.push((path.clone(), contents));
                }
            }
            files
        }
    };
    for (path, _) in &files {
        if !path.is_absolute() {
            return Err(failure("deployment path must be absolute"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| failure("deployment path has no parent"))?;
        ensure_real_dir(parent)
            .map_err(|error| path_error("inspect parent directory", parent, &error))?;
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                return Err(failure(&format!(
                    "deployment destination is not a regular file: {}",
                    path.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(path_error("inspect destination", path, &error)),
        }
    }
    for (path, contents) in files {
        let mode = if key_path.as_deref() == Some(path.as_path()) {
            permissions.key_mode
        } else {
            permissions.file_mode
        };
        atomic_publish(&path, contents, mode)?;
    }
    Ok(())
}

fn atomic_publish(path: &Path, contents: &[u8], mode: Option<u32>) -> Result<(), IssueError> {
    let parent = path
        .parent()
        .ok_or_else(|| failure("deployment path has no parent"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| path_error("stage file", path, &error))?;
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt as _;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| path_error("set permissions", path, &error))?;
    }
    #[cfg(not(unix))]
    if mode.is_some() {
        return Err(failure("Unix file modes are unsupported on this platform"));
    }
    temp.write_all(contents)
        .map_err(|error| path_error("write file", path, &error))?;
    temp.as_file()
        .sync_all()
        .map_err(|error| path_error("sync file", path, &error))?;
    temp.persist(path)
        .map_err(|error| path_error("replace destination", path, &error.error))?;
    crate::state_file::sync_directory(parent)
        .map_err(|error| path_error("sync parent directory", path, &error))?;
    Ok(())
}

fn validate_binding(binding: &DeploymentBinding) -> Result<(), IssueError> {
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
        } => {
            if certificate.is_none()
                && fullchain.is_none()
                && ca_chain.is_none()
                && private_key.is_none()
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
            {
                if !path.is_absolute() || !seen.insert(path) {
                    return Err(failure(
                        "deployment destinations must be distinct absolute paths",
                    ));
                }
            }
        }
        DeploymentTarget::Directory { .. } => {}
    }
    Ok(())
}

fn path_error(stage: &str, path: &Path, error: &dyn std::fmt::Display) -> IssueError {
    failure(&format!(
        "deployment {stage} failed at {}: {error}",
        path.display()
    ))
}

fn allocate_name(
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

fn validate_id(id: &str) -> Result<(), IssueError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(failure("invalid deployment ID"));
    }
    Ok(())
}

fn selected_record(slot: &Path, name: &CertificateName) -> Result<IssueRecord, IssueError> {
    let root = slot
        .parent()
        .ok_or_else(|| failure("certificate directory has no parent"))?;
    crate::issuance::query::read(
        root,
        &IssueQuery {
            name: Some(name.clone()),
            in_use: Some(true),
            ..IssueQuery::default()
        },
    )?
    .pop()
    .ok_or_else(|| failure("certificate has no selected generation"))
}

#[cfg(test)]
mod tests;
