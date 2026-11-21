//! CLI-owned deployment bindings, artifact publication and reload checkpoints.
use crate::issuance::{CertificateName, IssueError, IssueRecord, failure};
use crate::toml_file::FileLease;
use aster_acme::deployment::DeploymentPhase;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

mod checkpoint;
mod configuration;
mod permissions;
mod pkcs12;
mod publication;
mod session;
mod targets;
mod update;

/// Destination strategy selected through the CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeploymentTarget {
    /// Publish fullchain.pem, cert.pem, ca.pem and private-key.pem in this directory.
    Directory {
        /// Directory receiving every published artifact.
        path: PathBuf,
    },
    /// Publish only the selected artifact paths; every artifact destination is optional.
    Files {
        /// Destination for the leaf certificate in PEM form.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        certificate: Option<PathBuf>,
        /// Destination for the full certificate chain in PEM form.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fullchain: Option<PathBuf>,
        /// Destination for the CA chain (without the leaf) in PEM form.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca_chain: Option<PathBuf>,
        /// Destination for the PEM private key; stored with the key mode policy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        private_key: Option<PathBuf>,
        /// Destination for the PKCS#12 bundle (leaf, chain and private key);
        /// stored with the key mode policy. Password sources are references;
        /// an explicit interactive run may instead supply a transient password.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pkcs12: Option<PathBuf>,
        /// Environment variable holding the PKCS#12 password; the value is
        /// never persisted. Mutually exclusive with `pkcs12_password_file`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pkcs12_password_env: Option<String>,
        /// File whose first line holds the PKCS#12 password, user-managed
        /// and stored 0600. Mutually exclusive with `pkcs12_password_env`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pkcs12_password_file: Option<PathBuf>,
    },
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
    /// A completed issuance generation awaiting automatic publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_generation: Option<String>,
    /// Last durable deployment phase.
    #[serde(default = "configured")]
    pub phase: DeploymentPhase,
    /// Process invocations for the last operation generation.
    #[serde(default)]
    pub attempts: u8,
    /// Consecutive failed deployment invocations for this generation.
    #[serde(default)]
    pub retry_failures: u32,
    /// Earliest automatic retry for this binding and generation.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub retry_at: Option<time::OffsetDateTime>,
    /// Failure context (including paths/OS or exit status); never contains process output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl DeploymentBinding {
    /// Snapshot adapter for the library-owned execution state and admission policy.
    #[must_use]
    pub fn checkpoint(&self) -> aster_acme::deployment::DeploymentCheckpoint {
        aster_acme::deployment::DeploymentCheckpoint {
            generation: self.generation.clone(),
            pending_generation: self.pending_generation.clone(),
            phase: self.phase,
            attempts: self.attempts,
            retry_failures: self.retry_failures,
            retry_at: self.retry_at,
            last_error: self.last_error.clone(),
        }
    }

    fn apply_checkpoint(&mut self, state: aster_acme::deployment::DeploymentCheckpoint) {
        self.generation = state.generation;
        self.pending_generation = state.pending_generation;
        self.phase = state.phase;
        self.attempts = state.attempts;
        self.retry_failures = state.retry_failures;
        self.retry_at = state.retry_at;
        self.last_error = state.last_error;
    }
}

fn configured() -> DeploymentPhase {
    DeploymentPhase::Configured
}

/// Certificate artifact snapshot held only while its generation lease is owned.
pub struct DeploymentArtifacts {
    /// Selected operation generation.
    pub generation: String,
    /// Full certificate chain in PEM form.
    pub fullchain: Vec<u8>,
    /// Leaf certificate in PEM form.
    pub certificate: Vec<u8>,
    /// CA chain (without the leaf) in PEM form.
    pub ca_chain: Vec<u8>,
    /// PEM private key, zeroized when this artifact snapshot is dropped.
    pub private_key: Zeroizing<Vec<u8>>,
    /// PKCS#12 bundle (leaf, chain and private key) when the binding
    /// publishes one; zeroized when this artifact snapshot is dropped.
    pub pkcs12: Option<Zeroizing<Vec<u8>>>,
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

/// Validate a deployment component shared by storage and CLI.
///
/// # Errors
/// Rejects names outside 1–64 ASCII letters, digits, hyphens and underscores.
pub fn validate_id(id: &str) -> Result<(), IssueError> {
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

#[cfg(test)]
mod tests;
