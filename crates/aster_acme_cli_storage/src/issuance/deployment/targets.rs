//! Persisted destination ownership: configuration checks are serialized across certificates.
use crate::issuance::deployment::{DeploymentBinding, DeploymentTarget};
use crate::issuance::{
    CertificateName, CliIssueStore, IssueError, failure, managed_file_present, selection,
};
use crate::toml_file::{self, FileLease};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

impl CliIssueStore {
    pub(in crate::issuance::deployment) async fn deployment_config_lease(
        &self,
    ) -> Result<Arc<FileLease>, IssueError> {
        let path = self.root.join(".locks/deployment-config.lock");
        let timeout = self.timeout;
        let lease = tokio::task::spawn_blocking(move || toml_file::lock(&path, timeout))
            .await
            .map_err(|_| failure("deployment ownership lock worker failed"))?
            .map_err(|error| failure(&format!("deployment ownership lock failed: {error}")))?;
        Ok(Arc::new(lease))
    }
}

pub(super) fn paths(target: &DeploymentTarget) -> Vec<PathBuf> {
    match target {
        DeploymentTarget::Directory { path } => {
            ["cert.pem", "private-key.pem", "ca.pem", "fullchain.pem"]
                .map(|file| path.join(file))
                .into()
        }
        DeploymentTarget::Files {
            certificate,
            private_key,
            ca_chain,
            fullchain,
        } => certificate
            .iter()
            .chain(private_key.iter())
            .chain(ca_chain.iter())
            .chain(fullchain.iter())
            .cloned()
            .collect(),
    }
}

fn normalized(path: &Path) -> Result<PathBuf, IssueError> {
    // Resolve ancestor symlinks and '..' even when a destination does not exist yet.
    let filename = path
        .file_name()
        .ok_or_else(|| failure("deployment destination must name a file"))?;
    let parent = path
        .parent()
        .ok_or_else(|| failure("deployment destination has no parent"))?;
    let parent = fs::canonicalize(parent).map_err(|error| {
        failure(&format!(
            "cannot resolve deployment directory {}: {error}",
            parent.display()
        ))
    })?;
    Ok(parent.join(filename))
}

pub(super) fn check_conflicts(
    root: &Path,
    owner: &CertificateName,
    binding: &DeploymentBinding,
) -> Result<(), IssueError> {
    let root_path = fs::canonicalize(root).map_err(|error| failure(&error.to_string()))?;
    let mut wanted = HashSet::new();
    for path in paths(&binding.target) {
        let path = normalized(&path)?;
        if ["accounts", "certs", ".locks"]
            .iter()
            .any(|directory| path.starts_with(root_path.join(directory)))
            || ["config.toml", "config.toml.lock", "crash.log"]
                .iter()
                .any(|file| path == root_path.join(file))
        {
            return Err(failure(
                "deployment destination overlaps managed account/certificate state",
            ));
        }
        if !wanted.insert(path.clone()) {
            return Err(failure(&format!(
                "duplicate deployment destination: {}",
                path.display()
            )));
        }
    }
    let catalog = root.join("certs");
    for (index, item) in fs::read_dir(&catalog)
        .map_err(|error| failure(&error.to_string()))?
        .enumerate()
    {
        if index >= 1024 {
            return Err(failure("deployment ownership catalog exceeds scan limit"));
        }
        let item = item.map_err(|error| failure(&error.to_string()))?;
        if !item
            .file_type()
            .map_err(|error| failure(&error.to_string()))?
            .is_dir()
            || !managed_file_present(&item.path().join("cert.toml"))?
        {
            continue;
        }
        let config = selection(&item.path())?;
        for existing in config.cert.deployments {
            if config.cert.name == *owner && existing.id == binding.id {
                continue;
            }
            for path in paths(&existing.target) {
                // A temporarily unavailable unrelated target must not prevent new configurations.
                let path = normalized(&path).unwrap_or(path);
                if wanted.contains(&path) {
                    return Err(failure(&format!(
                        "deployment destination {} conflicts with certificate '{}' deployment '{}'",
                        path.display(),
                        config.cert.name,
                        existing.id
                    )));
                }
            }
        }
    }
    Ok(())
}
