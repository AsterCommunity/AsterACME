//! Persisted destination ownership: configuration checks are serialized across certificates.
use crate::issuance::deployment::{DeploymentBinding, DeploymentTarget};
use crate::issuance::{
    CertificateName, CliIssueStore, IssueError, failure, managed_file_present, selection,
};
use crate::toml_file::{self, FileLease};
use std::{
    collections::HashSet,
    fs, io,
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
            pkcs12,
            ..
        } => certificate
            .iter()
            .chain(private_key.iter())
            .chain(ca_chain.iter())
            .chain(fullchain.iter())
            .chain(pkcs12.iter())
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

fn password_path(path: &Path) -> Result<PathBuf, IssueError> {
    let mut ancestor = path;
    let mut missing = Vec::new();
    loop {
        match fs::canonicalize(ancestor) {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // A missing ordinary component can be compared via its nearest existing
                // ancestor. A dangling link cannot establish ownership and stays an error.
                match fs::symlink_metadata(ancestor) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    _ => return Err(failure("cannot resolve PKCS#12 password file ownership")),
                }
                missing.push(
                    ancestor
                        .file_name()
                        .ok_or_else(|| failure("invalid password path"))?
                        .to_owned(),
                );
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| failure("invalid password parent"))?;
            }
            Err(_) => return Err(failure("cannot resolve PKCS#12 password file ownership")),
        }
    }
}

fn overlaps(left: &Path, right: &Path) -> Result<bool, IssueError> {
    if left == right {
        return Ok(true);
    }
    let open = |path: &Path| match crate::state_file::open_regular(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(failure("cannot inspect deployment/password file identity")),
    };
    match (open(left)?, open(right)?) {
        (Some(left), Some(right)) => crate::state_file::same_file(&left, &right)
            .map_err(|_| failure("cannot compare deployment/password file identity")),
        _ => Ok(false),
    }
}

fn overlaps_any(path: &Path, others: &HashSet<PathBuf>) -> Result<bool, IssueError> {
    for other in others {
        if overlaps(path, other)? {
            return Ok(true);
        }
    }
    Ok(false)
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
    let password_file = match &binding.target {
        DeploymentTarget::Files {
            pkcs12_password_file: Some(path),
            ..
        } => Some(password_path(path)?),
        _ => None,
    };
    if let Some(path) = &password_file
        && overlaps_any(path, &wanted)?
    {
        return Err(failure(
            "deployment destination overlaps its PKCS#12 password file",
        ));
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
            if let DeploymentTarget::Files {
                pkcs12_password_file: Some(path),
                ..
            } = &existing.target
                && overlaps_any(&password_path(path)?, &wanted)?
            {
                return Err(failure(
                    "deployment destination overlaps a PKCS#12 password file",
                ));
            }
            for path in paths(&existing.target) {
                let path = normalized(&path).map_err(|error| failure(&format!(
                    "cannot prove deployment ownership for certificate '{}' deployment '{}': {error}",
                    config.cert.name, existing.id
                )))?;
                if let Some(password) = &password_file
                    && overlaps(password, &path)?
                {
                    return Err(failure(
                        "PKCS#12 password file overlaps a deployment destination",
                    ));
                }
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
