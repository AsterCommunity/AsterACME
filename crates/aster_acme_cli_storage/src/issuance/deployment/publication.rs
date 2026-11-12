//! Prepare the complete artifact set, then replace regular files at stable paths.
//!
//! Preparation never changes a live destination. Commit replaces files individually,
//! so a commit failure can leave a partial set; callers must not reload on failure.
//! No links or directory swaps are used. Dropping a prepared set removes its temporary
//! files on ordinary failure/cancellation; process crashes can leave temporary files.
use crate::issuance::deployment::{
    DeploymentArtifacts, DeploymentPermissions, DeploymentTarget, permissions,
};
use crate::issuance::{IssueError, ensure_real_dir, failure};
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

/// Owns all fully written/synced files until the explicit commit boundary.
pub(super) struct PreparedPublication {
    files: Vec<PreparedFile>,
}

struct PreparedFile {
    destination: PathBuf,
    temporary: NamedTempFile,
}

struct Destination<'a> {
    path: PathBuf,
    contents: &'a [u8],
    mode: Option<u32>,
}

impl PreparedPublication {
    pub(super) fn prepare(
        target: &DeploymentTarget,
        artifacts: &DeploymentArtifacts,
        permissions: &DeploymentPermissions,
    ) -> Result<Self, IssueError> {
        permissions::validate(permissions)?;
        let files = match target {
            DeploymentTarget::Directory { path } => {
                ensure_real_dir(path)
                    .map_err(|error| path_error("inspect target directory", path, &error))?;
                [
                    (
                        "fullchain.pem",
                        artifacts.fullchain.as_slice(),
                        permissions.file_mode,
                    ),
                    (
                        "cert.pem",
                        artifacts.certificate.as_slice(),
                        permissions.file_mode,
                    ),
                    (
                        "ca.pem",
                        artifacts.ca_chain.as_slice(),
                        permissions.file_mode,
                    ),
                    (
                        "private-key.pem",
                        artifacts.private_key.as_slice(),
                        permissions.key_mode,
                    ),
                ]
                .into_iter()
                .map(|(name, contents, mode)| Destination {
                    path: path.join(name),
                    contents,
                    mode,
                })
                .collect()
            }
            DeploymentTarget::Files {
                certificate,
                fullchain,
                ca_chain,
                private_key,
            } => [
                (
                    private_key,
                    artifacts.private_key.as_slice(),
                    permissions.key_mode,
                ),
                (
                    certificate,
                    artifacts.certificate.as_slice(),
                    permissions.file_mode,
                ),
                (
                    fullchain,
                    artifacts.fullchain.as_slice(),
                    permissions.file_mode,
                ),
                (
                    ca_chain,
                    artifacts.ca_chain.as_slice(),
                    permissions.file_mode,
                ),
            ]
            .into_iter()
            .filter_map(|(path, contents, mode)| {
                path.as_ref().map(|path| Destination {
                    path: path.clone(),
                    contents,
                    mode,
                })
            })
            .collect(),
        };
        stage_all(files, stage_file)
    }

    pub(super) fn commit(self) -> Result<(), IssueError> {
        // Recheck the whole set after preparation before replacing the first file.
        // This narrows external path-change races; trusted parent directories are still required.
        for file in &self.files {
            inspect_destination(&file.destination)?;
        }
        for file in self.files {
            inspect_destination(&file.destination)?;
            file.temporary.persist(&file.destination).map_err(|error| {
                path_error("replace destination", &file.destination, &error.error)
            })?;
            let parent = parent(&file.destination)?;
            crate::state_file::sync_directory(parent)
                .map_err(|error| path_error("sync parent directory", &file.destination, &error))?;
        }
        Ok(())
    }
}

/// The collection owns each successfully prepared file before starting the next.
/// Any preparation error therefore drops every temporary file without committing.
fn stage_all(
    files: Vec<Destination<'_>>,
    mut stage: impl FnMut(&Destination<'_>) -> Result<NamedTempFile, IssueError>,
) -> Result<PreparedPublication, IssueError> {
    if files.is_empty() {
        return Err(failure(
            "exact deployment needs at least one file destination",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for file in &files {
        if !seen.insert(&file.path) {
            return Err(failure(
                "deployment destinations must be distinct absolute paths",
            ));
        }
        inspect_destination(&file.path)?;
    }
    let mut prepared = Vec::with_capacity(files.len());
    for file in files {
        let temporary = stage(&file)?;
        prepared.push(PreparedFile {
            destination: file.path,
            temporary,
        });
    }
    Ok(PreparedPublication { files: prepared })
}

fn stage_file(file: &Destination<'_>) -> Result<NamedTempFile, IssueError> {
    let mut temporary = tempfile::Builder::new()
        .prefix(".aster-acme-deploy-")
        .tempfile_in(parent(&file.path)?)
        .map_err(|error| path_error("stage file", &file.path, &error))?;
    temporary
        .write_all(file.contents)
        .map_err(|error| path_error("write file", &file.path, &error))?;
    #[cfg(unix)]
    if let Some(mode) = file.mode {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| path_error("set permissions", &file.path, &error))?;
    }
    #[cfg(not(unix))]
    if file.mode.is_some() {
        return Err(failure("Unix file modes are unsupported on this platform"));
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| path_error("sync file", &file.path, &error))?;
    Ok(temporary)
}

fn inspect_destination(path: &Path) -> Result<(), IssueError> {
    if !path.is_absolute() {
        return Err(failure("deployment path must be absolute"));
    }
    let parent = parent(path)?;
    ensure_real_dir(parent)
        .map_err(|error| path_error("inspect parent directory", parent, &error))?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            Err(failure(&format!(
                "deployment destination is not a regular file: {}",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(path_error("inspect destination", path, &error)),
    }
}

fn parent(path: &Path) -> Result<&Path, IssueError> {
    path.parent()
        .ok_or_else(|| failure("deployment path has no parent"))
}

fn path_error(stage: &str, path: &Path, error: &dyn std::fmt::Display) -> IssueError {
    failure(&format!(
        "deployment {stage} failed at {}: {error}",
        path.display()
    ))
}

#[cfg(test)]
mod tests;
