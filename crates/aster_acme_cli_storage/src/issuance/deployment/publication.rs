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
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};
#[cfg(unix)]
mod anchored;
#[cfg(not(unix))]
mod portable;
#[cfg(unix)]
use crate::issuance::deployment::publication::anchored::{Published, Temporary};
#[cfg(not(unix))]
use crate::issuance::deployment::publication::portable::{Published, Temporary};

/// Owns all fully written/synced files until the explicit commit boundary.
pub(super) struct PreparedPublication {
    files: Vec<PreparedFile>,
}

struct PreparedFile {
    destination: PathBuf,
    temporary: Temporary,
    expected: ExpectedFile,
}

struct ExpectedFile {
    digest: [u8; 32],
    length: u64,
    #[cfg(unix)]
    mode: Option<u32>,
}

struct PublishedFile {
    destination: PathBuf,
    published: Published,
    expected: ExpectedFile,
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
        self.commit_observed(|| {})
    }

    fn commit_observed(self, after_replacement: impl Fn()) -> Result<(), IssueError> {
        // Recheck the whole set after preparation before replacing the first file.
        // Unix IO stays anchored even if a path changes after the last check.
        // Initial resolution and the portable path adapter need trusted ancestors.
        for file in &self.files {
            file.temporary.inspect(&file.destination)?;
        }
        let mut published = Vec::with_capacity(self.files.len());
        for file in self.files {
            let result = file
                .temporary
                .inspect(&file.destination)
                .and_then(|()| file.temporary.persist(&file.destination));
            match result {
                Ok(handle) => published.push(PublishedFile {
                    destination: file.destination,
                    published: handle,
                    expected: file.expected,
                }),
                Err(error) => return Err(partial_error(&published, &error)),
            }
            after_replacement();
        }
        for file in &published {
            file.published
                .verify(&file.destination, &file.expected)
                .map_err(|error| partial_error(&published, &error))?;
        }
        Ok(())
    }
}

fn partial_error(published: &[PublishedFile], error: &IssueError) -> IssueError {
    let paths = published
        .iter()
        .map(|file| file.destination.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    failure(&format!(
        "{error}; replacements completed before failure: [{paths}]; destinations may contain a partial or changed set (the failing replacement may also have taken effect); reload is forbidden; retry the complete set"
    ))
}

fn verify_contents(file: File, expected: &ExpectedFile, path: &Path) -> Result<(), IssueError> {
    let metadata = file
        .metadata()
        .map_err(|error| path_error("verify metadata", path, &error))?;
    if !metadata.is_file() || metadata.len() != expected.length {
        return Err(failure(&format!(
            "deployment verification failed at {}: file type or length changed",
            path.display()
        )));
    }
    #[cfg(unix)]
    if let Some(mode) = expected.mode {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o7777 != mode {
            return Err(failure(&format!(
                "deployment verification failed at {}: permissions changed",
                path.display()
            )));
        }
    }
    let mut digest = Sha256::new();
    let mut reader = file.take(expected.length.saturating_add(1));
    let mut buffer = zeroize::Zeroizing::new([0_u8; 8192]);
    let mut length = 0_u64;
    loop {
        let read = reader
            .read(buffer.as_mut())
            .map_err(|error| path_error("verify contents", path, &error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        length += read as u64;
    }
    if length != expected.length || <[u8; 32]>::from(digest.finalize()) != expected.digest {
        return Err(failure(&format!(
            "deployment verification failed at {}: contents changed",
            path.display()
        )));
    }
    Ok(())
}

/// The collection owns each successfully prepared file before starting the next.
/// Any preparation error therefore drops every temporary file without committing.
fn stage_all(
    files: Vec<Destination<'_>>,
    mut stage: impl FnMut(&Destination<'_>) -> Result<Temporary, IssueError>,
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
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt as _;
            Some(
                temporary
                    .as_file()
                    .metadata()
                    .map_err(|error| path_error("inspect staged permissions", &file.path, &error))?
                    .permissions()
                    .mode()
                    & 0o7777,
            )
        };
        prepared.push(PreparedFile {
            destination: file.path,
            temporary,
            expected: ExpectedFile {
                digest: Sha256::digest(file.contents).into(),
                length: file.contents.len() as u64,
                #[cfg(unix)]
                mode,
            },
        });
    }
    Ok(PreparedPublication { files: prepared })
}

fn stage_file(file: &Destination<'_>) -> Result<Temporary, IssueError> {
    let mut temporary = Temporary::create(&file.path)
        .map_err(|error| path_error("stage file", &file.path, &error))?;
    temporary
        .as_file_mut()
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
