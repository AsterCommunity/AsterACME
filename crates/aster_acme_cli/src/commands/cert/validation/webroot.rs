//! HTTP-01 files for an existing server; no listener or ACME protocol work here.
//!
//! Requirements are durable before publication. An operation-specific sibling
//! hard link retains file identity across a crash between publishing and receipt
//! persistence. Cleanup only unlinks an unchanged file with that exact identity;
//! borrowed or replaced files are retained. No directory or unrelated file is removed.
use crate::commands::cert::validation::{
    Arc, ChallengeKind, ChallengeSolver, IssueError, Progress,
};
use crate::common::output::MessageKind;
use aster_acme::{issuance::ValidationRequirement, solver::ExecutionContext};
use aster_acme_cli_storage::state_file;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
#[cfg(not(unix))]
use std::{fs::OpenOptions, io::Write as _};
#[cfg(any(test, not(unix)))]
use std::{
    fs::{self, File},
    io::Read as _,
};

#[cfg(unix)]
mod anchored;
pub(in crate::commands::cert::validation) mod workers;

pub(super) struct Webroot {
    pub(super) workers: workers::Workers,
    pub(super) root: PathBuf,
    pub(super) operation: String,
    pub(super) progress: Arc<Progress>,
}

/// Actual filesystem effects, rather than inferred success text. Borrowed files
/// are never reported as newly written or deleted by this operation.
#[derive(Debug, PartialEq, Eq)]
enum FileAction {
    Published,
    Reused,
    Borrowed,
    Removed,
    Retained,
    Missing,
}
impl FileAction {
    fn message(&self, path: &Path) -> String {
        let verb = match self {
            Self::Published => "Wrote HTTP challenge file",
            Self::Reused => "Reused owned HTTP challenge file",
            Self::Borrowed => "Using preexisting HTTP challenge file",
            Self::Removed => "Removed owned HTTP challenge file",
            Self::Retained => "Retained user-owned HTTP challenge file",
            Self::Missing => "HTTP challenge file already absent",
        };
        format!("{verb}: {}", path.display())
    }
}

#[async_trait]
impl ChallengeSolver for Webroot {
    async fn shutdown(&self) {
        self.workers.shutdown().await;
    }
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::Http01
    }
    async fn ready(
        &self,
        requirements: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        let root = self.root.clone();
        let operation = self.operation.clone();
        let requirements = requirements.to_vec();
        let execution = execution.clone();
        let progress = self.progress.clone();
        self.workers.run(move || {
            for requirement in &requirements {
                execution.check().map_err(|_| IssueError::Interrupted)?;
                let (target, _, _) = paths(&root, &operation, requirement, true)?;
                if let ValidationRequirement::Http01 { url, path, .. } = requirement {
                    tracing::debug!(webroot = %root.display(), local_file = %target.display(), public_url = %url, "HTTP-01 server mapping: serve this local file at the public URL; HTTP port 80 must be reachable, permitted redirects may lead to HTTPS");
                    tracing::debug!(request_path = %path, "Server setup: map /.well-known/acme-challenge/ to this webroot's matching directory; bypass authentication and application rewrites for this location");
                }
                let action = publish(&root, &operation, requirement)?;
                progress.output.progress(MessageKind::Info, &action.message(&target));
            }
            execution.check().map_err(|_| IssueError::Interrupted)?;
            Ok::<_, IssueError>(())
        })
        .await?;
        Ok(true)
    }
    async fn cleanup(
        &self,
        requirements: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        let root = self.root.clone();
        let operation = self.operation.clone();
        let requirements = requirements.to_vec();
        let execution = execution.clone();
        let progress = self.progress.clone();
        self.workers
            .run(move || {
                for requirement in &requirements {
                    execution.check().map_err(|_| IssueError::Interrupted)?;
                    let (target, _, _) = paths(&root, &operation, requirement, false)?;
                    let action = remove_owned(&root, &operation, requirement)?;
                    progress
                        .output
                        .progress(MessageKind::Info, &action.message(&target));
                }
                Ok::<_, IssueError>(())
            })
            .await?;
        self.progress.output.progress(
            MessageKind::Info,
            "HTTP challenge cleanup finished; preexisting or replaced user files were retained",
        );
        Ok(true)
    }
}

fn paths(
    root: &Path,
    operation: &str,
    requirement: &ValidationRequirement,
    create: bool,
) -> Result<(PathBuf, PathBuf, String), IssueError> {
    if !aster_acme_cli_storage::issuance::valid_operation_id(operation) {
        return Err(IssueError::InvalidInput(
            "invalid webroot publication identity",
        ));
    }
    let ValidationRequirement::Http01 { path, content, .. } = requirement else {
        return Err(IssueError::InvalidInput(
            "webroot received another validation method",
        ));
    };
    let token = path
        .strip_prefix("/.well-known/acme-challenge/")
        .ok_or(IssueError::InvalidInput("invalid HTTP challenge path"))?;
    aster_acme::challenge::ChallengeToken::new(token)?;
    if token.len() > 255 || content.len() > 4096 || content.chars().any(char::is_control) {
        return Err(IssueError::InvalidInput(
            "HTTP challenge file exceeds supported bounds",
        ));
    }
    state_file::ensure_directory(root)
        .map_err(|_| IssueError::InvalidInput("webroot is missing or linked"))?;
    #[cfg(unix)]
    if create {
        anchored::prepare(root)?;
    }
    #[cfg(not(unix))]
    prepare_paths(root, create)?;
    let directory = root.join(".well-known/acme-challenge");
    let receipt = format!(
        ".aster-acme-{operation}-{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
    );
    Ok((
        directory.join(token),
        directory.join(receipt),
        content.clone(),
    ))
}

#[cfg(not(unix))]
fn prepare_paths(root: &Path, create: bool) -> Result<(), IssueError> {
    #[cfg(windows)]
    let mut guard = state_file::windows_guard::DirectoryGuard::open(root)
        .map_err(|error| IssueError::Publication(error.to_string()))?;
    let mut directory = root.to_path_buf();
    for part in [".well-known", "acme-challenge"] {
        directory.push(part);
        if create {
            match fs::create_dir(&directory) {
                Ok(()) => {
                    state_file::expose_public_directory(&directory).map_err(|_| {
                        IssueError::InvalidInput("cannot prepare public HTTP directory permissions")
                    })?;
                    state_file::sync_directory(
                        directory
                            .parent()
                            .ok_or(IssueError::InvalidInput("missing HTTP directory parent"))?,
                    )
                    .map_err(|_| IssueError::InvalidInput("cannot sync HTTP directory creation"))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Existing directories may belong to the operator; do not chmod them.
                    // The advisory HTTP precheck determines whether the server can read the result.
                    let _ = error;
                }
                Err(_) => {
                    return Err(IssueError::InvalidInput(
                        "cannot create HTTP challenge directory",
                    ));
                }
            }
        }
        state_file::ensure_directory(&directory).map_err(|_| {
            IssueError::InvalidInput("HTTP challenge directory is missing, linked or unsafe")
        })?;
        #[cfg(windows)]
        guard
            .pin(&directory)
            .map_err(|error| IssueError::Publication(error.to_string()))?;
    }
    Ok(())
}

#[cfg(any(test, not(unix)))]
fn read(path: &Path) -> Result<Option<(File, Vec<u8>)>, IssueError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(IssueError::InvalidInput(
                "cannot inspect HTTP challenge file",
            ));
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
        return Err(IssueError::InvalidInput(
            "HTTP challenge file is linked, oversized or not regular",
        ));
    }
    let mut file = state_file::open_regular(path)
        .map_err(|_| IssueError::InvalidInput("cannot read HTTP challenge file"))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| IssueError::InvalidInput("cannot read HTTP challenge content"))?;
    if bytes.len() > 4096 {
        return Err(IssueError::InvalidInput(
            "HTTP challenge file exceeds size limit",
        ));
    }
    Ok(Some((file, bytes)))
}

#[cfg(unix)]
fn publish(
    root: &Path,
    operation: &str,
    requirement: &ValidationRequirement,
) -> Result<FileAction, IssueError> {
    anchored::publish(root, operation, requirement)
}
#[cfg(unix)]
fn remove_owned(
    root: &Path,
    operation: &str,
    requirement: &ValidationRequirement,
) -> Result<FileAction, IssueError> {
    anchored::remove(root, operation, requirement)
}

#[cfg(windows)]
fn pin_directories(root: &Path) -> Result<state_file::windows_guard::DirectoryGuard, IssueError> {
    let mut guard = state_file::windows_guard::DirectoryGuard::open(root)
        .map_err(|error| IssueError::Publication(error.to_string()))?;
    guard
        .pin(&root.join(".well-known"))
        .and_then(|()| guard.pin(&root.join(".well-known/acme-challenge")))
        .map_err(|error| IssueError::Publication(error.to_string()))?;
    Ok(guard)
}

#[cfg(not(unix))]
fn publish(
    root: &Path,
    operation: &str,
    requirement: &ValidationRequirement,
) -> Result<FileAction, IssueError> {
    let (target, receipt, content) = paths(root, operation, requirement, true)?;
    #[cfg(windows)]
    let _guard = pin_directories(root)?;
    let stage = match OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(&receipt)
    {
        Ok(mut file) => {
            state_file::expose_public_file(&file).map_err(|_| {
                IssueError::InvalidInput("cannot prepare public HTTP file permissions")
            })?;
            file.write_all(content.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_| IssueError::InvalidInput("cannot save HTTP publication ownership"))?;
            file
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let (file, bytes) = read(&receipt)?.ok_or(IssueError::InvalidInput(
                "HTTP ownership record disappeared",
            ))?;
            if bytes != content.as_bytes() {
                return Err(IssueError::InvalidInput(
                    "HTTP ownership file changed; retain it for inspection",
                ));
            }
            file
        }
        Err(_) => {
            return Err(IssueError::InvalidInput(
                "cannot create HTTP publication ownership file",
            ));
        }
    };
    let created = match fs::hard_link(&receipt, &target) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => {
            return Err(IssueError::InvalidInput(
                "cannot publish HTTP file exclusively; webroot must support hard links",
            ));
        }
    };
    state_file::sync_directory(
        target
            .parent()
            .ok_or(IssueError::InvalidInput("missing challenge directory"))?,
    )
    .map_err(|_| IssueError::InvalidInput("cannot sync HTTP publication directory"))?;
    let (file, bytes) = read(&target)?.ok_or(IssueError::InvalidInput(
        "published HTTP challenge disappeared",
    ))?;
    if bytes != content.as_bytes() {
        return Err(IssueError::InvalidInput(
            "HTTP challenge path already contains different content; it was not overwritten",
        ));
    }
    if !state_file::same_file(&stage, &file)
        .map_err(|_| IssueError::InvalidInput("cannot verify HTTP file ownership"))?
    {
        // Identical preexisting content is borrowed. Delete only our private receipt,
        // retaining the user's independently owned file during later cleanup.
        unlink_owned(&receipt, &stage, content.as_bytes())?;
        return Ok(FileAction::Borrowed);
    }
    Ok(if created {
        FileAction::Published
    } else {
        FileAction::Reused
    })
}

#[cfg(not(unix))]
fn remove_owned(
    root: &Path,
    operation: &str,
    requirement: &ValidationRequirement,
) -> Result<FileAction, IssueError> {
    let (target, receipt, content) = paths(root, operation, requirement, false)?;
    #[cfg(windows)]
    let _guard = pin_directories(root)?;
    let Some((stage, bytes)) = read(&receipt)? else {
        return Ok(if target.exists() {
            FileAction::Retained
        } else {
            FileAction::Missing
        });
    };
    if bytes != content.as_bytes() {
        return Err(IssueError::InvalidInput(
            "HTTP publication changed; cleanup retained the files",
        ));
    }
    let mut action = FileAction::Missing;
    if let Some((file, bytes)) = read(&target)? {
        action = FileAction::Retained;
        if bytes != content.as_bytes() {
            return Err(IssueError::InvalidInput(
                "HTTP challenge changed; cleanup retained the files",
            ));
        }
        if state_file::same_file(&stage, &file)
            .map_err(|_| IssueError::InvalidInput("cannot verify cleanup ownership"))?
            && unlink_owned(&target, &file, content.as_bytes())?
        {
            action = FileAction::Removed;
        }
    }
    unlink_owned(&receipt, &stage, content.as_bytes())?;
    Ok(action)
}

// Move the actual path entry into a private sibling directory before checking it.
// This binds deletion to the object moved, not to a prior pathname observation.
#[cfg(any(test, not(unix)))]
fn unlink_owned(path: &Path, expected: &File, content: &[u8]) -> Result<bool, IssueError> {
    let parent = path
        .parent()
        .ok_or(IssueError::InvalidInput("missing HTTP cleanup directory"))?;
    let quarantine = tempfile::Builder::new()
        .prefix(".aster-acme-cleanup-")
        .tempdir_in(parent)
        .map_err(|_| IssueError::InvalidInput("cannot isolate HTTP cleanup"))?;
    #[cfg(windows)]
    let _quarantine_guard = state_file::windows_guard::DirectoryGuard::open(quarantine.path())
        .map_err(|error| IssueError::Publication(error.to_string()))?;
    let moved = quarantine.path().join("entry");
    match fs::rename(path, &moved) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(IssueError::InvalidInput("cannot isolate HTTP cleanup file")),
    }
    let owned = read(&moved).and_then(|actual| match actual {
        Some((actual, bytes)) => Ok(bytes == content
            && state_file::same_file(expected, &actual).map_err(|_| {
                IssueError::InvalidInput("cannot verify isolated cleanup identity")
            })?),
        None => Ok(false),
    });
    if matches!(owned, Ok(true)) {
        fs::remove_file(&moved)
            .map_err(|_| IssueError::InvalidInput("cannot remove isolated owned HTTP file"))?;
        state_file::sync_directory(parent)
            .map_err(|_| IssueError::InvalidInput("cannot sync HTTP cleanup directory"))?;
        return Ok(true);
    }
    // hard_link restores without ever overwriting a concurrently created entry.
    #[cfg(windows)]
    let restore_guard = state_file::windows_guard::pin_regular(&moved);
    #[cfg(windows)]
    let regular = restore_guard.is_ok();
    #[cfg(not(windows))]
    let regular = fs::symlink_metadata(&moved)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink());
    if !regular || fs::hard_link(&moved, path).is_err() {
        let retained = quarantine.keep();
        return Err(IssueError::Publication(format!(
            "HTTP cleanup path changed; retained isolated content at {}",
            retained.display()
        )));
    }
    #[cfg(windows)]
    drop(restore_guard);
    fs::remove_file(&moved)
        .map_err(|_| IssueError::InvalidInput("cannot release restored HTTP cleanup entry"))?;
    state_file::sync_directory(parent)
        .map_err(|_| IssueError::InvalidInput("cannot sync restored HTTP cleanup entry"))?;
    owned.map(|_| false)
}

#[cfg(test)]
mod tests;
