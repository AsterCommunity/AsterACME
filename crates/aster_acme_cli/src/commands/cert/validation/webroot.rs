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
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

pub(super) struct Webroot {
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
        tokio::task::spawn_blocking(move || {
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
        .await
        .map_err(|_| IssueError::InvalidInput("webroot publication worker failed"))??;
        self.progress.output.progress(MessageKind::Info, "HTTP challenge files prepared in webroot; your server must expose them on public port 80");
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
        tokio::task::spawn_blocking(move || {
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
        .await
        .map_err(|_| IssueError::InvalidInput("webroot cleanup worker failed"))??;
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
    let mut directory = root.to_path_buf();
    for part in [".well-known", "acme-challenge"] {
        directory.push(part);
        if create {
            match fs::create_dir(&directory) {
                Ok(()) => state_file::expose_public_directory(&directory).map_err(|_| {
                    IssueError::InvalidInput("cannot prepare public HTTP directory permissions")
                })?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
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
    }
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

fn publish(
    root: &Path,
    operation: &str,
    requirement: &ValidationRequirement,
) -> Result<FileAction, IssueError> {
    let (target, receipt, content) = paths(root, operation, requirement, true)?;
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
        drop(stage);
        fs::remove_file(&receipt).map_err(|_| {
            IssueError::InvalidInput("cannot discard borrowed HTTP publication receipt")
        })?;
        return Ok(FileAction::Borrowed);
    }
    Ok(if created {
        FileAction::Published
    } else {
        FileAction::Reused
    })
}

fn remove_owned(
    root: &Path,
    operation: &str,
    requirement: &ValidationRequirement,
) -> Result<FileAction, IssueError> {
    let (target, receipt, content) = paths(root, operation, requirement, false)?;
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
        {
            drop(file);
            fs::remove_file(&target)
                .map_err(|_| IssueError::InvalidInput("cannot remove owned HTTP challenge file"))?;
            action = FileAction::Removed;
        }
    }
    drop(stage);
    fs::remove_file(receipt)
        .map_err(|_| IssueError::InvalidInput("cannot remove HTTP publication receipt"))?;
    Ok(action)
}

#[cfg(test)]
mod tests;
