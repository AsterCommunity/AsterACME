//! Unix publication resolves the trusted root once and pins every child directory.
use crate::commands::cert::validation::webroot::{FileAction, paths};
use aster_acme::issuance::{IssueError, ValidationRequirement};
use aster_acme_cli_storage::state_file::{self, public_directory::PublicDirectory};
use std::path::Path;

fn directory(root: &Path, create: bool) -> Result<PublicDirectory, IssueError> {
    PublicDirectory::open(root)
        .and_then(|root| root.child(".well-known", create))
        .and_then(|well_known| well_known.child("acme-challenge", create))
        .map_err(error)
}
fn error(error: impl std::fmt::Display) -> IssueError {
    IssueError::Publication(error.to_string())
}

pub(super) fn publish(
    root: &Path,
    operation: &str,
    requirement: &ValidationRequirement,
) -> Result<FileAction, IssueError> {
    let (target, receipt, content) = paths(root, operation, requirement, true)?;
    let directory = directory(root, true)?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(IssueError::InvalidInput("invalid challenge filename"))?;
    let receipt = receipt
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(IssueError::InvalidInput("invalid receipt filename"))?;
    let stage = match directory.create(receipt, content.as_bytes()) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let (file, bytes) =
                directory
                    .read(receipt)
                    .map_err(error)?
                    .ok_or(IssueError::InvalidInput(
                        "HTTP ownership record disappeared",
                    ))?;
            if bytes != content.as_bytes() {
                return Err(IssueError::InvalidInput(
                    "HTTP ownership file changed; retain it for inspection",
                ));
            }
            file
        }
        Err(e) => return Err(error(e)),
    };
    let created = match directory.link(receipt, name) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(error(e)),
    };
    let (file, bytes) = directory
        .read(name)
        .map_err(error)?
        .ok_or(IssueError::InvalidInput(
            "published HTTP challenge disappeared",
        ))?;
    if bytes != content.as_bytes() {
        return Err(IssueError::InvalidInput(
            "HTTP challenge path already contains different content; it was not overwritten",
        ));
    }
    if !state_file::same_file(&stage, &file).map_err(error)? {
        directory
            .remove_owned(receipt, &stage, content.as_bytes())
            .map_err(error)?;
        return Ok(FileAction::Borrowed);
    }
    Ok(if created {
        FileAction::Published
    } else {
        FileAction::Reused
    })
}
pub(super) fn remove(
    root: &Path,
    operation: &str,
    requirement: &ValidationRequirement,
) -> Result<FileAction, IssueError> {
    let (target, receipt, content) = paths(root, operation, requirement, false)?;
    let directory = directory(root, false)?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(IssueError::InvalidInput("invalid challenge filename"))?;
    let receipt = receipt
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(IssueError::InvalidInput("invalid receipt filename"))?;
    let Some((stage, bytes)) = directory.read(receipt).map_err(error)? else {
        return Ok(if directory.read(name).map_err(error)?.is_some() {
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
    if let Some((file, bytes)) = directory.read(name).map_err(error)? {
        if bytes != content.as_bytes() {
            return Err(IssueError::InvalidInput(
                "HTTP challenge changed; cleanup retained the files",
            ));
        }
        action = FileAction::Retained;
        if state_file::same_file(&stage, &file).map_err(error)?
            && directory
                .remove_owned(name, &file, content.as_bytes())
                .map_err(error)?
        {
            action = FileAction::Removed;
        }
    }
    directory
        .remove_owned(receipt, &stage, content.as_bytes())
        .map_err(error)?;
    Ok(action)
}

pub(super) fn prepare(root: &Path) -> Result<(), IssueError> {
    directory(root, true).map(|_| ())
}
