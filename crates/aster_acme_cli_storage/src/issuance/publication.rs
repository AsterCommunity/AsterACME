//! Stable certificate view: relative Unix links or a recoverable complete-copy swap.
//!
//! Copy publication never overwrites four live files one by one. A prepared
//! sibling directory is exchanged using a retained previous directory, and the
//! catalog selection decides rollback/cleanup after interruption.
//!
//! TODO(AsterFs #4): evaluate published complete-directory replacement/recovery
//! mechanisms to remove duplicated platform mechanics. ACME still owns the selected
//! generation, catalog commit and rollback decision. Two renames are recoverable,
//! not a cross-platform atomic exchange; preserve that distinction in the public contract.
//! <https://github.com/AsterCommunity/AsterFs/issues/4>
use crate::issuance::{IssueRecord, failure, read_journal};
use crate::{
    state_file::{self, ViewKind},
    toml_file::{atomic_write, ensure_real_dir, private_dir, read_private},
};
use aster_acme::issuance::IssueError;
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Reconcile the visible view against the catalog that actually survived a write.
pub(super) fn recover_selection(slot: &Path) -> Result<(), IssueError> {
    let config = crate::issuance::selection(slot)?;
    let expected = match config.cert.in_use.as_ref() {
        Some(id) => crate::issuance::query::read(
            slot.parent()
                .ok_or_else(|| failure("missing catalog parent"))?,
            &aster_acme::storage::query::IssueQuery {
                name: Some(config.cert.name),
                operation_id: Some(id.clone()),
                ..aster_acme::storage::query::IssueQuery::default()
            },
        )?
        .into_iter()
        .find(|record| &record.operation_id == id)
        .map(|record| record.generation_name())
        .ok_or_else(|| failure("selected certificate generation missing"))
        .map(Some)?,
        None => None,
    };
    NATIVE.recover(slot, expected.as_deref())
}

const FILES: [&str; 4] = ["fullchain.pem", "cert.pem", "ca.pem", "private-key.pem"];
const MARKER: &str = ".generation";
const PREVIOUS: &str = ".in_use.previous";

pub(super) struct Publication {
    pub(super) kind: ViewKind,
}
pub(super) const NATIVE: Publication = Publication {
    kind: state_file::VIEW_KIND,
};

impl Publication {
    pub(super) fn publish(&self, slot: &Path, record: &IssueRecord) -> Result<(), IssueError> {
        let kind = self.kind;
        let active = slot.join("in_use");
        if let Some(target) = self.target(&active)? {
            validate_generation(slot, &target, record)?;
        }
        let stage = slot.join(format!(".in_use-{}", record.operation_id));
        self.remove_empty_copy(&stage)?;
        if let Some(target) = self.target(&stage)? {
            if target != record.generation_name() {
                return Err(failure("publication staging belongs to another generation"));
            }
            self.remove(&stage)?;
        }
        match kind {
            ViewKind::Link => {
                state_file::create_view_link(Path::new(&record.generation_name()), &stage)
                    .map_err(|_| failure("cannot create in_use certificate link"))?;
                fs::rename(&stage, &active)
                    .map_err(|_| failure("cannot publish certificate link"))?;
            }
            ViewKind::Copy => {
                fs::create_dir(&stage).map_err(|_| failure("cannot prepare certificate view"))?;
                private_dir(&stage)?;
                atomic_write(&stage.join(MARKER), record.generation_name().as_bytes())
                    .map_err(|_| failure("cannot identify certificate view"))?;
                for name in FILES {
                    let bytes = zeroize::Zeroizing::new(
                        read_private(&slot.join(record.generation_name()).join(name), 1024 * 1024)
                            .map_err(|_| failure("cannot read complete certificate artifacts"))?,
                    );
                    atomic_write(&stage.join(name), &bytes)
                        .map_err(|_| failure("cannot prepare certificate view artifacts"))?;
                }
                state_file::sync_directory(&stage)
                    .map_err(|_| failure("cannot sync prepared certificate view"))?;
                let backup = slot.join(PREVIOUS);
                if self.target(&backup)?.is_some() {
                    return Err(failure(
                        "unfinished certificate view swap requires recovery",
                    ));
                }
                if self.target(&active)?.is_some() {
                    // Reject unknown user content before moving or deleting a managed view.
                    validate_entries(&active)?;
                    fs::rename(&active, &backup)
                        .map_err(|_| failure("cannot retain previous certificate view"))?;
                    state_file::sync_directory(slot)
                        .map_err(|_| failure("cannot sync previous certificate view"))?;
                }
                if fs::rename(&stage, &active).is_err() {
                    if self.target(&backup)?.is_some() {
                        fs::rename(&backup, &active)
                            .map_err(|_| failure("certificate view rollback requires recovery"))?;
                    }
                    return Err(failure("cannot install prepared certificate view"));
                }
            }
        }
        state_file::sync_directory(slot).map_err(|_| failure("cannot sync certificate publication"))
    }
}

fn validate_generation(slot: &Path, target: &str, record: &IssueRecord) -> Result<(), IssueError> {
    let previous = read_journal(&slot.join(target).join("operation.toml"))?;
    if previous.name != record.name || previous.generation_name() != target {
        return Err(failure("certificate view generation identity mismatch"));
    }
    Ok(())
}

/// Repair a copy swap according to the last durable catalog selection. Read-only
/// inventory does not mutate it; the certificate lease serializes this recovery.
impl Publication {
    pub(super) fn recover(&self, slot: &Path, expected: Option<&str>) -> Result<(), IssueError> {
        if self.kind == ViewKind::Link {
            let active = slot.join("in_use");
            let actual = self.target(&active)?;
            if actual.is_some() && actual.as_deref() != expected {
                match expected {
                    Some(target) => {
                        let record = read_journal(&slot.join(target).join("operation.toml"))?;
                        if record.generation_name() != target {
                            return Err(failure("selected generation identity mismatch"));
                        }
                        self.publish(slot, &record)?;
                    }
                    None => self.remove(&active)?,
                }
            }
            return Ok(());
        }
        self.remove_empty_copy(&slot.join(PREVIOUS))?;
        let active = slot.join("in_use");
        let backup = slot.join(PREVIOUS);
        let current = self.target(&active)?;
        let previous = self.target(&backup)?;
        match (current.as_deref(), previous.as_deref()) {
            (Some(current), Some(_)) if expected == Some(current) => self.remove(&backup)?,
            (current, Some(previous)) if expected == Some(previous) => {
                if current.is_some() {
                    self.remove(&active)?;
                }
                fs::rename(&backup, &active)
                    .map_err(|_| failure("cannot recover previous certificate view"))?;
            }
            (None, Some(_)) => {
                return Err(failure(
                    "previous certificate view does not match selection",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(failure("certificate view swap does not match selection"));
            }
            (Some(_), None) if expected.is_none() => self.remove(&active)?,
            _ => {}
        }
        state_file::sync_directory(slot)
            .map_err(|_| failure("cannot sync recovered certificate view"))
    }

    pub(super) fn matches(&self, slot: &Path, record: &IssueRecord) -> Result<bool, IssueError> {
        let active = slot.join("in_use");
        if self.target(&active)?.as_deref() != Some(record.generation_name().as_str()) {
            return Ok(false);
        }
        if self.kind == ViewKind::Copy {
            for name in FILES {
                let expected = zeroize::Zeroizing::new(
                    read_private(&slot.join(record.generation_name()).join(name), 1024 * 1024)
                        .map_err(|_| failure("selected certificate artifact unavailable"))?,
                );
                let actual = zeroize::Zeroizing::new(
                    read_private(&active.join(name), 1024 * 1024)
                        .map_err(|_| failure("in_use certificate copy unavailable"))?,
                );
                if *actual != *expected {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    pub(super) fn target(&self, path: &Path) -> Result<Option<String>, IssueError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(failure("cannot inspect certificate view")),
        };
        let target = match self.kind {
            ViewKind::Link if metadata.file_type().is_symlink() => {
                fs::read_link(path).map_err(|_| failure("cannot inspect certificate link"))?
            }
            ViewKind::Copy if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                ensure_real_dir(path)?;
                PathBuf::from(
                    String::from_utf8(
                        read_private(&path.join(MARKER), 256)
                            .map_err(|_| failure("certificate copy marker missing or unsafe"))?,
                    )
                    .map_err(|_| failure("invalid certificate copy marker"))?,
                )
            }
            _ => return Err(failure("certificate view is not a managed link/copy")),
        };
        let name = target
            .to_str()
            .ok_or_else(|| failure("invalid certificate view target"))?;
        if target.is_absolute()
            || target.components().count() != 1
            || name == "."
            || name == ".."
            || name.contains(['/', '\\', ':'])
        {
            return Err(failure(
                "certificate view points outside managed generations",
            ));
        }
        Ok(Some(name.to_owned()))
    }
}

fn validate_entries(path: &Path) -> Result<(), IssueError> {
    for entry in fs::read_dir(path).map_err(|_| failure("cannot inspect certificate copy"))? {
        let entry = entry.map_err(|_| failure("cannot inspect certificate copy file"))?;
        let name = entry.file_name();
        if !name
            .to_str()
            .is_some_and(|name| name == MARKER || FILES.contains(&name))
        {
            return Err(failure(
                "certificate view contains user files; refusing replacement or deletion",
            ));
        }
        let _bytes = zeroize::Zeroizing::new(
            read_private(&entry.path(), 1024 * 1024)
                .map_err(|_| failure("unsafe certificate copy file"))?,
        );
    }
    Ok(())
}

impl Publication {
    // Only an empty, real reserved directory is safe without a generation marker.
    // Nonempty unmarked paths remain an error and are never recursively deleted.
    fn remove_empty_copy(&self, path: &Path) -> Result<(), IssueError> {
        if self.kind != ViewKind::Copy {
            return Ok(());
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                ensure_real_dir(path)?;
                if fs::read_dir(path)
                    .map_err(|_| failure("cannot inspect incomplete copy"))?
                    .next()
                    .is_none()
                {
                    fs::remove_dir(path)
                        .map_err(|_| failure("cannot remove empty incomplete copy"))?;
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(failure("cannot inspect incomplete copy")),
        }
        Ok(())
    }

    pub(super) fn remove(&self, path: &Path) -> Result<(), IssueError> {
        if self.target(path)?.is_none() {
            return Ok(());
        }
        match self.kind {
            ViewKind::Link => {
                fs::remove_file(path).map_err(|_| failure("cannot remove certificate link"))
            }
            ViewKind::Copy => {
                validate_entries(path)?;
                for name in FILES.into_iter().chain([MARKER]) {
                    match fs::remove_file(path.join(name)) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => return Err(failure("cannot remove certificate copy file")),
                    }
                }
                fs::remove_dir(path)
                    .map_err(|_| failure("cannot remove certificate copy directory"))
            }
        }
    }
}

#[cfg(test)]
mod tests;
