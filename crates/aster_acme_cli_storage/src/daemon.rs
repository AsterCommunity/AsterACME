//! Resident daemon process lease, independent of per-certificate transactions.
use crate::toml_file::{self, FileLease, ObjectKind};
use aster_acme::issuance::IssueError;
use std::{path::PathBuf, time::Duration};

/// Exclusive resident process for a state root. Drop releases the OS lock;
/// the lock file remains in place so waiters keep a stable synchronization identity.
pub struct DaemonLease {
    _lease: FileLease,
}

impl DaemonLease {
    /// Acquire one resident daemon per data directory, without loading certificate keys.
    /// Foreground commands and run-once use the existing account/certificate leases.
    ///
    /// # Errors
    /// Reports contention separately from unsafe paths, invalid timeout and I/O errors.
    pub async fn acquire(root: PathBuf, timeout: Duration) -> Result<Self, IssueError> {
        tokio::task::spawn_blocking(move || {
            let path = toml_file::object_lock(&root, ObjectKind::Daemon, "instance")?;
            let lease = toml_file::lock(&path, timeout).map_err(|error| {
                if error.kind() == std::io::ErrorKind::TimedOut {
                    IssueError::LeaseUnavailable("daemon", error.to_string())
                } else {
                    IssueError::Store(crate::account::store_error("daemon lock failed"))
                }
            })?;
            Ok(Self { _lease: lease })
        })
        .await
        .map_err(|_| IssueError::Store(crate::account::store_error("daemon lock worker failed")))?
    }
}

#[cfg(test)]
mod tests;
