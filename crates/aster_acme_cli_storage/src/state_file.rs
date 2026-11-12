//! Platform boundary for managed files, locks and publication durability.
//!
//! Unix retains owner/mode checks and descriptor-anchored Forge IO. Windows uses
//! inherited filesystem permissions without managing ACLs, and rejects reparse
//! points and hard-linked managed files. Callers never choose a platform branch.
//!
//! TODO(AsterFs #3/#4): replace this interim platform adapter with delivered safe-open,
//! file-identity and explicit durability APIs. Standard-library operations must not
//! gain a forwarding facade solely for dependency uniformity; Windows ACL management
//! is optional. Remove direct rustix/winapi-util use only when the required APIs exist.
//! <https://github.com/AsterCommunity/AsterFs/issues/3>
//! <https://github.com/AsterCommunity/AsterFs/issues/4>
use std::{
    fs::{self, File},
    io,
    path::Path,
};

#[cfg(unix)]
#[path = "state_file/unix.rs"]
mod platform;
#[cfg(not(unix))]
#[path = "state_file/portable.rs"]
mod platform;

/// Verified directory with one filename policy shared by config, secrets and reports.
pub struct StateDirectory(platform::Directory);
impl StateDirectory {
    /// Open/create an application-controlled directory without following its final link.
    /// Windows retains inherited permissions; Unix additionally enforces owner control.
    ///
    /// # Errors
    /// Rejects linked/unsafe directories and filesystem errors.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self(platform::Directory::open(path.as_ref())?))
    }

    /// Open a non-truncating lock/report file and validate the actual file handle.
    ///
    /// # Errors
    /// Rejects links, invalid names and unsuitable files.
    pub fn open_lock(&self, name: &str) -> io::Result<File> {
        validate_name(name)?;
        self.0.open_lock(name)
    }

    /// Open an owner-private file on Unix, or an inherited-permission file on Windows.
    ///
    /// # Errors
    /// Returns path, permission or file errors without changing an existing file.
    pub fn open_private(&self, name: &str) -> io::Result<File> {
        let file = self.open_lock(name)?;
        platform::check_private(&file.metadata()?)?;
        Ok(file)
    }

    /// Read a bounded regular file. Config may be user-readable on Unix.
    ///
    /// # Errors
    /// Rejects unsafe names/files, oversized content and IO failures.
    pub fn read(&self, name: &str, maximum: usize) -> io::Result<Vec<u8>> {
        validate_name(name)?;
        if maximum == 0 {
            return Err(io::Error::other("state read limit must be positive"));
        }
        self.0.read(name, maximum)
    }

    /// Replace one complete file using a synced sibling temporary file.
    /// Unix also syncs the parent directory. Windows guarantees process-level
    /// replacement/recovery only; successful return does not promise rename durability
    /// across power loss because parent-directory flushing is unavailable here.
    ///
    /// # Errors
    /// Keeps the previous file on failed write/rename; rejects unsafe names and paths.
    pub fn atomic_write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        validate_name(name)?;
        self.0.atomic_write(name, bytes)
    }
}

/// Validate directories before entering or enumerating managed storage.
///
/// # Errors
/// Rejects links/reparse points and non-directory objects.
pub fn ensure_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || platform::linked(&metadata) {
        return Err(io::Error::other("storage path is not a real directory"));
    }
    Ok(())
}

/// Apply the platform's directory policy; Windows intentionally inherits its ACL.
///
/// # Errors
/// Reports path/permission failures without weakening Unix checks.
pub fn prepare_directory(path: &Path) -> io::Result<()> {
    ensure_directory(path)?;
    platform::prepare_directory(path)
}

/// Read a secret without creating a missing file.
///
/// # Errors
/// Rejects links, unsafe permissions, oversized files and IO errors.
pub fn read_private(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || platform::linked(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe managed file",
        ));
    }
    platform::check_private(&metadata)?;
    if metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed file exceeds size limit",
        ));
    }
    let (directory, name) = location(path)?;
    directory.read(name, maximum)
}

/// Locate a single component inside its verified parent.
///
/// # Errors
/// Rejects missing parents, invalid names and unsafe directories.
pub fn location(path: &Path) -> io::Result<(StateDirectory, &str)> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("missing parent"))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::other("invalid file name"))?;
    validate_name(name)?;
    Ok((StateDirectory::open(parent)?, name))
}

/// Flush directory metadata where supported. Windows file writes are flushed before
/// rename; std does not expose portable directory flush, so it verifies the directory.
///
/// # Errors
/// Reports unavailable/unsafe directories or an actual Unix directory sync failure.
pub fn sync_directory(path: &Path) -> io::Result<()> {
    ensure_directory(path)?;
    platform::sync_directory(path)
}

/// Give a newly created public validation file read permissions on Unix.
/// Callers must only use this for public material they created, never existing user files.
/// Windows retains inherited ACLs.
///
/// # Errors
/// Reports unsupported permissions or IO failures.
pub fn expose_public_file(file: &File) -> io::Result<()> {
    platform::expose_public_file(file)
}

/// Prepare permissions on a newly created public validation directory.
///
/// # Errors
/// Rejects linked/non-directory paths and permission failures.
pub fn expose_public_directory(path: &Path) -> io::Result<()> {
    ensure_directory(path)?;
    platform::expose_public_directory(path)
}

/// Open a regular published file without following its final symbolic/reparse link.
/// Unlike private state reads this permits public permissions and hard links used
/// as publication ownership receipts; the caller controls/trusts ancestor directories.
///
/// # Errors
/// Rejects final links, special files and inaccessible paths.
pub fn open_regular(path: &Path) -> io::Result<File> {
    platform::open_regular(path)
}

/// Compare already-open handles without relying on path spelling or timestamps.
/// Useful when a publication adapter must prove it still owns a file before removal.
///
/// # Errors
/// Reports unavailable platform identity information or invalid handles.
pub fn same_file(left: &File, right: &File) -> io::Result<bool> {
    Ok(platform::identity(left)? == platform::identity(right)?)
}

/// Unix publishes a relative symlink; platforms without unprivileged symlinks use copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ViewKind {
    Link,
    Copy,
}
pub(crate) const VIEW_KIND: ViewKind = platform::VIEW_KIND;

pub(crate) fn create_view_link(target: &Path, path: &Path) -> io::Result<()> {
    platform::create_view_link(target, path)
}

fn validate_name(name: &str) -> io::Result<()> {
    if !aster_acme_core::local_name::valid_component(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid or reserved managed filename",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(unix)]
pub mod public_directory;

#[cfg(windows)]
pub mod windows_guard;
