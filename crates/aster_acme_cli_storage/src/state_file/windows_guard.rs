//! Windows no-delete sharing pins directories while path-based IO runs below them.
use std::{
    fs::{File, OpenOptions},
    io,
    os::windows::fs::OpenOptionsExt as _,
    path::Path,
};

/// Retained handles deny ancestor rename/deletion until the guard is dropped.
pub struct DirectoryGuard(Vec<File>);
impl DirectoryGuard {
    /// Pin a trusted operator-selected root, rejecting a final reparse point.
    /// # Errors
    /// Reports inaccessible directories, reparse points and sharing conflicts.
    pub fn open(root: &Path) -> io::Result<Self> {
        let mut guard = Self(Vec::new());
        guard.pin(root)?;
        Ok(guard)
    }
    /// Pin the next child while its parent is already held by this guard.
    /// # Errors
    /// Rejects non-directory, reparse or inaccessible objects.
    pub fn pin(&mut self, path: &Path) -> io::Result<()> {
        let mut options = OpenOptions::new();
        // FILE_READ_ATTRIBUTES, FILE_SHARE_READ|WRITE (no DELETE),
        // FILE_FLAG_BACKUP_SEMANTICS|OPEN_REPARSE_POINT. No unsafe FFI needed.
        options
            .access_mode(0x80)
            .share_mode(0x3)
            .custom_flags(0x0220_0000);
        let file = options.open(path)?;
        let info = winapi_util::file::information(&file)?;
        if !file.metadata()?.is_dir() || info.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other(
                "public directory is linked or not a directory",
            ));
        }
        self.0.push(file);
        Ok(())
    }
}

/// Hold a non-reparse regular file against replacement during a hard-link restore.
/// # Errors
/// Rejects links/reparse points, non-files, inaccessible objects and sharing conflicts.
pub fn pin_regular(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).share_mode(0x3).custom_flags(0x0020_0000);
    let file = options.open(path)?;
    let info = winapi_util::file::information(&file)?;
    if !file.metadata()?.is_file() || info.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other(
            "isolated object is not a regular non-reparse file",
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use crate::state_file::windows_guard::*;
    #[test]
    fn pinned_directory_cannot_be_renamed_until_the_guard_releases_it() {
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("child");
        std::fs::create_dir(&child).unwrap();
        let mut guard = DirectoryGuard::open(temp.path()).unwrap();
        guard.pin(&child).unwrap();
        let moved = temp.path().join("moved");
        assert!(std::fs::rename(&child, &moved).is_err());
        drop(guard);
        std::fs::rename(child, moved).unwrap();
    }
}
