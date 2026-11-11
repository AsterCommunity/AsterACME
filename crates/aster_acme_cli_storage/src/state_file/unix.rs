//! Unix policy preserves anchored Forge IO and existing private-file invariants.
//!
//! TODO(AsterFs #3): centralize owner/mode and descriptor-relative no-follow IO in
//! the filesystem foundation once published, replacing this Forge-backed adapter.
//! <https://github.com/AsterCommunity/AsterFs/issues/3>
use std::{
    fs::{self, File, Metadata},
    io,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
};

pub(super) const VIEW_KIND: super::ViewKind = super::ViewKind::Link;
pub(super) struct Directory {
    inner: aster_forge_utils::state_directory::StateDirectory,
}
impl Directory {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            inner: aster_forge_utils::state_directory::StateDirectory::open(path)?,
        })
    }
    pub(super) fn open_lock(&self, name: &str) -> io::Result<File> {
        // macOS concurrent O_CREAT|O_NOFOLLOW may transiently return ENOENT.
        match self.inner.open_lock(name) {
            #[cfg(target_os = "macos")]
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.inner.open_lock(name),
            result => result,
        }
    }
    pub(super) fn read(&self, name: &str, limit: usize) -> io::Result<Vec<u8>> {
        self.inner.read(name, limit)
    }
    pub(super) fn atomic_write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        self.inner.atomic_write(name, bytes)
    }
}
pub(super) fn linked(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}
pub(super) fn check_private(metadata: &Metadata) -> io::Result<()> {
    if metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed file must be owner-private and single-linked",
        ));
    }
    Ok(())
}
pub(super) fn prepare_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "storage directory must be owner-controlled",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}
pub(super) fn create_view_link(target: &Path, path: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, path)
}
