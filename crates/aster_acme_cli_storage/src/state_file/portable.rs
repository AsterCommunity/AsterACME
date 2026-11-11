//! Portable/Windows storage: inherit permissions, reject links, sync files before rename.
//!
//! TODO(AsterFs #3/#4): move reparse/single-link handle validation and explicit Windows
//! replacement/durability guarantees upstream when implemented. Inherited permissions
//! remain supported without dedicated ACL management; do not add another lock API.
//! <https://github.com/AsterCommunity/AsterFs/issues/3>
//! <https://github.com/AsterCommunity/AsterFs/issues/4>
use base64::Engine as _;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

// Windows reparse flags are missing from the stable cross-platform metadata API.
// Keep native constants and checks here until AsterFs #3 provides the primitive.
#[cfg(windows)]
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const REPARSE_POINT: u32 = 0x400;

pub(super) const VIEW_KIND: super::ViewKind = super::ViewKind::Copy;
pub(super) struct Directory {
    path: PathBuf,
}
impl Directory {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        match fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        super::ensure_directory(path)?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
    fn file(&self, name: &str, create: bool) -> io::Result<File> {
        super::ensure_directory(&self.path)?;
        let path = self.path.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_file() || linked(&metadata) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe managed file",
                ));
            }
            Ok(_) => {}
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(create).create(create);
        configure_open(&mut options);
        let file = options.open(path)?;
        check_handle(&file)?;
        Ok(file)
    }
    pub(super) fn open_lock(&self, name: &str) -> io::Result<File> {
        self.file(name, true)
    }
    pub(super) fn read(&self, name: &str, limit: usize) -> io::Result<Vec<u8>> {
        let file = self.file(name, false)?;
        let mut bytes = Vec::new();
        file.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "state document exceeds byte limit",
            ));
        }
        Ok(bytes)
    }
    pub(super) fn atomic_write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        super::ensure_directory(&self.path)?;
        // Existing linked/special destinations are never replaced as managed files.
        match self.file(name, false) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut nonce = [0_u8; 16];
        aws_lc_rs::rand::fill(&mut nonce)
            .map_err(|_| io::Error::other("temporary filename randomness unavailable"))?;
        let temporary = self.path.join(format!(
            ".{name}.{}.tmp",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
        ));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            configure_open(&mut options);
            let mut file = options.open(&temporary)?;
            check_handle(&file)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            // Rust uses the platform's replace-existing rename for regular files.
            fs::rename(&temporary, self.path.join(name))
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

#[cfg(windows)]
fn configure_open(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;
    // Open the final reparse object itself so handle validation cannot follow it.
    options.custom_flags(OPEN_REPARSE_POINT);
}
#[cfg(not(windows))]
fn configure_open(_options: &mut OpenOptions) {}

#[cfg(windows)]
fn check_handle(file: &File) -> io::Result<()> {
    let information = winapi_util::file::information(file)?;
    if !file.metadata()?.is_file()
        || information.file_attributes() & u64::from(REPARSE_POINT) != 0
        || information.number_of_links() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed file must be regular, non-reparse and single-linked",
        ));
    }
    Ok(())
}
#[cfg(not(windows))]
fn check_handle(file: &File) -> io::Result<()> {
    check_private(&file.metadata()?)
}

pub(super) fn check_private(metadata: &Metadata) -> io::Result<()> {
    if !metadata.is_file() || linked(metadata) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe managed file",
        ));
    }
    Ok(())
}
#[cfg(windows)]
pub(super) fn linked(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes() & REPARSE_POINT != 0
}
#[cfg(not(windows))]
pub(super) fn linked(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}
pub(super) fn prepare_directory(path: &Path) -> io::Result<()> {
    super::ensure_directory(path)
}
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    super::ensure_directory(path)
}
pub(super) fn create_view_link(_target: &Path, _path: &Path) -> io::Result<()> {
    Err(io::Error::other(
        "this platform publishes certificate copies",
    ))
}

#[cfg(windows)]
pub(super) fn identity(file: &File) -> io::Result<(u64, u64)> {
    let information = winapi_util::file::information(file)?;
    Ok((information.volume_serial_number(), information.file_index()))
}
#[cfg(not(windows))]
pub(super) fn identity(_file: &File) -> io::Result<(u64, u64)> {
    Err(io::Error::other(
        "stable file identity is unavailable on this platform",
    ))
}

pub(super) fn open_regular(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_open(&mut options);
    let file = options.open(path)?;
    check_private(&file.metadata()?)?;
    Ok(file)
}

pub(super) fn expose_public_file(file: &File) -> io::Result<()> {
    check_private(&file.metadata()?)
}
pub(super) fn expose_public_directory(path: &Path) -> io::Result<()> {
    super::ensure_directory(path)
}
