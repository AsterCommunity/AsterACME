//! TOML file lifecycle: bounded reads, shared lock policy, atomic writes and durable sync.
//! Callers own schemas and edits; configuration preserves trivia, account state is regenerated.

use crate::{AccountStoreError, StorageError, store_error};
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    time::Duration,
};

/// Stable synchronization identity lives outside deletable product directories.
#[derive(Clone, Copy)]
pub(crate) enum ObjectKind {
    Account,
    Certificate,
}

pub(crate) fn object_lock(
    root: &Path,
    kind: ObjectKind,
    name: &str,
) -> Result<PathBuf, AccountStoreError> {
    let category = match kind {
        ObjectKind::Account => "accounts",
        ObjectKind::Certificate => "certificates",
    };
    for directory in [
        root.to_path_buf(),
        root.join(".locks"),
        root.join(".locks").join(category),
    ] {
        fs::create_dir_all(&directory).map_err(|_| store_error("cannot create lock directory"))?;
        ensure_real_dir(&directory)?;
        private_dir(&directory)?;
    }
    Ok(root
        .join(".locks")
        .join(category)
        .join(format!("{name}.lock")))
}

pub(crate) struct FileLease(pub(crate) File);
impl Drop for FileLease {
    fn drop(&mut self) {
        let _ = aster_fs::FileExt::unlock(&self.0);
    }
}
pub(crate) enum LockError {
    Busy,
    Io,
}

pub(crate) fn try_lock(path: &Path) -> Result<File, LockError> {
    let parent = path.parent().ok_or(LockError::Io)?;
    fs::create_dir_all(parent).map_err(|_| LockError::Io)?;
    ensure_real_dir(parent).map_err(|_| LockError::Io)?;
    private_dir(parent).map_err(|_| LockError::Io)?;
    let file = open_lock(path).map_err(|_| LockError::Io)?;
    match aster_fs::FileExt::try_lock(&file) {
        Ok(()) => Ok(file),
        Err(aster_fs::TryLockError::WouldBlock) => Err(LockError::Busy),
        Err(_) => Err(LockError::Io),
    }
}

#[cfg(unix)]
pub(crate) fn open_lock(path: &Path) -> std::io::Result<File> {
    let (directory, name) = state_location(path)?;
    open_state_lock(&directory, name)
}

/// macOS can return ENOENT to the loser of concurrent `O_CREAT | O_NOFOLLOW` opens,
/// even after the winner has created the file. Retry once through the same verified
/// directory descriptor; all no-follow, ownership, and hardlink checks still apply.
#[cfg(unix)]
pub(crate) fn open_state_lock(
    directory: &aster_forge_utils::state_directory::StateDirectory,
    name: &str,
) -> std::io::Result<File> {
    match directory.open_lock(name) {
        #[cfg(target_os = "macos")]
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => directory.open_lock(name),
        result => result,
    }
}
#[cfg(not(unix))]
pub(crate) fn open_lock(_path: &Path) -> std::io::Result<File> {
    Err(std::io::Error::other(
        "private CLI storage currently requires Unix",
    ))
}

#[cfg(unix)]
pub(crate) fn state_location(
    path: &Path,
) -> std::io::Result<(aster_forge_utils::state_directory::StateDirectory, &str)> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing parent"))?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| std::io::Error::other("invalid file name"))?;
    Ok((
        aster_forge_utils::state_directory::StateDirectory::open(parent)?,
        name,
    ))
}

#[cfg(unix)]
pub(crate) fn read_private(path: &Path, max: u64) -> Result<Vec<u8>, StorageError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(StorageError::NotFound);
        }
        Err(_) => return Err(StorageError::Io),
    };
    if metadata.len() > max {
        return Err(StorageError::TooLarge);
    }
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(StorageError::InsecurePath);
    }
    let (directory, name) = state_location(path).map_err(|_| StorageError::InsecurePath)?;
    let limit = aster_forge_utils::numbers::u64_to_usize(max, "state file limit")
        .map_err(|_| StorageError::TooLarge)?;
    directory.read(name, limit).map_err(|_| StorageError::Io)
}
#[cfg(not(unix))]
pub(crate) fn read_private(_path: &Path, _max: u64) -> Result<Vec<u8>, StorageError> {
    Err(StorageError::InsecurePath)
}

#[cfg(unix)]
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing parent"))?;
    fs::create_dir_all(parent)?;
    let (directory, name) = state_location(path)?;
    directory.atomic_write(name, bytes)
}
#[cfg(not(unix))]
pub(crate) fn atomic_write(_path: &Path, _bytes: &[u8]) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "private CLI storage currently requires Unix",
    ))
}

pub(crate) fn ensure_real_dir(path: &Path) -> Result<(), AccountStoreError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| store_error("cannot inspect storage directory"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(store_error("storage path is not a real directory"));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn private_dir(path: &Path) -> Result<(), AccountStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata =
        fs::symlink_metadata(path).map_err(|_| store_error("cannot inspect storage directory"))?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(store_error(
            "storage directory must be owner-controlled and not group/world writable",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| store_error("cannot secure storage directory"))
}
#[cfg(not(unix))]
pub(crate) fn private_dir(_path: &Path) -> Result<(), AccountStoreError> {
    Err(store_error(
        "private CLI storage currently requires Unix; embed a custom AccountStore/AccountKeyStore on other platforms",
    ))
}

/// Acquire the same bounded process lock for configuration edits and account operations.
///
/// # Errors
/// Rejects invalid deadlines, unsafe files, lock timeouts and I/O failures.
pub(crate) fn lock(path: &Path, timeout: Duration) -> io::Result<FileLease> {
    if timeout.is_zero() || timeout > Duration::from_secs(300) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid file lock timeout",
        ));
    }
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match try_lock(path) {
            Ok(file) => return Ok(FileLease(file)),
            Err(LockError::Busy) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(LockError::Busy) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "state file lock timed out",
                ));
            }
            Err(LockError::Io) => return Err(io::Error::other("cannot open state file lock")),
        }
    }
}

/// Update the latest document under its sidecar lock, preserving concurrent edits.
/// A callback error leaves the previous document intact. The blocking task owns the lease
/// through cancellation and syncs both the replacement file and its directory.
///
/// # Errors
/// Reports missing/unsafe files, callback failure, 64 KiB limits, lock timeout or I/O errors.
pub async fn update<F>(path: PathBuf, timeout: Duration, edit: F) -> io::Result<()>
where
    F: FnOnce(&str) -> io::Result<String> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let path = absolute(path)?;
        let _lease = lock(&sidecar(&path)?, timeout)?;
        let bytes = read_text(&path, 65536)?;
        let text = edit(std::str::from_utf8(&bytes).map_err(io::Error::other)?)?;
        write_text(&path, &text, 65536)
    })
    .await
    .map_err(|_| io::Error::other("TOML update worker failed"))?
}

/// Read an existing document byte for byte or initialize it under the same sidecar lock.
///
/// # Errors
/// Rejects unsafe files, invalid deadlines, files/templates over 64 KiB or I/O failures.
pub async fn load_or_create(
    path: PathBuf,
    template: String,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    if timeout.is_zero() || timeout > Duration::from_secs(300) || template.len() > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid TOML file limits",
        ));
    }
    tokio::task::spawn_blocking(move || {
        let path = absolute(path)?;
        match read_text(&path, 65536) {
            Ok(bytes) => return Ok(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let _lease = lock(&sidecar(&path)?, timeout)?;
        match read_text(&path, 65536) {
            Ok(bytes) => Ok(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                write_text(&path, &template, 65536)?;
                Ok(template.into_bytes())
            }
            Err(error) => Err(error),
        }
    })
    .await
    .map_err(|_| io::Error::other("TOML initialization worker failed"))?
}

fn absolute(path: PathBuf) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn sidecar(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("invalid TOML filename"))?;
    Ok(path.with_file_name(format!("{name}.lock")))
}

#[cfg(unix)]
fn read_text(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    // Unlike secrets, user-maintained config may be 0644, but never writable by others.
    let (directory, name) = state_location(path)?;
    directory.read(name, max)
}
#[cfg(not(unix))]
fn read_text(_path: &Path, _max: usize) -> io::Result<Vec<u8>> {
    Err(io::Error::other(
        "private CLI storage currently requires Unix",
    ))
}

/// Atomically replace a bounded UTF-8 document. The caller must hold its operation lease;
/// account operations retain it across network and persistence, configuration across edits.
pub(crate) fn write_text(path: &Path, text: &str, max: usize) -> io::Result<()> {
    if text.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TOML document exceeds size limit",
        ));
    }
    atomic_write(path, text.as_bytes())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    #[tokio::test]
    async fn updates_fail_atomically_and_share_the_initialization_lock() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        load_or_create(
            path.clone(),
            "version=1\n[config]\n".into(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let before = fs::read(&path).unwrap();
        assert!(
            update(path.clone(), Duration::from_secs(1), |_| Err(
                io::Error::other("injected edit failure")
            ))
            .await
            .is_err()
        );
        assert!(
            update(path.clone(), Duration::from_secs(1), |_| Ok(
                "x".repeat(65537)
            ))
            .await
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        let held = lock(
            &path.with_file_name("config.toml.lock"),
            Duration::from_secs(1),
        )
        .unwrap();
        let error = update(path.clone(), Duration::from_millis(20), |text| {
            Ok(text.into())
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(held);
        update(path.clone(), Duration::from_secs(1), |text| {
            Ok(format!("# changed\n{text}"))
        })
        .await
        .unwrap();
        assert!(fs::read_to_string(path).unwrap().starts_with("# changed"));
    }

    #[tokio::test]
    async fn initialization_is_private_concurrent_and_preserves_existing_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/state/config.toml");
        let first = "# Keep this comment\ntimeout = 17 # custom\n";
        let second = "timeout = 42\n";
        let (a, b) = tokio::join!(
            load_or_create(path.clone(), first.into(), Duration::from_secs(1)),
            load_or_create(path.clone(), second.into(), Duration::from_secs(1)),
        );
        let bytes = a.unwrap();
        assert_eq!(b.unwrap(), bytes);
        assert!(bytes == first.as_bytes() || bytes == second.as_bytes());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        // Malformed user TOML must not be repaired or replaced by initialization.
        fs::write(&path, "# intentional\ninvalid = [").unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(
            load_or_create(path.clone(), second.into(), Duration::from_secs(1))
                .await
                .unwrap(),
            before
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn lock_timeout_is_bounded_and_released_for_the_next_initializer() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        let file = open_lock(&temp.path().join("config.toml.lock")).unwrap();
        aster_fs::FileExt::try_lock(&file).unwrap();
        let start = std::time::Instant::now();
        let error = load_or_create(path.clone(), "timeout=30".into(), Duration::from_millis(30))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(30));
        assert!(!path.exists());
        drop(file);
        assert!(
            load_or_create(path, "timeout=30".into(), Duration::from_secs(1))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn size_limits_and_unsafe_files_fail_without_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        for timeout in [Duration::ZERO, Duration::from_secs(301)] {
            assert!(
                load_or_create(path.clone(), String::new(), timeout)
                    .await
                    .is_err()
            );
        }
        assert!(
            load_or_create(path.clone(), "x".repeat(65537), Duration::from_secs(1))
                .await
                .is_err()
        );
        fs::write(&path, "x".repeat(65536)).unwrap();
        assert_eq!(
            load_or_create(path.clone(), String::new(), Duration::from_secs(1))
                .await
                .unwrap()
                .len(),
            65536
        );
        fs::write(&path, "x".repeat(65537)).unwrap();
        assert!(
            load_or_create(path.clone(), String::new(), Duration::from_secs(1))
                .await
                .is_err()
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), 65537);
        fs::remove_file(&path).unwrap();
        let target = temp.path().join("target");
        fs::write(&target, "unchanged").unwrap();
        symlink(&target, &path).unwrap();
        assert!(
            load_or_create(path.clone(), "new".into(), Duration::from_secs(1))
                .await
                .is_err()
        );
        fs::remove_file(&path).unwrap();
        fs::hard_link(&target, &path).unwrap();
        assert!(
            load_or_create(path, "new".into(), Duration::from_secs(1))
                .await
                .is_err()
        );
        assert_eq!(fs::read_to_string(target).unwrap(), "unchanged");
    }
}
