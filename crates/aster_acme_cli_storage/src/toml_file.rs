//! TOML file lifecycle: bounded reads, shared lock policy, atomic writes and durable sync.
//! Callers own schemas and edits; configuration preserves trivia, account state is regenerated.
//!
//! TODO(AsterFs #3/#4): replace only missing safe-file/durability primitives after
//! delivery. Keep TOML edits, limits, lock deadlines and cancellation leases here;
//! Rust 1.89+ standard-library locks need no `AsterFs` compatibility adapter.
//! <https://github.com/AsterCommunity/AsterFs/issues/3>
//! <https://github.com/AsterCommunity/AsterFs/issues/4>

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
        let _ = self.0.unlock();
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
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(LockError::Busy),
        Err(_) => Err(LockError::Io),
    }
}

pub(crate) fn open_lock(path: &Path) -> io::Result<File> {
    let (directory, name) = crate::state_file::location(path)?;
    directory.open_lock(name)
}

pub(crate) fn read_private(path: &Path, max: u64) -> Result<Vec<u8>, StorageError> {
    let limit = aster_forge_utils::numbers::u64_to_usize(max, "state file limit")
        .map_err(|_| StorageError::TooLarge)?;
    crate::state_file::read_private(path, limit).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => StorageError::NotFound,
        io::ErrorKind::InvalidData => StorageError::TooLarge,
        io::ErrorKind::PermissionDenied => StorageError::InsecurePath,
        _ => StorageError::Io,
    })
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("missing parent"))?;
    fs::create_dir_all(parent)?;
    let (directory, name) = crate::state_file::location(path)?;
    directory.atomic_write(name, bytes)
}

pub(crate) fn ensure_real_dir(path: &Path) -> Result<(), AccountStoreError> {
    crate::state_file::ensure_directory(path)
        .map_err(|_| store_error("storage path is not a real directory"))
}

pub(crate) fn private_dir(path: &Path) -> Result<(), AccountStoreError> {
    crate::state_file::prepare_directory(path)
        .map_err(|_| store_error("storage directory is unsafe or inaccessible"))
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

fn read_text(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let (directory, name) = crate::state_file::location(path)?;
    directory.read(name, max)
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
        file.try_lock().unwrap();
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
