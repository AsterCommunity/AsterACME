//! Portable state file contracts shared by native CI targets.
use super::*;
#[test]
fn private_read_atomic_replace_and_nontruncating_lock() {
    let temp = tempfile::tempdir().unwrap();
    let directory = StateDirectory::open(temp.path()).unwrap();
    directory.atomic_write("state.toml", b"first").unwrap();
    directory.atomic_write("state.toml", b"second").unwrap();
    assert_eq!(
        read_private(&temp.path().join("state.toml"), 6).unwrap(),
        b"second"
    );
    assert!(read_private(&temp.path().join("state.toml"), 5).is_err());
    assert!(directory.read("missing", 8).is_err());
    assert!(!temp.path().join("missing").exists());
    directory.open_lock("state.toml").unwrap();
    assert_eq!(directory.read("state.toml", 6).unwrap(), b"second");
    for name in [
        "../key",
        "C:key",
        "dir/key",
        "dir\\key",
        "CON",
        "NUL.txt",
        "COM1",
        "trailing.",
    ] {
        assert!(directory.atomic_write(name, b"bad").is_err(), "{name}");
    }
}

/// Compare the actual file identity, not its path spelling, when proving stable lock reuse.
#[cfg(unix)]
pub(crate) fn file_identity(path: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}
#[cfg(windows)]
pub(crate) fn file_identity(path: &Path) -> (u64, u64) {
    let file = File::open(path).unwrap();
    let information = winapi_util::file::information(&file).unwrap();
    (information.volume_serial_number(), information.file_index())
}

#[test]
fn standard_lock_child() {
    let Some(path) = std::env::var_os("ASTER_TEST_STD_LOCK_PATH") else {
        return;
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    match file.try_lock() {
        Ok(()) => {
            file.unlock().unwrap();
        }
        Err(std::fs::TryLockError::WouldBlock) => std::process::exit(73),
        Err(std::fs::TryLockError::Error(error)) => panic!("unexpected OS lock failure: {error}"),
    }
}

#[test]
fn standard_library_locks_exclude_another_process_and_release_without_truncation() {
    let temp = tempfile::tempdir().unwrap();
    let directory = StateDirectory::open(temp.path()).unwrap();
    directory
        .atomic_write("operation.lock", b"sentinel")
        .unwrap();
    let file = directory.open_lock("operation.lock").unwrap();
    file.try_lock().unwrap();
    let path = temp.path().join("operation.lock");
    let run = || {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "state_file::tests::standard_lock_child"])
            .env("ASTER_TEST_STD_LOCK_PATH", &path)
            .output()
            .unwrap()
    };
    assert_eq!(run().status.code(), Some(73));
    file.unlock().unwrap();
    assert!(run().status.success());
    assert_eq!(fs::read(path).unwrap(), b"sentinel");
}

#[test]
fn managed_hard_links_are_rejected_without_modifying_the_target() {
    let temp = tempfile::tempdir().unwrap();
    let directory = StateDirectory::open(temp.path()).unwrap();
    directory.atomic_write("key", b"original").unwrap();
    fs::hard_link(temp.path().join("key"), temp.path().join("linked")).unwrap();
    assert!(directory.read("linked", 32).is_err());
    assert!(directory.open_private("linked").is_err());
    assert_eq!(fs::read(temp.path().join("key")).unwrap(), b"original");
}
