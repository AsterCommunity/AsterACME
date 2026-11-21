//! Portable state file contracts shared by native CI targets.
use crate::state_file::*;
#[cfg(unix)]
use std::io::Write as _;
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

#[test]
fn entry_identity_observes_aliases_without_reading_contents() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("file");
    let alias = temp.path().join("alias");
    fs::write(&path, b"sentinel").unwrap();
    fs::hard_link(&path, &alias).unwrap();
    let expected = entry_identity(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o200)).unwrap();
        assert_eq!(entry_identity(&path).unwrap(), expected);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(entry_identity(&path).unwrap(), expected);
        let link = temp.path().join("symlink");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_ne!(entry_identity(&link).unwrap(), expected);
        assert!(open_regular(&link).is_err());
    }
    assert_eq!(entry_identity(&alias).unwrap(), expected);
    assert_ne!(entry_identity(temp.path()).unwrap(), expected);
    assert_eq!(
        entry_identity(&temp.path().join("missing"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn external_secret_reads_accept_user_filenames_and_enforce_file_safety_and_limits() {
    let temp = tempfile::tempdir().unwrap();
    for name in ["p12 password.txt", "密码.txt"] {
        let path = temp.path().join(name);
        fs::write(&path, b"secret").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            read_external_private(&path, 6).unwrap().as_slice(),
            b"secret"
        );
        assert_eq!(
            read_external_private(&path, 5).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let alias = temp.path().join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(read_external_private(&path, 6).is_err());
        assert!(read_external_private(&alias, 6).is_err());
        fs::remove_file(&alias).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let link = temp.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_external_private(&link, 6).is_err());
            fs::remove_file(link).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_external_private(&path, 6).is_err());
        }
    }
    assert!(read_external_private(temp.path(), 6).is_err());
    assert!(read_external_private(&temp.path().join("missing"), 6).is_err());
}

#[cfg(unix)]
#[test]
fn external_secrets_can_live_in_root_owned_parents_and_special_files_never_block() {
    use std::os::unix::fs::MetadataExt as _;
    let mut file = tempfile::Builder::new()
        .prefix("p12 密码 ")
        .tempfile_in("/tmp")
        .unwrap();
    file.write_all(b"secret").unwrap();
    let parent = file.path().parent().unwrap();
    assert_eq!(fs::metadata(parent).unwrap().uid(), 0);
    assert_eq!(
        read_external_private(file.path(), 6).unwrap().as_slice(),
        b"secret"
    );
    if rustix::process::geteuid().as_raw() != 0 {
        assert!(StateDirectory::open(parent).is_err());
    }
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("password.socket");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    assert!(read_external_private(&socket, 4096).is_err());
}
