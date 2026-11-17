//! Exercise the portable publication adapter on every host, including missing files.
use crate::issuance::deployment::publication::{ExpectedFile, portable::Temporary};
use sha2::{Digest as _, Sha256};
use std::{fs, io::Write as _};

#[test]
fn portable_readback_accepts_the_published_file_and_rejects_each_later_change() {
    for fault in ["none", "contents", "length", "missing", "directory"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("cert.pem");
        let contents = b"new-leaf";
        let mut temporary = Temporary::create(&path).unwrap();
        temporary.as_file_mut().write_all(contents).unwrap();
        temporary.as_file().sync_all().unwrap();
        assert_eq!(temporary.path().parent(), Some(root.path()));
        temporary.inspect(&path).unwrap();
        let published = temporary.persist(&path).unwrap();
        match fault {
            "contents" => fs::write(&path, b"bad-leaf").unwrap(),
            "length" => fs::write(&path, b"short").unwrap(),
            "missing" => fs::remove_file(&path).unwrap(),
            "directory" => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            _ => {}
        }
        let result = published.verify(
            &path,
            &ExpectedFile {
                digest: Sha256::digest(contents).into(),
                length: contents.len() as u64,
                #[cfg(unix)]
                mode: None,
            },
        );
        if fault == "none" {
            result.unwrap();
        } else {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("verification"), "{fault}: {error}");
            assert!(error.contains(&path.display().to_string()), "{error}");
        }
    }
}

#[test]
fn portable_readback_rejects_a_different_open_file_identity() {
    let root = tempfile::tempdir().unwrap();
    let published_path = root.path().join("published.pem");
    let other_path = root.path().join("other.pem");
    let contents = b"new-leaf";
    let mut temporary = Temporary::create(&published_path).unwrap();
    temporary.as_file_mut().write_all(contents).unwrap();
    temporary.as_file().sync_all().unwrap();
    let published = temporary.persist(&published_path).unwrap();
    fs::write(&other_path, contents).unwrap();
    let error = published
        .verify(
            &other_path,
            &ExpectedFile {
                digest: Sha256::digest(contents).into(),
                length: contents.len() as u64,
                #[cfg(unix)]
                mode: None,
            },
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("file identity changed"), "{error}");
}
