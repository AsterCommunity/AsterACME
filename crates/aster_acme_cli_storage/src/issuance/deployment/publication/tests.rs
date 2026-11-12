//! Complete-set preparation, failure cleanup and explicit commit/retry boundaries.
use crate::issuance::deployment::publication::*;

const FILES: [&str; 4] = ["fullchain.pem", "cert.pem", "ca.pem", "private-key.pem"];

fn artifacts() -> DeploymentArtifacts {
    DeploymentArtifacts {
        generation: "test".into(),
        fullchain: b"new-chain".to_vec(),
        certificate: b"new-leaf".to_vec(),
        ca_chain: Vec::new(),
        private_key: zeroize::Zeroizing::new(b"new-key".to_vec()),
    }
}

fn old_files(root: &Path) {
    for file in FILES {
        fs::write(root.join(file), b"old").unwrap();
    }
}

fn assert_old(root: &Path) {
    for file in FILES {
        assert_eq!(fs::read(root.join(file)).unwrap(), b"old");
    }
}

fn assert_no_temporaries(root: &Path) {
    assert!(fs::read_dir(root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".aster-acme-deploy-")
    }));
}

#[test]
fn preparation_keeps_live_files_unchanged_until_explicit_commit_and_drop_cleans_up() {
    let root = tempfile::tempdir().unwrap();
    old_files(root.path());
    let bytes = artifacts();
    for commit in [false, true] {
        let prepared = PreparedPublication::prepare(
            &DeploymentTarget::Directory {
                path: root.path().into(),
            },
            &bytes,
            &DeploymentPermissions::default(),
        )
        .unwrap();
        assert_old(root.path());
        assert_eq!(prepared.files.len(), 4);
        for (file, expected) in prepared.files.iter().zip([
            bytes.fullchain.as_slice(),
            bytes.certificate.as_slice(),
            bytes.ca_chain.as_slice(),
            bytes.private_key.as_slice(),
        ]) {
            assert_eq!(fs::read(file.temporary.path()).unwrap(), expected);
            assert_eq!(file.temporary.path().parent(), Some(root.path()));
            assert!(
                fs::symlink_metadata(file.temporary.path())
                    .unwrap()
                    .is_file()
            );
        }
        if commit {
            prepared.commit().unwrap();
            assert_eq!(fs::read(root.path().join("cert.pem")).unwrap(), b"new-leaf");
            assert_eq!(
                fs::read(root.path().join("private-key.pem")).unwrap(),
                b"new-key"
            );
            assert_eq!(fs::read(root.path().join("ca.pem")).unwrap(), b"");
            for file in FILES {
                let metadata = fs::symlink_metadata(root.path().join(file)).unwrap();
                assert!(metadata.is_file() && !metadata.file_type().is_symlink());
            }
        } else {
            drop(prepared);
            assert_old(root.path());
        }
        assert_no_temporaries(root.path());
    }
}

#[test]
fn late_preparation_errors_preserve_live_files_and_clean_all_prepared_files() {
    // Faults are injected after real staging IO, without changing process-wide state.
    for stage in ["stage file", "write file", "set permissions", "sync file"] {
        for existing in [false, true] {
            let root = tempfile::tempdir().unwrap();
            if existing {
                old_files(root.path());
            }
            let files = FILES
                .map(|name| Destination {
                    path: root.path().join(name),
                    contents: b"replacement",
                    mode: None,
                })
                .into();
            let mut calls = 0;
            let result = stage_all(files, |file| {
                calls += 1;
                let temporary = stage_file(file)?;
                if calls == 4 {
                    return Err(path_error(
                        stage,
                        &file.path,
                        &std::io::Error::other("injected IO failure"),
                    ));
                }
                Ok(temporary)
            });
            let error = result.err().unwrap().to_string();
            assert_eq!(calls, 4);
            assert!(
                error.contains(stage)
                    && error.contains("private-key.pem")
                    && error.contains("injected IO failure")
            );
            if existing {
                assert_old(root.path());
            } else {
                assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
            }
            assert_no_temporaries(root.path());
        }
    }
}

#[test]
fn changed_destination_is_rejected_before_committing_any_prepared_file() {
    let root = tempfile::tempdir().unwrap();
    old_files(root.path());
    let prepared = PreparedPublication::prepare(
        &DeploymentTarget::Directory {
            path: root.path().into(),
        },
        &artifacts(),
        &DeploymentPermissions::default(),
    )
    .unwrap();
    let blocked = root.path().join("private-key.pem");
    fs::remove_file(&blocked).unwrap();
    fs::create_dir(&blocked).unwrap();
    let error = prepared.commit().unwrap_err().to_string();
    assert!(error.contains("not a regular file"));
    for file in &FILES[..3] {
        assert_eq!(fs::read(root.path().join(file)).unwrap(), b"old");
    }
    assert!(blocked.is_dir());
    assert_no_temporaries(root.path());
}

#[cfg(unix)]
#[test]
fn symlink_created_during_preparation_is_not_replaced_or_followed() {
    let root = tempfile::tempdir().unwrap();
    old_files(root.path());
    let prepared = PreparedPublication::prepare(
        &DeploymentTarget::Directory {
            path: root.path().into(),
        },
        &artifacts(),
        &DeploymentPermissions::default(),
    )
    .unwrap();
    let original = root.path().join("user-content");
    fs::write(&original, b"user-content").unwrap();
    let key = root.path().join("private-key.pem");
    fs::remove_file(&key).unwrap();
    std::os::unix::fs::symlink(&original, &key).unwrap();
    assert!(prepared.commit().is_err());
    assert_eq!(fs::read(original).unwrap(), b"user-content");
    assert_eq!(fs::read(root.path().join("fullchain.pem")).unwrap(), b"old");
    assert!(fs::symlink_metadata(key).unwrap().file_type().is_symlink());
    assert_no_temporaries(root.path());
}

#[test]
fn commit_failure_can_leave_a_partial_set_but_releases_staging_and_explicit_retry_repairs_it() {
    let root = tempfile::tempdir().unwrap();
    old_files(root.path());
    let target = DeploymentTarget::Directory {
        path: root.path().into(),
    };
    let prepared =
        PreparedPublication::prepare(&target, &artifacts(), &DeploymentPermissions::default())
            .unwrap();
    // Remove a later staged file to produce a real persist failure after the first replacement.
    fs::remove_file(prepared.files[1].temporary.path()).unwrap();
    let error = prepared.commit().unwrap_err().to_string();
    assert!(error.contains("replace destination") && error.contains("cert.pem"));
    assert_eq!(
        fs::read(root.path().join("fullchain.pem")).unwrap(),
        b"new-chain"
    );
    for file in &FILES[1..] {
        assert_eq!(fs::read(root.path().join(file)).unwrap(), b"old");
    }
    assert_no_temporaries(root.path());
    PreparedPublication::prepare(&target, &artifacts(), &DeploymentPermissions::default())
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(
        fs::read(root.path().join("private-key.pem")).unwrap(),
        b"new-key"
    );
    assert_eq!(fs::read(root.path().join("cert.pem")).unwrap(), b"new-leaf");
    assert_no_temporaries(root.path());
}

#[cfg(unix)]
#[test]
fn configured_permissions_are_applied_to_staged_files_before_commit() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    for modes in [
        (None, None),
        (Some(0o644), Some(0o640)),
        (Some(0), Some(0o600)),
    ] {
        let prepared = PreparedPublication::prepare(
            &DeploymentTarget::Directory {
                path: root.path().into(),
            },
            &artifacts(),
            &DeploymentPermissions {
                file_mode: modes.0,
                key_mode: modes.1,
            },
        )
        .unwrap();
        for file in &prepared.files {
            let expected = if file.destination.file_name().unwrap() == "private-key.pem" {
                modes.1
            } else {
                modes.0
            }
            .unwrap_or(0o600);
            assert_eq!(
                file.temporary
                    .as_file()
                    .metadata()
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                expected
            );
        }
        drop(prepared);
        assert_no_temporaries(root.path());
    }
}

#[test]
fn empty_duplicate_relative_destinations_and_invalid_modes_fail_before_staging() {
    let root = tempfile::tempdir().unwrap();
    for paths in [
        Vec::new(),
        vec![root.path().join("same"), root.path().join("same")],
        vec!["relative.pem".into()],
    ] {
        let files = paths
            .into_iter()
            .map(|path| Destination {
                path,
                contents: b"data",
                mode: None,
            })
            .collect();
        assert!(stage_all(files, |_| panic!("invalid plan must not stage files")).is_err());
    }
    assert!(
        PreparedPublication::prepare(
            &DeploymentTarget::Directory {
                path: root.path().into()
            },
            &artifacts(),
            &DeploymentPermissions {
                file_mode: Some(0o1644),
                key_mode: None
            }
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}
