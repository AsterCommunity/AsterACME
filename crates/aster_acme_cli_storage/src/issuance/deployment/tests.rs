//! Deployment regression and resource lifecycle tests.
use crate::issuance::deployment::*;

fn binding(target: DeploymentTarget) -> DeploymentBinding {
    DeploymentBinding {
        permissions: crate::issuance::deployment::DeploymentPermissions::default(),
        id: "nginx".into(),
        target,
        reload_command: vec!["systemctl".into(), "restart".into(), "nginx".into()],
        timeout_seconds: 30,
        max_retries: 3,
        generation: None,
        phase: DeploymentPhase::Configured,
        attempts: 0,
        last_error: None,
    }
}

#[test]
fn binding_validation_rejects_invalid_ids_paths_commands_and_limits() {
    let temp = tempfile::tempdir().unwrap();
    let absolute = temp.path().join("cert.pem");
    let overlong_id = "x".repeat(65);
    for id in ["", "../escape", "has space", &overlong_id] {
        let mut value = binding(DeploymentTarget::Directory {
            path: temp.path().to_path_buf(),
        });
        value.id = id.into();
        assert!(validate_binding(&value).is_err(), "accepted ID {id:?}");
    }

    for (timeout, retries, command) in [
        (0, 0, vec!["systemctl".into()]),
        (3601, 0, vec!["systemctl".into()]),
        (30, 11, vec!["systemctl".into()]),
        (30, 0, vec![String::new()]),
    ] {
        let mut value = binding(DeploymentTarget::Directory {
            path: temp.path().to_path_buf(),
        });
        value.timeout_seconds = timeout;
        value.max_retries = retries;
        value.reload_command = command;
        assert!(validate_binding(&value).is_err());
    }

    assert!(
        validate_binding(&binding(DeploymentTarget::Directory {
            path: PathBuf::from("relative"),
        }))
        .is_err()
    );
    assert!(
        validate_binding(&binding(DeploymentTarget::Files {
            fullchain: None,
            ca_chain: None,
            certificate: Some(absolute.clone()),
            private_key: Some(absolute),
        }))
        .is_err()
    );
}

#[test]
fn directory_publication_writes_exact_pem_set() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let bytes = DeploymentArtifacts {
        generation: "test".into(),
        fullchain: b"chain".to_vec(),
        certificate: b"leaf".to_vec(),
        ca_chain: b"ca".to_vec(),
        private_key: Zeroizing::new(b"private".to_vec()),
    };
    publish_files(
        &DeploymentTarget::Directory {
            path: target.clone(),
        },
        &bytes,
        &DeploymentPermissions::default(),
    )
    .unwrap();
    assert_eq!(fs::read(target.join("fullchain.pem")).unwrap(), b"chain");
    assert_eq!(fs::read(target.join("cert.pem")).unwrap(), b"leaf");
    assert_eq!(fs::read(target.join("ca.pem")).unwrap(), b"ca");
    assert_eq!(
        fs::read(target.join("private-key.pem")).unwrap(),
        b"private"
    );
}

#[test]
fn single_file_publication_replaces_regular_files_but_never_follows_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let certificate = temp.path().join("cert.pem");
    let private_key = temp.path().join("key.pem");
    fs::write(&certificate, b"old").unwrap();
    fs::write(&private_key, b"old-key").unwrap();
    publish_files(
        &DeploymentTarget::Files {
            fullchain: None,
            ca_chain: None,
            certificate: Some(certificate.clone()),
            private_key: Some(private_key.clone()),
        },
        &DeploymentArtifacts {
            generation: "test".into(),
            fullchain: Vec::new(),
            certificate: b"new".to_vec(),
            ca_chain: Vec::new(),
            private_key: Zeroizing::new(b"new-key".to_vec()),
        },
        &DeploymentPermissions::default(),
    )
    .unwrap();
    assert_eq!(fs::read(&certificate).unwrap(), b"new");
    assert_eq!(fs::read(&private_key).unwrap(), b"new-key");
}

#[cfg(unix)]
#[test]
fn publication_refuses_symlink_destinations_without_modifying_the_link_target() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("original.pem");
    let link = temp.path().join("link.pem");
    fs::write(&target, b"original").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let result = publish_files(
        &DeploymentTarget::Files {
            fullchain: None,
            ca_chain: None,
            certificate: Some(link.clone()),
            private_key: Some(temp.path().join("key.pem")),
        },
        &DeploymentArtifacts {
            generation: "test".into(),
            fullchain: Vec::new(),
            certificate: b"replacement".to_vec(),
            ca_chain: Vec::new(),
            private_key: Zeroizing::new(b"key".to_vec()),
        },
        &DeploymentPermissions::default(),
    );
    assert!(result.is_err());
    assert_eq!(fs::read(target).unwrap(), b"original");
    assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
}

#[test]
fn all_destinations_are_preflighted_before_any_existing_file_is_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let certificate = temp.path().join("cert.pem");
    let bad_key = temp.path().join("key-directory");
    fs::write(&certificate, b"original").unwrap();
    fs::create_dir(&bad_key).unwrap();
    let result = publish_files(
        &DeploymentTarget::Files {
            fullchain: None,
            ca_chain: None,
            certificate: Some(certificate.clone()),
            private_key: Some(bad_key),
        },
        &DeploymentArtifacts {
            generation: "test".into(),
            fullchain: Vec::new(),
            certificate: b"replacement".to_vec(),
            ca_chain: Vec::new(),
            private_key: Zeroizing::new(b"key".to_vec()),
        },
        &DeploymentPermissions::default(),
    );
    assert!(result.is_err());
    assert_eq!(fs::read(certificate).unwrap(), b"original");
}

#[test]
fn empty_reload_command_means_no_process_but_empty_executable_is_invalid() {
    let root = tempfile::tempdir().unwrap();
    let mut value = binding(DeploymentTarget::Directory {
        path: root.path().into(),
    });
    value.reload_command = Vec::new();
    validate_binding(&value).unwrap();
    value.reload_command.push(String::new());
    assert!(validate_binding(&value).is_err());
}

#[test]
fn automatic_names_retry_collisions_with_a_bound_and_explicit_names_never_change() {
    let temp = tempfile::tempdir().unwrap();
    let existing = [binding(DeploymentTarget::Directory {
        path: temp.path().into(),
    })];
    let mut calls = 0;
    let generated = allocate_name(None, &existing, || {
        calls += 1;
        Ok(if calls == 1 { "nginx" } else { "deploy-new" }.into())
    })
    .unwrap();
    assert_eq!(generated, "deploy-new");
    assert_eq!(calls, 2);
    calls = 0;
    assert!(
        allocate_name(None, &existing, || {
            calls += 1;
            Ok("nginx".into())
        })
        .is_err()
    );
    assert_eq!(calls, 16);
    assert!(
        allocate_name(Some("nginx".into()), &existing, || panic!(
            "explicit name must not generate"
        ))
        .is_err()
    );
    assert_eq!(
        allocate_name(Some("service".into()), &existing, || panic!(
            "explicit name must not generate"
        ))
        .unwrap(),
        "service"
    );
    assert!(
        allocate_name(Some("../invalid".into()), &existing, || panic!(
            "explicit name must not generate"
        ))
        .is_err()
    );
    assert!(allocate_name(None, &existing, || Err(failure("randomness unavailable"))).is_err());
}

#[test]
fn exact_paths_allow_every_artifact_alone_but_reject_empty_relative_and_duplicate_destinations() {
    let root = tempfile::tempdir().unwrap();
    let target = |paths: [Option<PathBuf>; 4]| {
        let [certificate, private_key, ca_chain, fullchain] = paths;
        DeploymentTarget::Files {
            certificate,
            private_key,
            ca_chain,
            fullchain,
        }
    };
    assert!(validate_binding(&binding(target([None, None, None, None]))).is_err());
    for index in 0..4 {
        let mut paths = [None, None, None, None];
        paths[index] = Some(root.path().join("file.pem"));
        validate_binding(&binding(target(paths.clone()))).unwrap();
        paths[index] = Some("relative.pem".into());
        assert!(validate_binding(&binding(target(paths))).is_err());
        for other in index + 1..4 {
            let mut paths = [None, None, None, None];
            paths[index] = Some(root.path().join("same.pem"));
            paths[other] = paths[index].clone();
            assert!(validate_binding(&binding(target(paths))).is_err());
        }
    }
}
