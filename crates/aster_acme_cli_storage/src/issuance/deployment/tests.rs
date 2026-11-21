//! Deployment regression and resource lifecycle tests.
use crate::issuance::deployment::*;
use aster_acme::deployment::DeploymentPhase;
use std::fs;

fn binding(target: DeploymentTarget) -> DeploymentBinding {
    DeploymentBinding {
        permissions: crate::issuance::deployment::DeploymentPermissions::default(),
        id: "nginx".into(),
        target,
        reload_command: vec!["systemctl".into(), "restart".into(), "nginx".into()],
        timeout_seconds: 30,
        max_retries: 3,
        generation: None,
        pending_generation: None,
        phase: DeploymentPhase::Configured,
        attempts: 0,
        retry_failures: 0,
        retry_at: None,
        last_error: None,
    }
}

#[test]
fn retry_due_has_exact_time_generation_and_phase_boundaries() {
    let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::nanoseconds(1);
    let mut value = binding(DeploymentTarget::Directory {
        path: std::env::temp_dir(),
    });
    value.generation = Some("current".into());
    for phase in [
        DeploymentPhase::Configured,
        DeploymentPhase::Publishing,
        DeploymentPhase::PublishFailed,
        DeploymentPhase::PublicationComplete,
        DeploymentPhase::Reloading,
        DeploymentPhase::ReloadFailed,
        DeploymentPhase::ReloadUncertain,
        DeploymentPhase::Deployed,
    ] {
        value.phase = phase;
        value.retry_at = Some(now);
        let retryable = matches!(
            phase,
            DeploymentPhase::Publishing
                | DeploymentPhase::PublishFailed
                | DeploymentPhase::PublicationComplete
                | DeploymentPhase::ReloadFailed
        );
        assert_eq!(
            value.checkpoint().due("current", now),
            retryable,
            "{phase:?}"
        );
        assert!(
            !value
                .checkpoint()
                .due("current", now - time::Duration::nanoseconds(1))
        );
        assert!(!value.checkpoint().due("previous", now));
        value.retry_at = None;
        assert_eq!(value.checkpoint().due("current", now), retryable);
    }
}

#[test]
fn pending_generation_is_retryable_without_claiming_the_previous_generation_was_deployed() {
    let now = time::OffsetDateTime::UNIX_EPOCH;
    let mut value = binding(DeploymentTarget::Directory {
        path: std::env::temp_dir(),
    });
    value.generation = Some("generation-a".into());
    value.pending_generation = Some("generation-b".into());
    value.phase = DeploymentPhase::Deployed;
    assert!(value.checkpoint().due("generation-b", now));
    assert!(!value.checkpoint().due("generation-a", now));
    value.phase = DeploymentPhase::ReloadUncertain;
    assert!(!value.checkpoint().due("generation-b", now));
    value.phase = DeploymentPhase::Deployed;
    value.retry_at = Some(now + time::Duration::seconds(1));
    assert!(!value.checkpoint().due("generation-b", now));
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
            pkcs12: None,
            pkcs12_password_env: None,
            pkcs12_password_file: None,

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
        pkcs12: None,

        generation: "test".into(),
        fullchain: b"chain".to_vec(),
        certificate: b"leaf".to_vec(),
        ca_chain: b"ca".to_vec(),
        private_key: Zeroizing::new(b"private".to_vec()),
    };
    publication::PreparedPublication::prepare(
        &DeploymentTarget::Directory {
            path: target.clone(),
        },
        &bytes,
        &DeploymentPermissions::default(),
    )
    .and_then(publication::PreparedPublication::commit)
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
    publication::PreparedPublication::prepare(
        &DeploymentTarget::Files {
            pkcs12: None,
            pkcs12_password_env: None,
            pkcs12_password_file: None,

            fullchain: None,
            ca_chain: None,
            certificate: Some(certificate.clone()),
            private_key: Some(private_key.clone()),
        },
        &DeploymentArtifacts {
            pkcs12: None,

            generation: "test".into(),
            fullchain: Vec::new(),
            certificate: b"new".to_vec(),
            ca_chain: Vec::new(),
            private_key: Zeroizing::new(b"new-key".to_vec()),
        },
        &DeploymentPermissions::default(),
    )
    .and_then(publication::PreparedPublication::commit)
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
    let result = publication::PreparedPublication::prepare(
        &DeploymentTarget::Files {
            pkcs12: None,
            pkcs12_password_env: None,
            pkcs12_password_file: None,

            fullchain: None,
            ca_chain: None,
            certificate: Some(link.clone()),
            private_key: Some(temp.path().join("key.pem")),
        },
        &DeploymentArtifacts {
            pkcs12: None,

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
    let result = publication::PreparedPublication::prepare(
        &DeploymentTarget::Files {
            pkcs12: None,
            pkcs12_password_env: None,
            pkcs12_password_file: None,

            fullchain: None,
            ca_chain: None,
            certificate: Some(certificate.clone()),
            private_key: Some(bad_key),
        },
        &DeploymentArtifacts {
            pkcs12: None,

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
            pkcs12: None,
            pkcs12_password_env: None,
            pkcs12_password_file: None,

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

use crate::issuance::deployment::configuration::{allocate_name, validate_binding};

#[test]
fn pkcs12_binding_sources_and_serialization_preserve_reference_only_contract() {
    let root = tempfile::tempdir().unwrap();
    let target = |p12, env, file| DeploymentTarget::Files {
        certificate: Some(root.path().join("leaf.pem")),
        fullchain: None,
        ca_chain: None,
        private_key: None,
        pkcs12: p12,
        pkcs12_password_env: env,
        pkcs12_password_file: file,
    };
    let p12 = Some(root.path().join("bundle.p12"));
    for (env, file) in [
        (None, None),
        (Some("PASSWORD".into()), None),
        (None, Some(root.path().join("secret"))),
    ] {
        let value = binding(target(p12.clone(), env.clone(), file.clone()));
        validate_binding(&value).unwrap();
        let text = toml::to_string(&value).unwrap();
        assert_eq!(toml::from_str::<DeploymentBinding>(&text).unwrap(), value);
        if let Some(name) = env {
            assert!(text.contains(&name));
        }
    }
    for (p12, env, file) in [
        (None, Some("PASSWORD".into()), None),
        (None, None, Some(root.path().join("secret"))),
        (
            p12.clone(),
            Some("PASSWORD".into()),
            Some(root.path().join("secret")),
        ),
        (p12.clone(), Some("BAD=ENV".into()), None),
        (p12.clone(), Some(String::new()), None),
        (p12.clone(), Some("x".repeat(513)), None),
        (p12.clone(), Some("BAD\nENV".into()), None),
        (p12.clone(), None, Some("relative".into())),
        (Some(root.path().join("leaf.pem")), None, None),
    ] {
        assert!(validate_binding(&binding(target(p12, env, file))).is_err());
    }
    // Old PEM-only serialized bindings omit all optional p12 fields.
    let pem = binding(target(None, None, None));
    validate_binding(&pem).unwrap();
    let text = toml::to_string(&pem).unwrap();
    assert!(!text.contains("pkcs12"));
    assert_eq!(toml::from_str::<DeploymentBinding>(&text).unwrap(), pem);
}

#[test]
fn pkcs12_publication_requires_preparation_and_uses_key_permissions() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("bundle.p12");
    fs::write(&path, b"old").unwrap();
    let target = DeploymentTarget::Files {
        certificate: None,
        fullchain: None,
        ca_chain: None,
        private_key: None,
        pkcs12: Some(path.clone()),
        pkcs12_password_env: None,
        pkcs12_password_file: None,
    };
    let mut artifacts = DeploymentArtifacts {
        generation: "g".into(),
        certificate: vec![],
        fullchain: vec![],
        ca_chain: vec![],
        private_key: Zeroizing::new(vec![]),
        pkcs12: None,
    };
    let permissions = DeploymentPermissions {
        file_mode: cfg!(unix).then_some(0o644),
        key_mode: cfg!(unix).then_some(0o600),
    };
    assert!(publication::PreparedPublication::prepare(&target, &artifacts, &permissions).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"old");
    artifacts.pkcs12 = Some(Zeroizing::new(b"bundle".to_vec()));
    publication::PreparedPublication::prepare(&target, &artifacts, &permissions)
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"bundle");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
