//! PKCS#12 CLI publication, noninteractive errors and secret-reference safety.
use crate::commands::cert::deployment::automatic::retry_due;
use crate::commands::cert::deployment::tests::{Fixture, manage_binding, managed_candidates};
use crate::common::session::{ExitStatus, Format};
use aster_acme::deployment::DeploymentPhase;
use aster_acme_cli_storage::issuance::DeploymentTarget;
use std::time::Duration;

fn json(report: &crate::commands::cert::report::CertificateReport) -> String {
    crate::commands::cert::render::render(report, Format::plain(true)).unwrap()
}

fn check_pfx(path: &std::path::Path) {
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(bytes[0], 0x30);
    let header = if bytes[1] & 0x80 == 0 {
        2
    } else {
        2 + (bytes[1] & 0x7f) as usize
    };
    assert_eq!(&bytes[header..header + 3], &[0x02, 0x01, 0x03]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn invalid_destination_combinations_report_all_supported_formats() {
    for certificate in [None, Some(std::path::PathBuf::from("leaf.pem"))] {
        let directory = certificate
            .as_ref()
            .map(|_| std::path::PathBuf::from("directory"));
        let error = crate::commands::cert::deployment::configuration::destination(
            directory,
            certificate,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("--p12-path"));
        assert!(error.to_string().contains("mutually exclusive"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn unsafe_password_ancestors_fail_before_configuration() {
    let fixture = Fixture::new().await;
    let root = fixture.temp.path();
    let dangling = root.join("dangling");
    std::os::unix::fs::symlink(root.join("absent"), &dangling).unwrap();
    let blocker = root.join("not-a-directory");
    std::fs::write(&blocker, b"sentinel").unwrap();
    let password = root.join("password");
    std::fs::write(&password, b"dummy-password").unwrap();
    for (source, expected) in [
        (
            dangling.join("password"),
            "cannot resolve PKCS#12 password file ownership",
        ),
        (
            blocker.join("password"),
            "cannot resolve PKCS#12 password file ownership",
        ),
    ] {
        let error = fixture
            .store
            .add_deployment(
                &fixture.name,
                aster_acme_cli_storage::issuance::DeploymentDefinition {
                    name: Some("unsafe".into()),
                    target: DeploymentTarget::Files {
                        certificate: None,
                        private_key: None,
                        ca_chain: None,
                        fullchain: None,
                        pkcs12: Some(root.join("bundle.p12")),
                        pkcs12_password_env: None,
                        pkcs12_password_file: Some(source),
                    },
                    permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
                    reload_command: vec![],
                    timeout_seconds: 1,
                    max_retries: 0,
                },
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(
            fixture.store.deployments(&fixture.name).await.unwrap(),
            Vec::<aster_acme_cli_storage::issuance::DeploymentBinding>::new()
        );
        assert!(!root.join("bundle.p12").exists());
    }
    assert_eq!(std::fs::read(&blocker).unwrap(), b"sentinel");
    assert_eq!(std::fs::read(&password).unwrap(), b"dummy-password");
}

#[tokio::test]
async fn uninspectable_destination_identity_is_not_treated_as_an_unrelated_file() {
    let fixture = Fixture::new().await;
    let password = fixture.temp.path().join("password");
    std::fs::write(&password, b"dummy-password").unwrap();
    let target = fixture.temp.path().join("x".repeat(300));
    let before = std::fs::read(fixture.temp.path().join("certs/web/cert.toml")).unwrap();
    let error = manage_binding(
        &fixture,
        &[
            "add",
            "-n",
            "uninspectable",
            "--p12-path",
            target.to_str().unwrap(),
            "--p12-password-file",
            password.to_str().unwrap(),
        ],
    )
    .await
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("cannot inspect deployment/password file identity"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(fixture.temp.path().join("certs/web/cert.toml")).unwrap(),
        before
    );
    assert_eq!(std::fs::read(&password).unwrap(), b"dummy-password");
}

#[test]
fn env_password_is_set_in_a_child_without_mutating_the_test_process() {
    for secret in ["dummy-p12-export-password", ""] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::cert::deployment::tests::pkcs12::env_publication_child",
                "--nocapture",
            ])
            .env("ASTER_ACME_P12_TEST_SECRET", secret)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn another_bindings_nonregular_target_does_not_block_a_safe_password_deployment() {
    for symbolic_link in [true, false] {
        let fixture = Fixture::new().await;
        let directory = fixture.add("broken", vec![], 0).await;
        let target = directory.join("cert.pem");
        let password = fixture.temp.path().join("p12 password 密码.txt");
        std::fs::write(&password, b"dummy-password").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let _listener = if symbolic_link {
            std::os::unix::fs::symlink(&password, &target).unwrap();
            None
        } else {
            Some(std::os::unix::net::UnixListener::bind(&target).unwrap())
        };
        let bundle = fixture.temp.path().join("safe.p12");
        let added = manage_binding(
            &fixture,
            &[
                "add",
                "-n",
                "safe",
                "--p12-path",
                bundle.to_str().unwrap(),
                "--p12-password-file",
                password.to_str().unwrap(),
            ],
        )
        .await
        .unwrap();
        assert!(
            matches!(added.exit_status(), ExitStatus::Success),
            "{}",
            json(&added)
        );
        check_pfx(&bundle);
        let before = std::fs::read(&bundle).unwrap();
        let batch = manage_binding(&fixture, &["run"]).await.unwrap();
        assert!(matches!(batch.exit_status(), ExitStatus::Failed));
        let status: serde_json::Value = serde_json::from_str(&json(&batch)).unwrap();
        assert!(
            status["deployments"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["id"] == "safe"
                    && entry["phase"] == "deployed"
                    && entry["execution_error"].is_null())
        );
        assert!(
            status["deployments"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["id"] == "broken" && entry["execution_error"].is_string())
        );
        assert_ne!(std::fs::read(&bundle).unwrap(), before);
        assert_eq!(std::fs::read(&password).unwrap(), b"dummy-password");
        let metadata = std::fs::symlink_metadata(&target).unwrap();
        if symbolic_link {
            assert!(metadata.is_symlink());
        } else {
            use std::os::unix::fs::FileTypeExt as _;
            assert!(metadata.file_type().is_socket());
        }
    }
}

#[tokio::test]
async fn env_publication_child() {
    let Ok(secret) = std::env::var("ASTER_ACME_P12_TEST_SECRET") else {
        return;
    };
    let fixture = Fixture::new().await;
    let path = fixture.temp.path().join("bundle.p12");
    let arguments = [
        "add",
        "-n",
        "bundle",
        "--p12-path",
        path.to_str().unwrap(),
        "--p12-password-env",
        "ASTER_ACME_P12_TEST_SECRET",
    ];
    let added = manage_binding(&fixture, &arguments).await.unwrap();
    if secret.is_empty() {
        assert!(matches!(added.exit_status(), ExitStatus::Failed));
        assert!(json(&added).contains("empty value"));
        assert!(!path.exists());
        return;
    }
    assert!(matches!(added.exit_status(), ExitStatus::Success));
    std::fs::remove_file(&path).unwrap();
    let deployed = manage_binding(&fixture, &["run", "-n", "bundle"])
        .await
        .unwrap();
    assert!(matches!(deployed.exit_status(), ExitStatus::Success));
    check_pfx(&path);
    let serialized = json(&deployed);
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert!(
        parsed["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["pkcs12_path"] == path.canonicalize().unwrap().to_str().unwrap())
    );
    assert!(serialized.contains("pkcs12"));
    assert!(serialized.contains("deployed"));
    for report in [
        serialized,
        json(&manage_binding(&fixture, &["show", "bundle"]).await.unwrap()),
    ] {
        assert!(!report.contains(&secret));
    }
    let config = std::fs::read_to_string(fixture.temp.path().join("certs/web/cert.toml")).unwrap();
    assert!(config.contains("ASTER_ACME_P12_TEST_SECRET"));
    assert!(!config.contains(&secret));
}

#[tokio::test]
async fn file_password_failure_preserves_published_files_and_secret_reference() {
    let fixture = Fixture::new().await;
    let root = fixture.temp.path();
    let password_file = root.join("password");
    let secret = "dummy-file-p12-secret";
    std::fs::write(&password_file, format!("{secret}\r\nignored")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let path = root.join("bundle.p12");
    let certificate = root.join("leaf.pem");
    let added = manage_binding(
        &fixture,
        &[
            "add",
            "-n",
            "file",
            "--p12-path",
            path.to_str().unwrap(),
            "--p12-password-file",
            password_file.to_str().unwrap(),
            "--cert-path",
            certificate.to_str().unwrap(),
        ],
    )
    .await
    .unwrap();
    assert!(matches!(added.exit_status(), ExitStatus::Success));
    check_pfx(&path);
    assert!(!json(&added).contains(secret));
    let previous = std::fs::read(&path).unwrap();
    fixture.complete(true).await;
    let bindings = fixture.automatic(&fixture.store).await;
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].phase, DeploymentPhase::Deployed);
    assert_ne!(std::fs::read(&path).unwrap(), previous);
    let previous_certificate = std::fs::read(&certificate).unwrap();
    let old = std::fs::read(&path).unwrap();
    std::fs::remove_file(&password_file).unwrap();
    let failed = manage_binding(&fixture, &["run", "-n", "file"])
        .await
        .unwrap();
    assert!(matches!(failed.exit_status(), ExitStatus::Failed));
    assert!(!json(&failed).contains("pkcs12_path"));
    assert_eq!(std::fs::read(&path).unwrap(), old);
    assert_eq!(std::fs::read(&certificate).unwrap(), previous_certificate);
    assert_eq!(
        fixture.status("file").await.phase,
        DeploymentPhase::Deployed
    );
    assert!(fixture.status("file").await.retry_at.is_none());
    let config = std::fs::read_to_string(root.join("certs/web/cert.toml")).unwrap();
    assert!(!config.contains(secret));
}

#[tokio::test]
async fn ephemeral_override_does_not_persist_values_or_schedule_automatic_retry() {
    let fixture = Fixture::new().await;
    let root = fixture.temp.path();
    let ephemeral = root.join("ephemeral.p12");
    let report = manage_binding(
        &fixture,
        &[
            "add",
            "-n",
            "ephemeral",
            "--p12-path",
            ephemeral.to_str().unwrap(),
        ],
    )
    .await
    .unwrap();
    assert!(matches!(report.exit_status(), ExitStatus::Failed));
    assert!(json(&report).contains("no password source"));
    assert!(!ephemeral.exists());
    let binding = fixture.status("ephemeral").await;
    assert!(binding.retry_at.is_none());
    assert!(binding.pending_generation.is_none());
    assert_eq!(binding.phase, DeploymentPhase::Configured);
    let mut session = fixture
        .store
        .open_deployment(
            &fixture.name,
            "ephemeral",
            Some(zeroize::Zeroizing::new("one-time-secret".into())),
        )
        .await
        .unwrap();
    session.publish().await.unwrap();
    // Even a failed explicit publication cannot cause automatic replay with a prompt-only binding.
    session
        .save_state(
            DeploymentPhase::PublishFailed,
            0,
            Some("test failure".into()),
        )
        .await
        .unwrap();
    drop(session);
    check_pfx(&ephemeral);
    let reports = retry_due(
        &fixture.store,
        Duration::from_secs(1),
        &tokio_util::sync::CancellationToken::new(),
        &crate::common::context::CommandContext::new(true),
        managed_candidates(&fixture.store).await,
    )
    .await;
    assert!(reports.is_empty());
    let config = std::fs::read_to_string(root.join("certs/web/cert.toml")).unwrap();
    assert!(!config.contains("one-time-secret"));
    let updated = manage_binding(
        &fixture,
        &[
            "update",
            "-n",
            "ephemeral",
            "--p12-path",
            ephemeral.to_str().unwrap(),
            "--p12-password-env",
            "ASTER_ACME_P12_MISSING_75E9",
        ],
    )
    .await
    .unwrap();
    assert!(matches!(updated.exit_status(), ExitStatus::Success));
    let failed = manage_binding(&fixture, &["run", "-n", "ephemeral"])
        .await
        .unwrap();
    assert!(json(&failed).contains("unavailable"));
    assert!(matches!(failed.exit_status(), ExitStatus::Failed));
}

#[tokio::test]
async fn password_file_cannot_be_overwritten_by_any_deployment_destination() {
    let fixture = Fixture::new().await;
    let source = fixture.temp.path().join("password");
    let p12 = fixture.temp.path().join("bundle.p12");
    let definition =
        |id: &str, output, password| aster_acme_cli_storage::issuance::DeploymentDefinition {
            name: Some(id.into()),
            target: DeploymentTarget::Files {
                certificate: None,
                private_key: None,
                ca_chain: None,
                fullchain: None,
                pkcs12: Some(output),
                pkcs12_password_env: None,
                pkcs12_password_file: password,
            },
            permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
            reload_command: vec![],
            timeout_seconds: 1,
            max_retries: 0,
        };
    assert!(
        fixture
            .store
            .add_deployment(
                &fixture.name,
                definition("same", source.clone(), Some(source.clone()))
            )
            .await
            .is_err()
    );
    fixture
        .store
        .add_deployment(
            &fixture.name,
            definition("first", p12.clone(), Some(source.clone())),
        )
        .await
        .unwrap();
    assert!(
        fixture
            .store
            .add_deployment(&fixture.name, definition("second", source.clone(), None))
            .await
            .is_err()
    );
    fixture
        .store
        .remove_deployment(&fixture.name, "first")
        .await
        .unwrap();
    fixture
        .store
        .add_deployment(&fixture.name, definition("second", source.clone(), None))
        .await
        .unwrap();
    assert!(
        fixture
            .store
            .add_deployment(&fixture.name, definition("first", p12, Some(source)))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn missing_password_keeps_renewed_generation_pending_until_source_is_restored() {
    let fixture = Fixture::new().await;
    let password = fixture.temp.path().join("password");
    let bundle = fixture.temp.path().join("bundle.p12");
    std::fs::write(&password, b"test-password").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    manage_binding(
        &fixture,
        &[
            "add",
            "-n",
            "queued",
            "--p12-path",
            bundle.to_str().unwrap(),
            "--p12-password-file",
            password.to_str().unwrap(),
        ],
    )
    .await
    .unwrap();
    let original = fixture.status("queued").await;
    let old_bytes = std::fs::read(&bundle).unwrap();
    std::fs::remove_file(&password).unwrap();
    let renewed = fixture.complete(true).await;
    fixture.automatic(&fixture.store).await;
    let waiting = fixture.status("queued").await;
    assert_eq!(waiting.generation, original.generation);
    assert_eq!(
        waiting.pending_generation.as_deref(),
        Some(renewed.generation_name().as_str())
    );
    assert_eq!(std::fs::read(&bundle).unwrap(), old_bytes);
    std::fs::write(&password, b"test-password").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let reports = retry_due(
        &fixture.store,
        Duration::from_secs(5),
        &tokio_util::sync::CancellationToken::new(),
        &crate::common::context::CommandContext::new(true),
        managed_candidates(&fixture.store).await,
    )
    .await;
    assert_eq!(reports.len(), 1);
    assert!(!reports[0].has_failures());
    let deployed = fixture.status("queued").await;
    assert_eq!(
        deployed.generation.as_deref(),
        Some(renewed.generation_name().as_str())
    );
    assert!(deployed.pending_generation.is_none());
    assert_eq!(deployed.phase, DeploymentPhase::Deployed);
    assert_ne!(std::fs::read(&bundle).unwrap(), old_bytes);
}

#[tokio::test]
async fn missing_password_parent_does_not_block_unrelated_pem_and_aliases_remain_protected() {
    let fixture = Fixture::new().await;
    let root = fixture.temp.path();
    let password_dir = root.join("secrets");
    std::fs::create_dir(&password_dir).unwrap();
    let password = password_dir.join("Password");
    std::fs::write(&password, b"test-password").unwrap();
    let binding = fixture
        .store
        .add_deployment(
            &fixture.name,
            aster_acme_cli_storage::issuance::DeploymentDefinition {
                name: Some("guarded".into()),
                target: DeploymentTarget::Files {
                    certificate: None,
                    private_key: None,
                    ca_chain: None,
                    fullchain: None,
                    pkcs12: Some(root.join("bundle.p12")),
                    pkcs12_password_env: None,
                    pkcs12_password_file: Some(password.clone()),
                },
                permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
                reload_command: vec![],
                timeout_seconds: 1,
                max_retries: 0,
            },
        )
        .await
        .unwrap();
    // On case-insensitive filesystems this alternative spelling is the same file.
    // On case-sensitive filesystems create a hard link to exercise the same identity check.
    let alias = password_dir.join("password");
    if !alias.exists() {
        std::fs::hard_link(&password, &alias).unwrap();
    }
    let collision = manage_binding(
        &fixture,
        &[
            "add",
            "-n",
            "collision",
            "--cert-path",
            alias.to_str().unwrap(),
        ],
    )
    .await;
    assert!(collision.is_err());
    assert_eq!(std::fs::read(&password).unwrap(), b"test-password");
    let hidden = root.join("secrets-unavailable");
    std::fs::rename(&password_dir, &hidden).unwrap();
    let certificate = root.join("unrelated.pem");
    let unrelated = manage_binding(
        &fixture,
        &[
            "add",
            "-n",
            "pem",
            "--cert-path",
            certificate.to_str().unwrap(),
        ],
    )
    .await
    .unwrap();
    assert!(matches!(unrelated.exit_status(), ExitStatus::Success));
    assert!(certificate.exists());
    assert_eq!(fixture.status("guarded").await, binding);
    assert!(
        fixture
            .store
            .open_deployment(&fixture.name, "guarded", None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn password_file_identity_conflicts_cover_same_binding_and_reverse_cross_binding() {
    for same_binding in [true, false] {
        let fixture = Fixture::new().await;
        let root = fixture.temp.path();
        let password = root.join("Password");
        let alias = root.join("password");
        std::fs::write(&password, b"test-password").unwrap();
        if !alias.exists() {
            std::fs::hard_link(&password, &alias).unwrap();
        }
        if !same_binding {
            fixture
                .store
                .add_deployment(
                    &fixture.name,
                    aster_acme_cli_storage::issuance::DeploymentDefinition {
                        name: Some("pem".into()),
                        target: DeploymentTarget::Files {
                            certificate: Some(alias.clone()),
                            private_key: None,
                            ca_chain: None,
                            fullchain: None,
                            pkcs12: None,
                            pkcs12_password_env: None,
                            pkcs12_password_file: None,
                        },
                        permissions:
                            aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
                        reload_command: vec![],
                        timeout_seconds: 1,
                        max_retries: 0,
                    },
                )
                .await
                .unwrap();
        }
        let result = fixture
            .store
            .add_deployment(
                &fixture.name,
                aster_acme_cli_storage::issuance::DeploymentDefinition {
                    name: Some("bundle".into()),
                    target: DeploymentTarget::Files {
                        certificate: same_binding.then_some(alias),
                        private_key: None,
                        ca_chain: None,
                        fullchain: None,
                        pkcs12: Some(root.join("bundle.p12")),
                        pkcs12_password_env: None,
                        pkcs12_password_file: Some(password.clone()),
                    },
                    permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
                    reload_command: vec![],
                    timeout_seconds: 1,
                    max_retries: 0,
                },
            )
            .await;
        assert!(result.is_err());
        assert_eq!(std::fs::read(&password).unwrap(), b"test-password");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn password_file_conflict_checks_allow_unreadable_existing_bundle_targets() {
    use std::os::unix::fs::PermissionsExt as _;
    for mode in ["0200", "0000"] {
        let fixture = Fixture::new().await;
        let password = fixture.temp.path().join("password");
        let bundle = fixture.temp.path().join("bundle.p12");
        std::fs::write(&password, b"test-password").unwrap();
        std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
        let added = manage_binding(
            &fixture,
            &[
                "add",
                "-n",
                "bundle",
                "--p12-path",
                bundle.to_str().unwrap(),
                "--p12-password-file",
                password.to_str().unwrap(),
                "--key-mode",
                mode,
            ],
        )
        .await
        .unwrap();
        assert!(matches!(added.exit_status(), ExitStatus::Success));
        let first = std::fs::symlink_metadata(&bundle).unwrap();
        assert_eq!(
            first.permissions().mode() & 0o777,
            u32::from_str_radix(mode, 8).unwrap()
        );
        let rerun = manage_binding(&fixture, &["run", "-n", "bundle"])
            .await
            .unwrap();
        assert!(
            matches!(rerun.exit_status(), ExitStatus::Success),
            "{}",
            json(&rerun)
        );
        assert_eq!(
            std::fs::symlink_metadata(&bundle)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            u32::from_str_radix(mode, 8).unwrap()
        );
    }
}

#[tokio::test]
#[ignore = "Native PTY fixture invoked by test-deployment-terminal.py"]
#[expect(
    clippy::too_many_lines,
    reason = "Keep the native terminal fixture and its durable-state assertions together"
)]
async fn password_terminal_child() {
    use crate::commands::cert::args::{
        CertCommand,
        deployment::{DeployArgs, DeployCommand},
    };
    use clap::Parser as _;
    let mode = std::env::var("ASTER_P12_TERMINAL_MODE").unwrap();
    let fixture = Fixture::new().await;
    let path = fixture.temp.path().join("interactive.p12");
    let add = crate::app::Args::try_parse_from([
        "aster-acme",
        "cert",
        "deploy",
        "add",
        "web",
        "-n",
        "interactive",
        "--p12-path",
        path.to_str().unwrap(),
        "--data-dir",
        fixture.temp.path().to_str().unwrap(),
    ])
    .unwrap();
    let crate::app::Command::Cert {
        command:
            CertCommand::Deploy(DeployArgs {
                command: DeployCommand::Add(add),
            }),
    } = add.command
    else {
        panic!("expected add")
    };
    if mode != "add" {
        let mut definition =
            crate::commands::cert::deployment::configuration::definition(add).unwrap();
        if mode == "pem" {
            let directory = fixture.temp.path().join("pem");
            std::fs::create_dir(&directory).unwrap();
            definition.target = DeploymentTarget::Directory { path: directory };
        }
        fixture
            .store
            .add_deployment(&fixture.name, definition)
            .await
            .unwrap();
    }
    let before = std::fs::read(fixture.temp.path().join("certs/web/cert.toml")).unwrap();
    let mut words = vec![
        "aster-acme",
        "cert",
        "deploy",
        if mode == "add" { "add" } else { "run" },
        "web",
        "-n",
        "interactive",
        "--data-dir",
        fixture.temp.path().to_str().unwrap(),
    ];
    if mode == "add" {
        words.extend([
            "--p12-path",
            path.to_str().unwrap(),
            "--reload-cmd",
            "must-not-run",
        ]);
    }
    if mode == "json" {
        words.push("--json");
    }
    let parsed = crate::app::Args::try_parse_from(words).unwrap();
    let crate::app::Command::Cert {
        command: CertCommand::Deploy(args),
    } = parsed.command
    else {
        panic!("expected run")
    };
    let report = crate::commands::cert::deployment::command::execute(
        args,
        &crate::common::context::CommandContext::new(mode == "json"),
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    if mode == "success" {
        assert!(matches!(report.exit_status(), ExitStatus::Success));
        check_pfx(&path);
    } else if mode == "pem" {
        assert!(matches!(report.exit_status(), ExitStatus::Success));
        assert!(!path.exists());
        for name in ["cert.pem", "ca.pem", "fullchain.pem", "private-key.pem"] {
            assert!(fixture.temp.path().join("pem").join(name).is_file());
        }
    } else {
        if mode == "cancel" {
            assert!(matches!(report.exit_status(), ExitStatus::Cancelled));
            assert!(json(&report).contains("\"cancelled\": true"));
        } else {
            assert!(matches!(report.exit_status(), ExitStatus::Failed));
        }
        assert!(!path.exists());
        if mode == "add" {
            assert_eq!(
                fixture.status("interactive").await.phase,
                DeploymentPhase::Configured
            );
        } else {
            assert_eq!(
                std::fs::read(fixture.temp.path().join("certs/web/cert.toml")).unwrap(),
                before
            );
        }
    }
    let config = std::fs::read_to_string(fixture.temp.path().join("certs/web/cert.toml")).unwrap();
    assert!(!config.contains("pty-secret-55"));
    assert!(!json(&report).contains("pty-secret-55"));
    println!("P12_TERMINAL_DONE {mode}");
}
