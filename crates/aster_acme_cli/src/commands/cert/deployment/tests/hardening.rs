//! Failure isolation, configuration patches, permission policy and destination ownership.
use crate::commands::cert::{
    deployment::tests::{Fixture, child_command, manage_binding},
    deployment::*,
    report::{CertificateReport, CertificateResult},
};
use aster_acme::issuance::IssueOutcome;

#[tokio::test]
async fn open_failure_keeps_saved_history_but_reports_current_failure_and_runs_next_target() {
    let fixture = Fixture::new().await;
    let first = fixture.add("first", Vec::new(), 0).await;
    fixture.add("second", child_command("success"), 0).await;
    manage_binding(&fixture, &["run"]).await.unwrap();
    std::fs::rename(&first, first.with_extension("unavailable")).unwrap();
    let report = manage_binding(&fixture, &["run"]).await.unwrap();
    assert!(matches!(
        report.exit_status(),
        crate::common::session::ExitStatus::Failed
    ));
    let json: serde_json::Value = serde_json::from_str(
        &crate::commands::cert::render::render(
            &report,
            crate::common::session::Format::plain(true),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(json["deployments"][0]["phase"], "deployed");
    assert!(
        json["deployments"][0]["execution_error"]
            .as_str()
            .unwrap()
            .contains("cannot resolve deployment directory")
    );
    assert!(json["deployments"][1]["execution_error"].is_null());
    assert_eq!(json["deployments"][1]["phase"], "deployed");
    let human = crate::commands::cert::render::render(
        &report,
        crate::common::session::Format::plain(false),
    )
    .unwrap();
    assert!(human.contains("execution failed"));
    assert_eq!(
        fixture.status("first").await.phase,
        DeploymentPhase::Deployed
    );
    assert!(json["events"].as_array().unwrap().iter().any(|event| {
        event["deployment"] == "second"
            && event["message"]
                .as_str()
                .unwrap()
                .contains("reload succeeded")
    }));
}

#[cfg(unix)]
#[tokio::test]
async fn destination_ownership_resolves_ancestor_aliases_and_managed_state_paths() {
    let fixture = Fixture::new().await;
    let target = fixture.add("first", Vec::new(), 0).await;
    let alias = fixture.temp.path().join("alias");
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    for path in [
        alias.join("cert.pem"),
        target.join("../first/cert.pem"),
        fixture.temp.path().join("config.toml"),
    ] {
        let result = fixture
            .store
            .add_deployment(
                &fixture.name,
                DeploymentDefinition {
                    name: Some("collision".into()),
                    target: DeploymentTarget::Files {
                        certificate: Some(path),
                        private_key: None,
                        ca_chain: None,
                        fullchain: None,
                    },
                    reload_command: Vec::new(),
                    timeout_seconds: 30,
                    max_retries: 0,
                    permissions: DeploymentPermissions::default(),
                },
            )
            .await;
        assert!(result.is_err());
    }
    assert_eq!(
        fixture
            .store
            .deployments(&fixture.name)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(!target.join("cert.pem").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn permission_updates_are_saved_without_execution_and_defaults_remain_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = Fixture::new().await;
    let target = fixture.add("first", Vec::new(), 0).await;
    manage_binding(&fixture, &["run"]).await.unwrap();
    assert_eq!(
        std::fs::metadata(target.join("private-key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    manage_binding(
        &fixture,
        &[
            "update",
            "-n",
            "first",
            "--file-mode",
            "0644",
            "--key-mode",
            "0640",
        ],
    )
    .await
    .unwrap();
    assert_eq!(
        std::fs::metadata(target.join("private-key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let report = manage_binding(&fixture, &["show", "first"]).await.unwrap();
    let text = crate::commands::cert::render::render(
        &report,
        crate::common::session::Format::plain(false),
    )
    .unwrap();
    assert!(text.contains("0644") && text.contains("0640"));
    manage_binding(&fixture, &["run"]).await.unwrap();
    assert_eq!(
        std::fs::metadata(target.join("private-key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert_eq!(
        std::fs::metadata(target.join("cert.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    let prior = fixture.status("first").await;
    assert!(
        fixture
            .store
            .update_deployment(
                &fixture.name,
                "first",
                DeploymentPatch {
                    permissions: DeploymentPermissions {
                        file_mode: Some(0o1644),
                        key_mode: None
                    },
                    ..DeploymentPatch::default()
                }
            )
            .await
            .is_err()
    );
    assert_eq!(fixture.status("first").await, prior);
}

#[tokio::test]
async fn stale_success_is_never_reported_for_failed_run_and_other_targets_continue() {
    let fixture = Fixture::new().await;
    let first = fixture.add("first", child_command("success"), 0).await;
    fixture.add("second", child_command("success"), 0).await;
    manage_binding(&fixture, &["run"]).await.unwrap();
    std::fs::remove_file(first.join("fullchain.pem")).unwrap();
    std::fs::create_dir(first.join("fullchain.pem")).unwrap();
    let report = manage_binding(&fixture, &["run"]).await.unwrap();
    assert!(matches!(
        report.exit_status(),
        crate::common::session::ExitStatus::Failed
    ));
    let CertificateReport::Deployment(report) = report else {
        panic!("expected deployment");
    };
    assert_eq!(report.entries[0].phase, DeploymentPhase::PublishFailed);
    assert!(
        report.entries[0]
            .last_error
            .as_deref()
            .unwrap()
            .contains("fullchain.pem")
    );
    assert_eq!(report.entries[1].phase, DeploymentPhase::Deployed);
    assert!(
        report
            .events
            .iter()
            .any(|event| event.kind == MessageKind::Error)
    );
}

#[tokio::test]
async fn inventory_errors_and_old_deployed_states_make_single_and_batch_reports_fail() {
    let fixture = Fixture::new().await;
    fixture.add("first", child_command("success"), 0).await;
    manage_binding(&fixture, &["run"]).await.unwrap();
    let current = fixture
        .store
        .query(IssueQuery {
            in_use: Some(true),
            ..IssueQuery::default()
        })
        .await
        .unwrap()
        .remove(0);
    let folder = fixture
        .temp
        .path()
        .join("certs/web")
        .join(current.generation_name());
    std::fs::remove_file(folder.join("private-key.pk8")).unwrap();
    let bindings = fixture.store.deployments(&fixture.name).await.unwrap();
    let execution = run_target(&fixture.store, &fixture.name, &bindings[0], true, None).await;
    assert_eq!(execution.binding.phase, DeploymentPhase::Deployed);
    assert!(
        execution
            .events
            .iter()
            .any(|event| event.kind == MessageKind::Error)
    );
    // No bindings can be read: the absence of entries must not turn the warning into success.
    std::fs::write(fixture.temp.path().join("certs/web/cert.toml"), "corrupt").unwrap();
    let (deployments, deployment_events) =
        after_issuance(&fixture.store, &fixture.name, &current.generation_name()).await;
    assert_eq!(deployments, []);
    let result = CertificateResult::Issued {
        outcome: IssueOutcome::Completed {
            record: Box::new(current),
            cleanup: Vec::new(),
        },
        deployments,
        deployment_events,
    };
    let report = CertificateReport::Result {
        result,
        data_dir: fixture.temp.path().into(),
    };
    assert!(matches!(
        report.exit_status(),
        crate::common::session::ExitStatus::Failed
    ));
    let json =
        crate::commands::cert::render::render(&report, crate::common::session::Format::plain(true))
            .unwrap();
    assert!(json.contains("deployment inventory could not be read"));
    assert!(json.contains("\"level\": \"error\""));
}

#[tokio::test]
async fn reload_output_is_returned_in_json_and_does_not_pollute_stdout_with_human_logs() {
    let fixture = Fixture::new().await;
    fixture
        .add("output", child_command("output-failure"), 0)
        .await;
    let report = manage_binding(&fixture, &["run"]).await.unwrap();
    assert!(matches!(
        report.exit_status(),
        crate::common::session::ExitStatus::Failed
    ));
    let json =
        crate::commands::cert::render::render(&report, crate::common::session::Format::plain(true))
            .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(json.contains("failure stdout"));
    assert!(json.contains("failure stderr"));
    assert!(
        parsed["deployments"][0]["last_error"]
            .as_str()
            .unwrap()
            .contains('7')
    );
    assert!(
        parsed["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event.get("level").is_some())
    );
}

#[tokio::test]
async fn updates_patch_only_requested_fields_never_execute_and_failed_updates_keep_old_config() {
    let fixture = Fixture::new().await;
    let target = fixture.add("nginx", child_command("failure"), 0).await;
    let report = manage_binding(
        &fixture,
        &[
            "update",
            "-n",
            "nginx",
            "--clear-reload",
            "--reload-timeout",
            "12",
            "--max-retries",
            "4",
        ],
    )
    .await
    .unwrap();
    assert!(matches!(
        report,
        CertificateReport::DeploymentUpdated { .. }
    ));
    let saved = fixture.status("nginx").await;
    assert_eq!(saved.reload_command, [] as [&str; 0]);
    assert_eq!(saved.timeout_seconds, 12);
    assert_eq!(saved.max_retries, 4);
    assert!(!target.join("cert.pem").exists());
    manage_binding(&fixture, &["run", "-n", "nginx"])
        .await
        .unwrap();
    assert!(target.join("cert.pem").exists());
    let next = fixture.temp.path().join("new-target");
    std::fs::create_dir(&next).unwrap();
    manage_binding(
        &fixture,
        &["update", "-n", "nginx", "--target", next.to_str().unwrap()],
    )
    .await
    .unwrap();
    let saved = fixture.status("nginx").await;
    assert_eq!(saved.phase, DeploymentPhase::Configured);
    assert_eq!(saved.timeout_seconds, 12);
    assert_eq!(saved.generation, None);
    assert!(!next.join("cert.pem").exists());
    assert!(
        manage_binding(&fixture, &["update", "-n", "missing", "--clear-reload"])
            .await
            .is_err()
    );
    assert!(
        manage_binding(
            &fixture,
            &["update", "-n", "nginx", "--target", "nonexistent-directory"]
        )
        .await
        .is_err()
    );
    assert_eq!(fixture.status("nginx").await, saved);
}

#[cfg(unix)]
#[tokio::test]
async fn unix_modes_are_applied_and_retained_on_renewal_without_changing_the_parent() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = Fixture::new().await;
    let target = fixture.temp.path().join("modes");
    std::fs::create_dir(&target).unwrap();
    let parent_mode = std::fs::metadata(&target).unwrap().permissions().mode();
    manage_binding(
        &fixture,
        &[
            "add",
            "-n",
            "modes",
            "--target",
            target.to_str().unwrap(),
            "--file-mode",
            "0644",
            "--key-mode",
            "0640",
        ],
    )
    .await
    .unwrap();
    for renewed in [false, true] {
        if renewed {
            fixture.complete(true).await;
            fixture.automatic(&fixture.store).await;
        }
        for (file, mode) in [
            ("cert.pem", 0o644),
            ("ca.pem", 0o644),
            ("fullchain.pem", 0o644),
            ("private-key.pem", 0o640),
        ] {
            assert_eq!(
                std::fs::metadata(target.join(file))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                mode
            );
        }
    }
    assert_eq!(
        std::fs::metadata(target).unwrap().permissions().mode(),
        parent_mode
    );
}

#[tokio::test]
async fn path_ownership_rejects_conflicts_within_and_across_certificates_before_writes() {
    let mut fixture = Fixture::new().await;
    let target = fixture.add("nginx", Vec::new(), 0).await;
    assert!(
        manage_binding(
            &fixture,
            &[
                "add",
                "-n",
                "overlap",
                "--fullchain-path",
                target.join("fullchain.pem").to_str().unwrap()
            ]
        )
        .await
        .is_err()
    );
    let original_name = fixture.name.clone();
    fixture.name = CertificateName::new("second-cert").unwrap();
    fixture.complete(false).await;
    let definition = DeploymentDefinition {
        name: Some("other".into()),
        permissions: DeploymentPermissions::default(),
        target: DeploymentTarget::Directory {
            path: target.clone(),
        },
        reload_command: Vec::new(),
        timeout_seconds: 30,
        max_retries: 0,
    };
    assert!(
        fixture
            .store
            .add_deployment(&fixture.name, definition.clone())
            .await
            .is_err()
    );
    let second = fixture.add("other", Vec::new(), 0).await;
    let patch = DeploymentPatch {
        target: Some(DeploymentTarget::Directory {
            path: target.clone(),
        }),
        ..DeploymentPatch::default()
    };
    assert!(
        fixture
            .store
            .update_deployment(&fixture.name, "other", patch)
            .await
            .is_err()
    );
    assert!(!target.join("cert.pem").exists());
    assert!(!second.join("cert.pem").exists());
    assert_eq!(
        fixture
            .store
            .deployments(&original_name)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn concurrent_target_claims_allow_only_one_binding_and_failed_claim_keeps_inventory_intact() {
    let fixture = Fixture::new().await;
    let target = fixture.temp.path().join("shared");
    std::fs::create_dir(&target).unwrap();
    let definition = DeploymentDefinition {
        name: None,
        permissions: DeploymentPermissions::default(),
        target: DeploymentTarget::Directory { path: target },
        reload_command: Vec::new(),
        timeout_seconds: 30,
        max_retries: 0,
    };
    let store = CliIssueStore::new(fixture.temp.path().into(), Duration::from_secs(2));
    let (left, right) = tokio::join!(
        store.add_deployment(&fixture.name, definition.clone()),
        store.add_deployment(&fixture.name, definition)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert_eq!(store.deployments(&fixture.name).await.unwrap().len(), 1);
}

#[cfg(not(unix))]
#[tokio::test]
async fn explicit_unix_modes_fail_before_configuration_or_file_changes_on_other_platforms() {
    let fixture = Fixture::new().await;
    let target = fixture.temp.path().join("modes");
    std::fs::create_dir(&target).unwrap();
    let error = manage_binding(
        &fixture,
        &[
            "add",
            "-n",
            "modes",
            "--target",
            target.to_str().unwrap(),
            "--key-mode",
            "0640",
        ],
    )
    .await
    .err()
    .unwrap();
    assert!(error.to_string().contains("unsupported on this platform"));
    assert_eq!(fixture.store.deployments(&fixture.name).await.unwrap(), []);
    assert_eq!(std::fs::read_dir(target).unwrap().count(), 0);
}

#[tokio::test]
async fn deployment_result_events_make_batch_summary_fail_even_when_inventory_is_empty() {
    use crate::commands::cert::report::{RenewalBatch, RenewalEntry, RenewalResult};
    let fixture = Fixture::new().await;
    let current = fixture
        .store
        .query(IssueQuery {
            in_use: Some(true),
            ..IssueQuery::default()
        })
        .await
        .unwrap()
        .remove(0);
    let result = CertificateResult::Issued {
        outcome: IssueOutcome::Completed {
            record: Box::new(current),
            cleanup: Vec::new(),
        },
        deployments: Vec::new(),
        deployment_events: vec![event(
            MessageKind::Error,
            "deployment inventory read failed",
        )],
    };
    let report = RenewalBatch {
        entries: vec![RenewalEntry {
            name: "web".into(),
            result: RenewalResult::Outcome(result),
        }],
        cancelled: false,
    };
    assert_eq!(report.summary().failed, 1);
    assert_eq!(report.summary().completed, 0);
    let report = CertificateReport::Batch {
        report,
        data_dir: fixture.temp.path().into(),
    };
    assert!(matches!(
        report.exit_status(),
        crate::common::session::ExitStatus::Failed
    ));
    let json =
        crate::commands::cert::render::render(&report, crate::common::session::Format::plain(true))
            .unwrap();
    assert!(json.contains("deployment inventory read failed"));
}
