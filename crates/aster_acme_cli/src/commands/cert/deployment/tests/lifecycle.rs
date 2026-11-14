//! Cancellation boundaries and uncertain reload outcomes use real checkpoints.
use crate::commands::cert::{
    deployment::tests::{Fixture, assert_descendant_exited, child_command},
    deployment::*,
    report::CertificateReport,
};

#[tokio::test]
async fn started_reload_wait_failure_is_uncertain_and_never_authorizes_automatic_replay() {
    let fixture = Fixture::new().await;
    fixture.add("unobserved", child_command("success"), 3).await;
    let mut session = fixture
        .store
        .open_deployment(&fixture.name, "unobserved")
        .await
        .unwrap();
    session.publish().await.unwrap();
    let binding = session.definition().clone();
    session
        .save_state(DeploymentPhase::Reloading, 1, None)
        .await
        .unwrap();
    // OS wait failures are rare and platform-specific. Inject the result at
    // the classification boundary while exercising real checkpoint persistence.
    let result = finish_reload_attempt(
        &mut session,
        &binding,
        1,
        reload::ReloadResult {
            status: Err(std::io::Error::other("injected wait failure after spawn")),
            timed_out: false,
            started: true,
        },
        &mut Vec::new(),
        None,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(session.definition().phase, DeploymentPhase::ReloadUncertain);
    assert_eq!(session.definition().attempts, 1);
    drop(session);
    let skipped = fixture.automatic(&fixture.store).await;
    assert_eq!(skipped[0].phase, DeploymentPhase::ReloadUncertain);
    assert_eq!(skipped[0].attempts, 1);
    assert!(
        skipped[0]
            .last_error
            .as_ref()
            .unwrap()
            .contains("injected wait failure")
    );
    let explicit = run_one(
        &fixture.store,
        &fixture.name,
        "unobserved",
        aster_acme::deployment::DeploymentIntent::Explicit,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(explicit.binding.phase, DeploymentPhase::Deployed);
}

#[tokio::test]
async fn reload_start_failure_remains_retryable_and_successful_exit_is_confirmed() {
    let fixture = Fixture::new().await;
    fixture
        .add("start-failed", child_command("success"), 3)
        .await;
    let mut session = fixture
        .store
        .open_deployment(&fixture.name, "start-failed")
        .await
        .unwrap();
    let binding = session.definition().clone();
    let retry = finish_reload_attempt(
        &mut session,
        &binding,
        1,
        reload::ReloadResult {
            status: Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing program",
            )),
            timed_out: false,
            started: false,
        },
        &mut Vec::new(),
        None,
    )
    .await
    .unwrap();
    assert!(!retry);
    assert_eq!(session.definition().phase, DeploymentPhase::ReloadFailed);
}

#[tokio::test]
async fn manual_cancellation_after_publication_retains_files_and_skips_reload() {
    let fixture = Fixture::new().await;
    let target = fixture.add("cancelled", child_command("success"), 0).await;
    let mut session = fixture
        .store
        .open_deployment(&fixture.name, "cancelled")
        .await
        .unwrap();
    session
        .save_state(DeploymentPhase::Publishing, 0, None)
        .await
        .unwrap();
    let execution = Execution {
        cancellation: tokio_util::sync::CancellationToken::new(),
        deadline: None,
    };
    session.publish().await.unwrap();
    execution.cancellation.cancel();
    let outcome = finish_publication(
        &mut session,
        &fixture.name,
        &mut Vec::new(),
        None,
        Some(&execution),
    )
    .await
    .unwrap();
    assert_eq!(outcome.binding.phase, DeploymentPhase::PublicationComplete);
    assert_eq!(outcome.binding.attempts, 0);
    assert!(target.join("private-key.pem").is_file());
    drop(session);
    assert_eq!(
        fixture.status("cancelled").await.phase,
        DeploymentPhase::PublicationComplete
    );
}

#[tokio::test]
async fn manual_cancel_before_start_does_not_publish_or_reload() {
    let fixture = Fixture::new().await;
    let target = fixture
        .add("cancel-before", child_command("success"), 0)
        .await;
    let execution = Execution {
        cancellation: tokio_util::sync::CancellationToken::new(),
        deadline: None,
    };
    execution.cancellation.cancel();
    assert!(
        run_one(
            &fixture.store,
            &fixture.name,
            "cancel-before",
            aster_acme::deployment::DeploymentIntent::Explicit,
            None,
            Some(&execution)
        )
        .await
        .is_err()
    );
    assert!(!target.join("private-key.pem").exists());
    assert_eq!(
        fixture.status("cancel-before").await.phase,
        DeploymentPhase::Configured
    );
}

#[tokio::test]
async fn manual_cancellation_during_publication_waits_for_completion_and_saves_outcome() {
    for fails in [false, true] {
        let fixture = Fixture::new().await;
        let target = fixture.add("publishing", child_command("success"), 0).await;
        let mut session = fixture
            .store
            .open_deployment(&fixture.name, "publishing")
            .await
            .unwrap();
        session
            .save_state(DeploymentPhase::Publishing, 0, None)
            .await
            .unwrap();
        let execution = Execution {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: None,
        };
        let entered = tokio::sync::Notify::new();
        let release = tokio::sync::Notify::new();
        let mut events = Vec::new();
        {
            let publication = publish_and_finish(
                &mut session,
                &fixture.name,
                &mut events,
                None,
                Some(&execution),
                async |session: &aster_acme_cli_storage::issuance::DeploymentSession| {
                    entered.notify_one();
                    release.notified().await;
                    if fails {
                        return Err(aster_acme::issuance::IssueError::InvalidInput(
                            "injected publication failure",
                        ));
                    }
                    session.publish().await
                },
            );
            tokio::pin!(publication);
            tokio::select! {
                result = &mut publication => panic!("publication finished before release: {}", result.is_ok()),
                () = entered.notified() => {},
            }
            execution.cancellation.cancel();
            // Cancellation cannot discard the in-flight operation. The result
            // must remain pending until its publication outcome is available.
            assert!(
                tokio::time::timeout(Duration::from_millis(30), &mut publication)
                    .await
                    .is_err()
            );
            release.notify_one();
            let outcome = publication.await.unwrap();
            assert_eq!(
                outcome.binding.phase,
                if fails {
                    DeploymentPhase::PublishFailed
                } else {
                    DeploymentPhase::PublicationComplete
                }
            );
            assert_eq!(outcome.binding.attempts, 0);
        }
        drop(session);
        assert_eq!(
            fixture.status("publishing").await.phase,
            if fails {
                DeploymentPhase::PublishFailed
            } else {
                DeploymentPhase::PublicationComplete
            }
        );
        assert_eq!(target.join("private-key.pem").exists(), !fails);
    }
}

#[tokio::test]
async fn manual_add_and_run_propagate_cancellation_to_reload_and_preserve_the_checkpoint() {
    use clap::Parser as _;
    for action in ["add", "run"] {
        let fixture = Fixture::new().await;
        let heartbeat = fixture.temp.path().join("manual-heartbeat");
        let command = child_command(&format!("tree-wait-inherited:{}", heartbeat.display()));
        let target = if action == "run" {
            fixture.add("manual", command.clone(), 3).await
        } else {
            let target = fixture.temp.path().join("manual");
            std::fs::create_dir(&target).unwrap();
            target
        };
        let mut words = vec![
            "aster-acme".to_owned(),
            "cert".into(),
            "deploy".into(),
            action.into(),
            "web".into(),
            "--json".into(),
            "--data-dir".into(),
            fixture.temp.path().to_str().unwrap().into(),
        ];
        if action == "add" {
            words.extend([
                "-n".into(),
                "manual".into(),
                "--target".into(),
                target.to_str().unwrap().into(),
                "--reload-cmd".into(),
                shlex::try_join(command.iter().map(String::as_str)).unwrap(),
                "--reload-timeout".into(),
                "30".into(),
            ]);
        }
        if action == "run" {
            fixture.add("zzz-skipped", Vec::new(), 0).await;
        }
        let parsed = crate::app::Args::try_parse_from(words).unwrap();
        let crate::app::Command::Cert {
            command: crate::commands::cert::args::CertCommand::Deploy(args),
        } = parsed.command
        else {
            panic!("expected deployment");
        };
        let execution = Execution {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: None,
        };
        let cli = crate::common::context::CommandContext::new(true);
        let running = execute(args, &cli, execution.cancellation.clone());
        tokio::pin!(running);
        tokio::select! {
            result = &mut running => panic!("command exited before cancellation: {}", result.is_ok()),
            () = async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while !heartbeat.exists() { tokio::time::sleep(Duration::from_millis(10)).await; }
                }).await.unwrap();
            } => {},
        }
        execution.cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_secs(3), running)
            .await
            .unwrap()
            .unwrap();
        assert_cancelled_report(&result);
        if action == "run" {
            let CertificateReport::Deployment(report) = &result else {
                panic!("missing report");
            };
            assert_eq!(report.entries.len(), 2);
            assert_eq!(report.entries[1].phase, DeploymentPhase::Configured);
            assert!(
                !fixture
                    .temp
                    .path()
                    .join("zzz-skipped/private-key.pem")
                    .exists()
            );
        }
        assert!(target.join("private-key.pem").exists());
        let saved = fixture.status("manual").await;
        assert_eq!(saved.phase, DeploymentPhase::ReloadUncertain);
        assert_eq!(saved.attempts, 1);
        assert_descendant_exited(&heartbeat).await;
    }
}

fn assert_cancelled_report(result: &CertificateReport) {
    assert_eq!(
        result.exit_status(),
        crate::common::session::ExitStatus::Failed
    );
    let text =
        crate::commands::cert::render::render(result, crate::common::session::Format::plain(true))
            .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["deployments"][0]["phase"], "reload_uncertain");
    assert!(
        json["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["deployment"] == "manual")
    );
    assert!(text.contains("cancelled"));
    let CertificateReport::Deployment(report) = result else {
        panic!("missing deployment report");
    };
    assert_eq!(report.entries[0].phase, DeploymentPhase::ReloadUncertain);
}

#[tokio::test]
async fn cancellation_after_reload_intent_does_not_invent_a_process_or_erase_prior_state() {
    for phase in [
        DeploymentPhase::PublicationComplete,
        DeploymentPhase::ReloadUncertain,
        DeploymentPhase::ReloadFailed,
    ] {
        let fixture = Fixture::new().await;
        let heartbeat = fixture.temp.path().join("must-not-start");
        fixture
            .add(
                "intent",
                child_command(&format!("heartbeat:{}", heartbeat.display())),
                3,
            )
            .await;
        let mut session = fixture
            .store
            .open_deployment(&fixture.name, "intent")
            .await
            .unwrap();
        session.publish().await.unwrap();
        session
            .save_state(phase, 2, Some("previous outcome".into()))
            .await
            .unwrap();
        let previous = session.definition().clone();
        // Deterministically cancel at the exact point reached when a signal
        // arrives during the awaited intent write, before reload::run is polled.
        session
            .save_state(DeploymentPhase::Reloading, 1, None)
            .await
            .unwrap();
        let execution = Execution {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: None,
        };
        execution.cancellation.cancel();
        let mut events = Vec::new();
        let result = reload::run(
            &previous.reload_command,
            Duration::from_secs(30),
            "intent",
            1,
            &mut events,
            None,
            Some(&execution),
        )
        .await;
        assert!(!result.started);
        assert!(!result.timed_out);
        assert!(
            settle_reload_attempt(
                &mut session,
                &previous,
                1,
                result,
                &mut events,
                None,
                Some(&execution)
            )
            .await
            .is_err()
        );
        assert_eq!(session.definition(), &previous);
        assert!(!heartbeat.with_extension("alive").exists());
        assert!(
            !events
                .iter()
                .any(|event| event.message.contains("tree was terminated"))
        );
        drop(session);
        assert_eq!(fixture.status("intent").await, previous);
    }
}

#[tokio::test]
async fn explicit_retry_retains_uncertainty_through_publication_and_cancellation() {
    for original in [DeploymentPhase::ReloadUncertain, DeploymentPhase::Reloading] {
        for stage in [
            "before-publication",
            "publication-failed",
            "after-publication",
        ] {
            let fixture = Fixture::new().await;
            fixture.add("retry", child_command("success"), 3).await;
            let mut session = fixture
                .store
                .open_deployment(&fixture.name, "retry")
                .await
                .unwrap();
            session
                .save_state(original, 2, Some("old reload unconfirmed".into()))
                .await
                .unwrap();
            let previous = session.definition().clone();
            let execution = Execution {
                cancellation: tokio_util::sync::CancellationToken::new(),
                deadline: None,
            };
            if stage == "before-publication" {
                execution.cancellation.cancel();
            }
            let prepared = prepare_publication(&mut session, Some(&execution)).await;
            assert_eq!(session.definition(), &previous);
            if stage == "before-publication" {
                assert!(prepared.is_err());
            } else {
                prepared.unwrap();
                execution.cancellation.cancel();
                if stage == "publication-failed" {
                    publish_and_finish(
                        &mut session,
                        &fixture.name,
                        &mut Vec::new(),
                        None,
                        Some(&execution),
                        async |_| {
                            Err(aster_acme::issuance::IssueError::InvalidInput(
                                "injected failure",
                            ))
                        },
                    )
                    .await
                    .unwrap();
                } else {
                    session.publish().await.unwrap();
                    assert!(
                        finish_publication(
                            &mut session,
                            &fixture.name,
                            &mut Vec::new(),
                            None,
                            Some(&execution)
                        )
                        .await
                        .is_err()
                    );
                }
            }
            assert_eq!(session.definition(), &previous);
            drop(session);
            let automatic = fixture.automatic(&fixture.store).await;
            assert_eq!(automatic[0], previous);
            let explicit = run_one(
                &fixture.store,
                &fixture.name,
                "retry",
                aster_acme::deployment::DeploymentIntent::Explicit,
                None,
                None,
            )
            .await
            .unwrap();
            assert_eq!(explicit.binding.phase, DeploymentPhase::Deployed);
        }
    }
}

#[tokio::test]
async fn reload_failure_during_backoff_is_checkpointed_before_deadline_return() {
    let fixture = Fixture::new().await;
    fixture.add("backoff", child_command("failure"), 3).await;
    let mut failed = fixture
        .store
        .open_deployment(&fixture.name, "backoff")
        .await
        .unwrap();
    failed
        .save_state(
            DeploymentPhase::ReloadFailed,
            1,
            Some("previous failure".into()),
        )
        .await
        .unwrap();
    failed
        .record_failure(
            DeploymentPhase::ReloadFailed,
            1,
            "previous failure".into(),
            time::OffsetDateTime::now_utc() - time::Duration::minutes(30),
        )
        .await
        .unwrap();
    let retry_snapshot = failed.definition().clone();
    drop(failed);
    let mut session = fixture
        .store
        .open_deployment(&fixture.name, "backoff")
        .await
        .unwrap();
    let mut events = Vec::new();
    record_reload_failure(&mut session, &mut events, None)
        .await
        .unwrap();
    drop(session);
    let saved = fixture.status("backoff").await;
    assert_eq!(saved.phase, DeploymentPhase::ReloadFailed);
    assert_eq!(saved.attempts, retry_snapshot.attempts);
    assert_eq!(saved.retry_failures, retry_snapshot.retry_failures + 1);
    assert!(
        saved
            .retry_at
            .is_some_and(|retry_at| retry_at > time::OffsetDateTime::now_utc())
    );
}
