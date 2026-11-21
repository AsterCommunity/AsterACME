//! Library-computed retry state is persisted only if the leased snapshot is unchanged.
use crate::issuance::tests::{completed_generation, fixture};
use crate::issuance::{
    DeploymentDefinition, DeploymentPermissions, DeploymentTarget, selection, write_selection,
};
use aster_acme::deployment::DeploymentPhase;
use time::OffsetDateTime;

#[tokio::test]
async fn retry_updates_reject_changed_binding_and_selection_without_overwriting_disk() {
    for scheduling in [false, true] {
        for changed_selection in [false, true] {
            let f = fixture().await;
            let current = completed_generation(&f).await;
            let target = f.temp.path().join("deployment");
            std::fs::create_dir(&target).unwrap();
            let binding = f
                .store
                .add_deployment(
                    &current.name,
                    DeploymentDefinition {
                        permissions: DeploymentPermissions::default(),
                        name: Some("service".into()),
                        target: DeploymentTarget::Directory { path: target },
                        reload_command: vec![],
                        timeout_seconds: 1,
                        max_retries: 0,
                    },
                )
                .await
                .unwrap();
            let mut session = f
                .store
                .open_deployment(&current.name, &binding.id, None)
                .await
                .unwrap();
            session
                .save_state(DeploymentPhase::PublicationComplete, 0, None)
                .await
                .unwrap();
            let slot = f.store.slot(&current.name);
            let mut config = selection(&slot).unwrap();
            if changed_selection {
                config.cert.in_use = None;
            } else {
                config.cert.deployments[0].last_error = Some("new observation".into());
            }
            write_selection(&slot, &config).unwrap();
            let before = std::fs::read(slot.join("cert.toml")).unwrap();
            let result = if scheduling {
                session.schedule_retry(OffsetDateTime::now_utc()).await
            } else {
                session
                    .record_failure(
                        DeploymentPhase::ReloadFailed,
                        1,
                        "old failure".into(),
                        OffsetDateTime::now_utc(),
                    )
                    .await
            };
            assert!(result.is_err());
            assert_eq!(std::fs::read(slot.join("cert.toml")).unwrap(), before);
        }
    }
}

#[tokio::test]
async fn retry_checkpoint_cannot_attribute_an_old_attempt_to_the_current_generation() {
    let f = fixture().await;
    let current = completed_generation(&f).await;
    let target = f.temp.path().join("deployment");
    std::fs::create_dir(&target).unwrap();
    let binding = f
        .store
        .add_deployment(
            &current.name,
            DeploymentDefinition {
                permissions: DeploymentPermissions::default(),
                name: Some("service".into()),
                target: DeploymentTarget::Directory { path: target },
                reload_command: vec![],
                timeout_seconds: 1,
                max_retries: 0,
            },
        )
        .await
        .unwrap();
    let slot = f.store.slot(&current.name);
    let mut config = selection(&slot).unwrap();
    config.cert.deployments[0].generation = Some("previous-generation".into());
    config.cert.deployments[0].phase = DeploymentPhase::PublicationComplete;
    write_selection(&slot, &config).unwrap();
    let mut session = f
        .store
        .open_deployment(&current.name, &binding.id, None)
        .await
        .unwrap();
    let before = std::fs::read(slot.join("cert.toml")).unwrap();
    assert!(
        session
            .schedule_retry(OffsetDateTime::now_utc())
            .await
            .is_err()
    );
    assert!(
        session
            .record_failure(
                DeploymentPhase::ReloadFailed,
                1,
                "old attempt".into(),
                OffsetDateTime::now_utc()
            )
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(slot.join("cert.toml")).unwrap(), before);
}

#[tokio::test]
async fn queueing_an_already_deployed_generation_is_idempotent() {
    let f = fixture().await;
    let current = completed_generation(&f).await;
    let target = f.temp.path().join("deployment");
    std::fs::create_dir(&target).unwrap();
    let binding = f
        .store
        .add_deployment(
            &current.name,
            DeploymentDefinition {
                permissions: DeploymentPermissions::default(),
                name: Some("service".into()),
                target: DeploymentTarget::Directory { path: target },
                reload_command: vec![],
                timeout_seconds: 1,
                max_retries: 0,
            },
        )
        .await
        .unwrap();
    let slot = f.store.slot(&current.name);
    let mut config = selection(&slot).unwrap();
    config.cert.deployments[0].generation = Some(current.generation_name());
    config.cert.deployments[0].phase = DeploymentPhase::Deployed;
    write_selection(&slot, &config).unwrap();
    let before = std::fs::read(slot.join("cert.toml")).unwrap();

    let mut session = f
        .store
        .open_deployment(&current.name, &binding.id, None)
        .await
        .unwrap();
    session
        .save_pending_generation(&current.generation_name())
        .await
        .unwrap();

    assert!(session.definition().checkpoint().is_deployed());
    assert_eq!(std::fs::read(slot.join("cert.toml")).unwrap(), before);
    drop(session);
    let queued = f
        .store
        .queue_deployment(&current.name, &binding.id, &current.generation_name())
        .await
        .unwrap();
    assert!(queued.checkpoint().is_deployed());
    assert_eq!(std::fs::read(slot.join("cert.toml")).unwrap(), before);
}

#[tokio::test]
async fn queueing_rejects_stale_generation_missing_binding_and_uncertain_reload_without_writes() {
    let f = fixture().await;
    let current = completed_generation(&f).await;
    let target = f.temp.path().join("deployment");
    std::fs::create_dir(&target).unwrap();
    f.store
        .add_deployment(
            &current.name,
            DeploymentDefinition {
                permissions: DeploymentPermissions::default(),
                name: Some("service".into()),
                target: DeploymentTarget::Directory { path: target },
                reload_command: vec![],
                timeout_seconds: 1,
                max_retries: 0,
            },
        )
        .await
        .unwrap();
    let slot = f.store.slot(&current.name);
    let before = std::fs::read(slot.join("cert.toml")).unwrap();
    for (id, generation) in [
        ("service", "stale"),
        ("missing", current.generation_name().as_str()),
    ] {
        assert!(
            f.store
                .queue_deployment(&current.name, id, generation)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(slot.join("cert.toml")).unwrap(), before);
    }
    let mut config = selection(&slot).unwrap();
    config.cert.deployments[0].phase = DeploymentPhase::ReloadUncertain;
    write_selection(&slot, &config).unwrap();
    let before = std::fs::read(slot.join("cert.toml")).unwrap();
    assert!(
        f.store
            .queue_deployment(&current.name, "service", &current.generation_name())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(slot.join("cert.toml")).unwrap(), before);
}

#[tokio::test]
async fn unavailable_existing_destination_blocks_configuration_and_execution_until_repaired() {
    let f = fixture().await;
    let current = completed_generation(&f).await;
    let existing = f.temp.path().join("existing");
    let available = f.temp.path().join("available");
    std::fs::create_dir(&existing).unwrap();
    std::fs::create_dir(&available).unwrap();
    let definition = |name: &str, path: std::path::PathBuf| DeploymentDefinition {
        permissions: DeploymentPermissions::default(),
        name: Some(name.into()),
        target: DeploymentTarget::Directory { path },
        reload_command: vec![],
        timeout_seconds: 1,
        max_retries: 0,
    };
    f.store
        .add_deployment(&current.name, definition("existing", existing.clone()))
        .await
        .unwrap();
    std::fs::remove_dir(&existing).unwrap();
    let slot = f.store.slot(&current.name);
    let before = std::fs::read(slot.join("cert.toml")).unwrap();
    let error = f
        .store
        .add_deployment(&current.name, definition("new", available.clone()))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("cannot prove deployment ownership") && error.contains("existing"),
        "{error}"
    );
    assert_eq!(std::fs::read(slot.join("cert.toml")).unwrap(), before);
    assert!(std::fs::read_dir(&available).unwrap().next().is_none());
    std::fs::create_dir(&existing).unwrap();
    f.store
        .add_deployment(&current.name, definition("new", available.clone()))
        .await
        .unwrap();
    std::fs::remove_dir(&existing).unwrap();
    assert!(
        f.store
            .open_deployment(&current.name, "new", None)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("cannot prove deployment ownership")
    );
    assert!(std::fs::read_dir(&available).unwrap().next().is_none());
    std::fs::create_dir(&existing).unwrap();
    let session = f
        .store
        .open_deployment(&current.name, "new", None)
        .await
        .unwrap();
    session.publish().await.unwrap();
    assert!(available.join("cert.pem").is_file());
}

#[cfg(unix)]
#[tokio::test]
async fn canonical_ancestor_alias_cannot_claim_an_existing_deployment() {
    let f = fixture().await;
    let current = completed_generation(&f).await;
    let target = f.temp.path().join("destination");
    let alias = f.temp.path().join("alias");
    std::fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    for (index, path) in [target, alias].into_iter().enumerate() {
        let result = f
            .store
            .add_deployment(
                &current.name,
                DeploymentDefinition {
                    permissions: DeploymentPermissions::default(),
                    name: Some(format!("service-{index}")),
                    target: DeploymentTarget::Directory { path },
                    reload_command: vec![],
                    timeout_seconds: 1,
                    max_retries: 0,
                },
            )
            .await;
        if index == 0 {
            result.unwrap();
        } else {
            assert!(result.unwrap_err().to_string().contains("conflicts"));
        }
    }
}
