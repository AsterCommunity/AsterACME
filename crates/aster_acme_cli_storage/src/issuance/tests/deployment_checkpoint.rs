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
                .open_deployment(&current.name, &binding.id)
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
        .open_deployment(&current.name, &binding.id)
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
        .open_deployment(&current.name, &binding.id)
        .await
        .unwrap();
    session
        .save_pending_generation(&current.generation_name())
        .await
        .unwrap();

    assert!(session.definition().checkpoint().is_deployed());
    assert_eq!(std::fs::read(slot.join("cert.toml")).unwrap(), before);
}
