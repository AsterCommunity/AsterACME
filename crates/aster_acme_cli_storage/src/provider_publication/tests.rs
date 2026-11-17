use crate::provider_publication::ProviderPublicationStore;
use aster_acme_dns::{
    DnsRecord, ProviderExecution,
    operation::{PublicationStore, RecoveryState},
};
use std::time::{Duration, Instant};
fn record() -> DnsRecord {
    DnsRecord {
        publication_id: "publication-1".into(),
        challenge_name: "_acme-challenge.example.com.".into(),
        cname_chain: vec!["_acme-challenge.example.com.".into()],
        name: "_acme-challenge.example.com.".into(),
        value: "value".into(),
        ttl_seconds: Some(120),
    }
}
fn scope() -> ProviderExecution {
    ProviderExecution {
        cancellation: tokio_util::sync::CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(2),
    }
}
#[tokio::test]
async fn checkpoints_survive_restart_and_identity_changes_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let store = ProviderPublicationStore::new(root.path().into());
    let mut session = store
        .open("com.example.dns.one", "zone-1", &record(), &scope())
        .await
        .unwrap();
    let state = RecoveryState {
        version: 1,
        data: serde_json::json!({"intent":"present"}),
    };
    session.save(state.clone()).await.unwrap();
    drop(session);
    let recovered = ProviderPublicationStore::new(root.path().into())
        .open("com.example.dns.one", "zone-1", &record(), &scope())
        .await
        .unwrap();
    assert_eq!(recovered.state(), Some(state));
    drop(recovered);
    for (backend, binding) in [
        ("com.example.dns.two", "zone-1"),
        ("com.example.dns.one", "zone-2"),
    ] {
        assert!(
            store
                .open(backend, binding, &record(), &scope())
                .await
                .is_err()
        );
    }
    let mut changed = record();
    changed.value = "changed".into();
    assert!(
        store
            .open("com.example.dns.one", "zone-1", &changed, &scope())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn rrset_lease_coordinates_different_publications_and_honors_cancellation() {
    let root = tempfile::tempdir().unwrap();
    let store = ProviderPublicationStore::new(root.path().into());
    let first = store
        .open("com.example.dns.one", "zone-1", &record(), &scope())
        .await
        .unwrap();
    let mut next = record();
    next.publication_id = "publication-2".into();
    next.value = "other".into();
    let short = ProviderExecution {
        deadline: Instant::now() + Duration::from_millis(60),
        ..scope()
    };
    assert!(
        store
            .open("com.example.dns.one", "auto", &next, &short)
            .await
            .is_err()
    );
    drop(first);
    assert!(
        store
            .open("com.example.dns.one", "zone-1", &next, &scope())
            .await
            .is_ok()
    );
    let cancelled = scope();
    cancelled.cancellation.cancel();
    assert!(
        store
            .open("com.example.dns.one", "zone-1", &next, &cancelled)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn corrupt_or_linked_checkpoints_are_never_reset() {
    let root = tempfile::tempdir().unwrap();
    let store = ProviderPublicationStore::new(root.path().into());
    drop(
        store
            .open("com.example.dns.one", "zone-1", &record(), &scope())
            .await
            .unwrap(),
    );
    let path = std::fs::read_dir(root.path().join("providers/.publications"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(&path, b"broken").unwrap();
    assert!(
        store
            .open("com.example.dns.one", "zone-1", &record(), &scope())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"broken");
}

#[test]
#[ignore = "child process fixture"]
fn lease_child() {
    let Ok(root) = std::env::var("ASTER_DNS_LEASE_CHILD_ROOT") else {
        return;
    };
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let store = ProviderPublicationStore::new(root.into());
        let mut second = record();
        second.publication_id = "another-process".into();
        let execution = ProviderExecution {
            deadline: Instant::now() + Duration::from_millis(80),
            ..scope()
        };
        assert!(
            store
                .open("com.example.dns.one", "zone-1", &second, &execution)
                .await
                .is_err()
        );
    });
}

#[tokio::test]
async fn remote_rrset_lock_excludes_another_process() {
    let root = tempfile::tempdir().unwrap();
    let store = ProviderPublicationStore::new(root.path().into());
    let _session = store
        .open("com.example.dns.one", "zone-1", &record(), &scope())
        .await
        .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "provider_publication::tests::lease_child",
        ])
        .env("ASTER_DNS_LEASE_CHILD_ROOT", root.path())
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn cancelled_save_keeps_its_lease_until_the_blocking_write_finishes() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let root = tempfile::tempdir().unwrap();
        let store = ProviderPublicationStore::new(root.path().into());
        let mut session = store
            .open("com.example.dns.one", "zone-1", &record(), &scope())
            .await
            .unwrap();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let save = tokio::spawn(async move {
            session
                .save(RecoveryState {
                    version: 1,
                    data: serde_json::json!({"saved":true}),
                })
                .await
        });
        tokio::task::yield_now().await;
        save.abort();
        let _ = save.await;
        let hash = crate::provider_publication::digest(&record().publication_id).unwrap();
        let path = crate::toml_file::object_lock(
            root.path(),
            crate::toml_file::ObjectKind::Provider,
            &format!("publication-{hash}"),
        )
        .unwrap();
        let contender = crate::toml_file::open_lock(&path).unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        let recovered = store
            .open("com.example.dns.one", "zone-1", &record(), &scope())
            .await
            .unwrap();
        assert_eq!(
            recovered.state().unwrap().data,
            serde_json::json!({"saved":true})
        );
    });
}

#[tokio::test]
async fn invalid_or_oversized_checkpoint_is_rejected_without_replacing_previous_state() {
    let root = tempfile::tempdir().unwrap();
    let store = ProviderPublicationStore::new(root.path().into());
    let mut session = store
        .open("com.example.dns.one", "zone-1", &record(), &scope())
        .await
        .unwrap();
    for state in [
        RecoveryState {
            version: 0,
            data: serde_json::json!({}),
        },
        RecoveryState {
            version: 1,
            data: serde_json::json!({"large":"x".repeat(32769)}),
        },
    ] {
        assert!(session.save(state).await.is_err());
        assert!(session.state().is_none());
    }
}
