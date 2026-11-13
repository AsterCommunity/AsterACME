//! Failed cleanup is conservative, revalidated under lease and local-only.
use crate::issuance::removal::RemovalScope;
use crate::issuance::tests::*;
fn rejection(status: u16) -> aster_acme::issuance::RequestFailure {
    aster_acme::issuance::RequestFailure {
        status,
        problem: None,
        retry_at: None,
    }
}

#[tokio::test]
async fn failed_scope_selects_definitive_failures_but_preserves_unknown_outcomes_and_success() {
    for (status, removes) in [
        (400, true),
        (403, true),
        (408, false),
        (429, false),
        (500, false),
        (503, false),
    ] {
        let f = fixture().await;
        let session = f.store.create(&request(), &f.account).await.unwrap();
        let mut record = session.record().await.unwrap();
        record.new_order_intent_saved = true;
        record.creation_failure = Some(rejection(status));
        session.save(&record).await.unwrap();
        drop(session);
        let records = f
            .store
            .query(IssueQuery {
                failed_at: Some(time::OffsetDateTime::now_utc()),
                ..IssueQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(records.len(), usize::from(removes));
        let removal = f
            .store
            .prepare_removal(&record.name, RemovalScope::Failed)
            .await
            .unwrap();
        assert_eq!(removal.generations(), usize::from(removes));
        assert!(!removal.removes_in_use());
        removal.remove().await.unwrap();
        assert_eq!(
            f.store
                .slot(&record.name)
                .join(record.generation_name())
                .exists(),
            !removes
        );
    }
}

#[tokio::test]
async fn failed_renewal_cleanup_retains_current_history_user_files_and_lock_identity() {
    let f = fixture().await;
    let history = completed_generation(&f).await;
    let current = completed_generation(&f).await;
    let session = f.store.renew(&current.name, &f.account).await.unwrap();
    let mut failed = session.record().await.unwrap();
    failed.creation_failure = Some(rejection(400));
    failed.new_order_intent_saved = true;
    session.save(&failed).await.unwrap();
    drop(session);
    let slot = f.store.slot(&current.name);
    let generation = slot.join(failed.generation_name());
    fs::write(generation.join("user-note"), b"retain").unwrap();
    let removal = f
        .store
        .prepare_removal(&current.name, RemovalScope::Failed)
        .await
        .unwrap();
    assert_eq!(removal.records()[0].operation_id, failed.operation_id);
    assert!(!removal.removes_in_use());
    removal.remove().await.unwrap();
    assert_eq!(fs::read(generation.join("user-note")).unwrap(), b"retain");
    assert!(!generation.join("private-key.pk8").exists());
    assert!(
        slot.join(history.generation_name())
            .join("private-key.pk8")
            .exists()
    );
    assert!(
        slot.join(current.generation_name())
            .join("private-key.pk8")
            .exists()
    );
    assert_eq!(
        selection(&slot).unwrap().cert.in_use,
        Some(current.operation_id)
    );
    let empty = f
        .store
        .prepare_removal(&current.name, RemovalScope::Failed)
        .await
        .unwrap();
    assert_eq!(empty.generations(), 0);
    empty.remove().await.unwrap();
}

#[tokio::test]
async fn failed_selection_is_rechecked_under_lease_instead_of_trusting_inventory_snapshot() {
    let f = fixture().await;
    let session = f.store.create(&request(), &f.account).await.unwrap();
    let mut saved = session.record().await.unwrap();
    saved.creation_failure = Some(rejection(400));
    session.save(&saved).await.unwrap();
    drop(session);
    assert_eq!(
        f.store
            .query(IssueQuery {
                failed_at: Some(time::OffsetDateTime::now_utc()),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .len(),
        1
    );
    let session = f
        .store
        .open(&saved.name, &saved.operation_id)
        .await
        .unwrap();
    saved.creation_failure = Some(rejection(503));
    session.save(&saved).await.unwrap();
    drop(session);
    let removal = f
        .store
        .prepare_removal(&saved.name, RemovalScope::Failed)
        .await
        .unwrap();
    assert_eq!(removal.generations(), 0);
    removal.remove().await.unwrap();
    assert!(
        f.store
            .slot(&saved.name)
            .join(saved.generation_name())
            .join("private-key.pk8")
            .exists()
    );
}
