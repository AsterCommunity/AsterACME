//! Metadata-only retry checkpoints protect against stale workers and duplicate accounting.
use crate::issuance::tests::{completed_generation, fixture};
use aster_acme::storage::issuance::IssueStore;
use time::OffsetDateTime;

#[tokio::test]
async fn child_submission_evidence_blocks_new_orders_even_without_parent_retry_checkpoint() {
    use aster_acme::issuance::{IssueError, RequestFailure};
    for status in [None, Some(408), Some(429), Some(500)] {
        let f = fixture().await;
        let current = completed_generation(&f).await;
        let child = f.store.renew(&current.name, &f.account).await.unwrap();
        let mut pending = child.record().await.unwrap();
        pending.new_order_intent_saved = true;
        pending.creation_failure = status.map(|status| RequestFailure {
            status,
            problem: None,
            retry_at: Some(OffsetDateTime::now_utc() + time::Duration::hours(1)),
        });
        child.save(&pending).await.unwrap();
        drop(child);
        let error = f
            .store
            .prepare_renewal(&current.name, &current.operation_id, true, &f.account)
            .await
            .err()
            .unwrap();
        match status {
            None => assert!(matches!(error, IssueError::CreationUncertain)),
            Some(429) => assert!(matches!(error, IssueError::Transport(_))),
            Some(_) => assert!(matches!(error, IssueError::MutationUncertain(_))),
        }
        assert_eq!(
            f.store
                .query(aster_acme::storage::query::IssueQuery::default())
                .await
                .unwrap()
                .len(),
            2
        );
    }
}

#[tokio::test]
async fn definitive_creation_rejection_keeps_history_and_allows_a_fresh_renewal() {
    let f = fixture().await;
    let current = completed_generation(&f).await;
    let child = f.store.renew(&current.name, &f.account).await.unwrap();
    let mut rejected = child.record().await.unwrap();
    rejected.new_order_intent_saved = true;
    rejected.creation_failure = Some(aster_acme::issuance::RequestFailure {
        status: 400,
        problem: None,
        retry_at: None,
    });
    child.save(&rejected).await.unwrap();
    drop(child);
    let next = f.store.renew(&current.name, &f.account).await.unwrap();
    assert_ne!(
        next.record().await.unwrap().operation_id,
        rejected.operation_id
    );
}

#[tokio::test]
async fn preparation_failure_is_compare_and_update_and_never_loads_private_material() {
    let mut f = fixture().await;
    // Both contenders must acquire the lease to test compare-and-update.
    // Durable I/O and worker scheduling on Windows can exceed the shared
    // fixture's 100 ms contention budget; timeout behavior is tested separately.
    f.store = crate::issuance::CliIssueStore::new(
        f.temp.path().into(),
        std::time::Duration::from_secs(5),
    );
    let current = completed_generation(&f).await;
    let key = f
        .store
        .slot(&current.name)
        .join(current.generation_name())
        .join("private-key.pk8");
    std::fs::write(&key, b"unavailable key").unwrap();
    let now = OffsetDateTime::now_utc();
    let (first, second) = tokio::join!(
        f.store
            .record_renewal_preparation_failure(&current, true, now),
        f.store
            .record_renewal_preparation_failure(&current, true, now),
    );
    let results = [first.unwrap(), second.unwrap()];
    assert_eq!(results.iter().filter(|state| state.is_some()).count(), 1);
    let saved = f
        .store
        .open_observation(&current.name, &current.operation_id)
        .await
        .unwrap()
        .record()
        .await
        .unwrap();
    let retry = saved.renewal_retry.unwrap();
    assert_eq!(retry.failures, 1);
    assert_eq!(retry.retry_at, Some(now + time::Duration::minutes(1)));
    assert_eq!(std::fs::read(&key).unwrap(), b"unavailable key");
}

#[tokio::test]
async fn preparation_failure_lock_timeout_leaves_retry_and_private_material_unchanged() {
    let f = fixture().await;
    let current = completed_generation(&f).await;
    let key = f
        .store
        .slot(&current.name)
        .join(current.generation_name())
        .join("private-key.pk8");
    std::fs::write(&key, b"unavailable key").unwrap();
    let session = f
        .store
        .open_observation(&current.name, &current.operation_id)
        .await
        .unwrap();
    // Hold the actual certificate lease through the entire competing call,
    // rather than guessing which worker wins using sleeps or elapsed time.
    let before = session.record().await.unwrap();
    let error = f
        .store
        .record_renewal_preparation_failure(&current, true, OffsetDateTime::now_utc())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        aster_acme::issuance::IssueError::LeaseUnavailable("certificate", _)
    ));
    let after = session.record().await.unwrap();
    assert_eq!(after.operation_id, before.operation_id);
    assert_eq!(after.renewal_retry, before.renewal_retry);
    assert!(after.renewal_retry.is_none());
    assert_eq!(std::fs::read(&key).unwrap(), b"unavailable key");
    drop(session);

    // Dropping the lease must let the same store complete the update; timeout
    // does not consume a failure count or leave a lease behind.
    let updated = f
        .store
        .record_renewal_preparation_failure(&current, true, OffsetDateTime::now_utc())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.failures, 1);
}

#[tokio::test]
async fn stale_preparation_failure_does_not_overwrite_a_new_selected_generation() {
    let f = fixture().await;
    let old = completed_generation(&f).await;
    let current = completed_generation(&f).await;
    assert!(
        f.store
            .record_renewal_preparation_failure(&old, true, OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_none()
    );
    let saved = f
        .store
        .open_observation(&current.name, &current.operation_id)
        .await
        .unwrap()
        .record()
        .await
        .unwrap();
    assert!(saved.renewal_retry.is_none());
    assert!(saved.is_in_use);
}

#[tokio::test]
async fn preparation_failure_respects_normal_schedule_backoff_and_ca_deadline() {
    let f = fixture().await;
    let current = completed_generation(&f).await;
    let now = OffsetDateTime::now_utc();
    assert!(
        f.store
            .record_renewal_preparation_failure(&current, false, now)
            .await
            .unwrap()
            .is_none()
    );
    f.store
        .record_renewal_preparation_failure(&current, true, now)
        .await
        .unwrap()
        .unwrap();
    let session = f
        .store
        .open_observation(&current.name, &current.operation_id)
        .await
        .unwrap();
    let mut saved = session.record().await.unwrap();
    drop(session);
    assert!(
        f.store
            .record_renewal_preparation_failure(&saved, false, now)
            .await
            .unwrap()
            .is_none()
    );
    saved.renewal_retry.as_mut().unwrap().ca_retry_at = Some(now + time::Duration::hours(1));
    let session = f
        .store
        .open_observation(&saved.name, &saved.operation_id)
        .await
        .unwrap();
    session.save(&saved).await.unwrap();
    drop(session);
    assert!(
        f.store
            .record_renewal_preparation_failure(&saved, true, now)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn expired_early_renewal_does_not_override_future_renewal_schedule() {
    let f = fixture().await;
    let current = completed_generation(&f).await;
    let child = f.store.renew(&current.name, &f.account).await.unwrap();
    let mut saved = child.record().await.unwrap();
    saved.order_url =
        Some(aster_acme_protocol::url::AcmeUrl::new("https://ca.example/order/early").unwrap());
    saved.order=Some(serde_json::from_value(serde_json::json!({"status":"pending","expires":"2000-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[],"finalize":"https://ca.example/finalize"})).unwrap());
    child.save(&saved).await.unwrap();
    drop(child);
    let result = f
        .store
        .prepare_renewal(&current.name, &current.operation_id, false, &f.account)
        .await
        .unwrap();
    assert!(matches!(
        result,
        crate::issuance::RenewalPreparation::NotDue(_)
    ));
    assert_eq!(
        f.store
            .query(aster_acme::storage::query::IssueQuery::default())
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn finalize_rejection_retry_after_blocks_new_generation_even_with_now() {
    let f = fixture().await;
    let current = completed_generation(&f).await;
    let child = f.store.renew(&current.name, &f.account).await.unwrap();
    let mut saved = child.record().await.unwrap();
    saved.finalize_rejection = Some(aster_acme::issuance::RequestFailure {
        status: 429,
        problem: None,
        retry_at: Some(OffsetDateTime::now_utc() + time::Duration::hours(1)),
    });
    child.save(&saved).await.unwrap();
    drop(child);
    assert!(matches!(
        f.store
            .prepare_renewal(&current.name, &current.operation_id, true, &f.account)
            .await,
        Err(aster_acme::issuance::IssueError::Transport(_))
    ));
    assert_eq!(
        f.store
            .query(aster_acme::storage::query::IssueQuery::default())
            .await
            .unwrap()
            .len(),
        2
    );
}
