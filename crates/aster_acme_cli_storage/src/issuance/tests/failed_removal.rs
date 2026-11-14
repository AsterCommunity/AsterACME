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
        let current = completed_generation(&f).await;
        let session = f.store.renew(&current.name, &f.account).await.unwrap();
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
        assert!(
            f.store
                .query(IssueQuery::default())
                .await
                .unwrap()
                .iter()
                .any(|candidate| candidate.operation_id == current.operation_id)
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

#[tokio::test]
async fn failed_cleanup_keeps_expired_unconfirmed_finalize_key_csr_and_journal() {
    let f = fixture().await;
    let session = f.store.create(&request(), &f.account).await.unwrap();
    let mut saved = session.record().await.unwrap();
    saved.new_order_intent_saved = true;
    saved.finalize_submitted = SubmissionState::Submitted;
    saved.order_url =
        Some(aster_acme_protocol::url::AcmeUrl::new("https://ca.example/order/1").unwrap());
    saved.order=Some(serde_json::from_value(serde_json::json!({"status":"ready","expires":"2000-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[],"finalize":"https://ca.example/finalize"})).unwrap());
    session.save(&saved).await.unwrap();
    drop(session);
    let generation = f.store.slot(&saved.name).join(saved.generation_name());
    let key = fs::read(generation.join("private-key.pk8")).unwrap();
    let csr = fs::read(generation.join("request.der")).unwrap();
    assert!(saved.expired(time::OffsetDateTime::now_utc()));
    assert!(!saved.failed_unresumable(time::OffsetDateTime::now_utc()));
    let removal = f
        .store
        .prepare_removal(&saved.name, RemovalScope::Failed)
        .await
        .unwrap();
    assert_eq!(removal.generations(), 0);
    removal.remove().await.unwrap();
    assert_eq!(fs::read(generation.join("private-key.pk8")).unwrap(), key);
    assert_eq!(fs::read(generation.join("request.der")).unwrap(), csr);
    assert!(generation.join("operation.toml").is_file());
}

#[tokio::test]
async fn bad_csr_external_publication_must_be_cleaned_before_certificate_removal() {
    let f = fixture().await;
    let mut external_request = request();
    external_request.solver_id = "dns_external".into();
    external_request.solver_config = serde_json::json!({
        "provider_instance_id":"test-provider",
        "provider_profile_version":1
    });
    let session = f.store.create(&external_request, &f.account).await.unwrap();
    let mut saved = session.record().await.unwrap();
    saved.phase = aster_acme_core::workflow::IssuancePhase::Finalizing;
    saved.finalize_rejection = Some(aster_acme::issuance::RequestFailure {
        status: 400,
        problem: None,
        retry_at: None,
    });
    let mut json = serde_json::to_value(&saved).unwrap();
    json["authorizations"] = serde_json::json!([{
        "url":"https://ca.example/auth/1",
        "resource":{"identifier":{"type":"dns","value":"example.com"},"status":"pending","challenges":[]},
        "challenge_url":null,
        "validation_requirement":{"method":"dns-01","name":"_acme-challenge.example.com","value":"expected"},
        "publication_id":"publication-1",
        "publication_plan":{"publication_id":"publication-1","challenge_name":"_acme-challenge.example.com.","cname_chain":["_acme-challenge.example.com."],"name":"_acme-challenge.example.com.","value":"expected","ttl_seconds":120},
        "publication_receipt":{"record_id":"receipt-1","ownership":"created","record_name":"_acme-challenge.example.com.","cname_chain":["_acme-challenge.example.com."]},
        "cleanup_pending":true,
        "acknowledgement":"not_submitted"
    }]);
    saved = serde_json::from_value(json).unwrap();
    session.save(&saved).await.unwrap();
    drop(session);

    let blocked = f
        .store
        .prepare_removal(
            &saved.name,
            RemovalScope::Operation(saved.operation_id.clone()),
        )
        .await
        .unwrap();
    assert!(blocked.remove().await.is_err());

    let session = f
        .store
        .open(&saved.name, &saved.operation_id)
        .await
        .unwrap();
    let mut cleaned = session.record().await.unwrap();
    for auth in &mut cleaned.authorizations {
        auth.cleanup_pending = false;
    }
    session.save(&cleaned).await.unwrap();
    drop(session);
    f.store
        .prepare_removal(
            &saved.name,
            RemovalScope::Operation(saved.operation_id.clone()),
        )
        .await
        .unwrap()
        .remove()
        .await
        .unwrap();
}
