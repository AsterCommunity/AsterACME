//! Deactivation signature, durable intent, failure and reconciliation contracts.
use crate::crypto::key_algorithm::KeyAlgorithm;
use aster_acme_protocol::jws::FlattenedJws;

use crate::account::tests::*;
use crate::transport::{TransportOptions, tests::server};

pub(super) async fn fixture(
    options: TransportOptions,
) -> (
    wiremock::MockServer,
    AccountService,
    Arc<MemoryStore>,
    AccountKey,
) {
    let (server, client) = server(options).await;
    let directory = client.directory_url().clone();
    let key = AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let thumbprint = key.jwk().unwrap().thumbprint().unwrap();
    let store = Arc::new(MemoryStore::default());
    *store.record.lock().await = Some(AccountRecord {
        key_algorithm: KeyAlgorithm::EcdsaP256,
        user_agent: None,
        times: crate::account::AccountTimes::default(),
        account_id: account_id(&directory, &thumbprint),
        directory_url: directory,
        key_thumbprint: thumbprint,
        account_url: Some(AcmeUrl::new(&format!("{}/account/1", server.uri())).unwrap()),
        contacts: vec!["mailto:local@example.com".into()],
        server_contacts: Some(vec![]),
        last_status: Some(AccountStatus::Valid),
        deactivation: DeactivationState::NotRequested,
        key_rotation: None,
        accepted_terms_url: None,
        state: AccountRecordState::Registered,
    });
    (
        server,
        AccountService::new(Arc::new(client), store.clone()),
        store,
        key,
    )
}

fn posts(requests: &[wiremock::Request]) -> Vec<&wiremock::Request> {
    requests
        .iter()
        .filter(|request| request.method == "POST")
        .collect()
}

#[tokio::test]
async fn deactivation_signs_exact_status_with_kid_and_retains_local_identity() {
    let (server, service, store, key) = fixture(local_options()).await;
    let before = store.record.lock().await.clone().unwrap();
    Mock::given(method("POST"))
        .and(path("/account/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "done")
                .set_body_json(serde_json::json!({"status":"deactivated","contact":[]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = service.deactivate(&key).await.unwrap();
    assert_eq!(result.status, AccountStatus::Deactivated);
    let record = store.record.lock().await.clone().unwrap();
    assert_eq!(record.deactivation, DeactivationState::Confirmed);
    assert_eq!(record.last_status, Some(AccountStatus::Deactivated));
    assert_eq!(record.contacts, before.contacts);
    assert_eq!(record.account_id, before.account_id);
    assert_eq!(record.key_thumbprint, before.key_thumbprint);
    let requests = server.received_requests().await.unwrap();
    let posts = posts(&requests);
    assert_eq!(posts.len(), 1);
    let jws: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.protected).unwrap()).unwrap();
    assert_eq!(header["kid"], before.account_url.as_ref().unwrap().as_str());
    assert_eq!(header["url"], before.account_url.as_ref().unwrap().as_str());
    assert!(header.get("jwk").is_none());
    assert_eq!(
        URL_SAFE_NO_PAD.decode(jws.payload).unwrap(),
        br#"{"status":"deactivated"}"#
    );
    // Repeated calls return saved confirmation without another POST.
    assert_eq!(
        service.deactivate(&key).await.unwrap().status,
        AccountStatus::Deactivated
    );
    assert_eq!(posts.len(), 1);
    server.verify().await;
}

#[tokio::test]
async fn invalid_identity_missing_url_inactive_state_and_failed_intent_never_post() {
    for case in 0..6 {
        let (server, service, store, key) = fixture(local_options()).await;
        let mut record = store.record.lock().await.clone().unwrap();
        match case {
            0 => record.key_thumbprint = "different".into(),
            1 => record.account_url = None,
            2 => record.last_status = Some(AccountStatus::Revoked),
            3 => record.last_status = Some(AccountStatus::Unknown("future".into())),
            4 => record.deactivation = DeactivationState::Pending,
            5 => store.fail_save.store(true, Ordering::SeqCst),
            _ => unreachable!(),
        }
        *store.record.lock().await = Some(record);
        assert!(service.deactivate(&key).await.is_err());
        assert_eq!(posts(&server.received_requests().await.unwrap()).len(), 0);
    }
}

#[tokio::test]
async fn timeout_rate_limit_malformed_and_unexpected_status_preserve_uncertain_intent() {
    for response in [
        ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(2)),
        ResponseTemplate::new(429)
            .set_body_json(serde_json::json!({"type":"urn:ietf:params:acme:error:rateLimited"})),
        ResponseTemplate::new(503).set_body_string("unavailable"),
        ResponseTemplate::new(200).set_body_string("invalid JSON"),
        ResponseTemplate::new(201).set_body_json(serde_json::json!({"status":"deactivated"})),
        ResponseTemplate::new(200).set_body_json(serde_json::json!({"status":"valid"})),
    ] {
        let (server, service, store, key) = fixture(TransportOptions {
            request_timeout: std::time::Duration::from_secs(1),
            ..local_options()
        })
        .await;
        Mock::given(method("POST"))
            .and(path("/account/1"))
            .respond_with(response.insert_header("Replay-Nonce", "failure"))
            .expect(1)
            .mount(&server)
            .await;
        assert!(service.deactivate(&key).await.is_err());
        let record = store.record.lock().await.clone().unwrap();
        assert_eq!(record.deactivation, DeactivationState::Pending);
        assert_eq!(record.last_status, Some(AccountStatus::Valid));
        assert!(matches!(
            service.deactivate(&key).await,
            Err(AccountError::DeactivationUncertain)
        ));
        assert_eq!(posts(&server.received_requests().await.unwrap()).len(), 1);
    }
}

#[tokio::test]
async fn cancellation_and_failed_confirmation_save_preserve_pending_state() {
    let (server, service, store, key) = fixture(local_options()).await;
    Mock::given(method("POST"))
        .and(path("/account/1"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(2)))
        .mount(&server)
        .await;
    let key = Arc::new(key);
    let task = tokio::spawn({
        let key = key.clone();
        async move { service.deactivate(key.as_ref()).await }
    });
    for _ in 0..100 {
        if !posts(&server.received_requests().await.unwrap()).is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(posts(&server.received_requests().await.unwrap()).len(), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        store.record.lock().await.as_ref().unwrap().deactivation,
        DeactivationState::Pending
    );

    let (server, service, store, key) = fixture(local_options()).await;
    let fail_store = store.clone();
    Mock::given(method("POST"))
        .and(path("/account/1"))
        .respond_with(move |_: &wiremock::Request| {
            fail_store.fail_save.store(true, Ordering::SeqCst);
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "done")
                .set_body_json(serde_json::json!({"status":"deactivated"}))
        })
        .mount(&server)
        .await;
    assert!(matches!(
        service.deactivate(&key).await,
        Err(AccountError::Store(_))
    ));
    assert_eq!(
        store.record.lock().await.as_ref().unwrap().deactivation,
        DeactivationState::Pending
    );
}

#[tokio::test]
async fn inspection_resolves_pending_only_from_an_authoritative_response() {
    for status in ["valid", "deactivated", "unauthorized"] {
        let (server, service, store, key) = fixture(local_options()).await;
        store.record.lock().await.as_mut().unwrap().deactivation = DeactivationState::Pending;
        let response = match status {
            "unauthorized" => ResponseTemplate::new(401).set_body_json(
                serde_json::json!({"type":"urn:ietf:params:acme:error:unauthorized"}),
            ),
            _ => ResponseTemplate::new(200).set_body_json(serde_json::json!({"status":status})),
        };
        Mock::given(method("POST"))
            .and(path("/account/1"))
            .respond_with(response.insert_header("Replay-Nonce", "read"))
            .expect(1)
            .mount(&server)
            .await;
        let result = service.inspect(&key).await;
        let record = store.record.lock().await.clone().unwrap();
        match status {
            "valid" => {
                result.unwrap();
                assert_eq!(record.deactivation, DeactivationState::NotRequested);
            }
            "deactivated" => {
                result.unwrap();
                assert_eq!(record.deactivation, DeactivationState::Confirmed);
            }
            "unauthorized" => {
                assert!(result.is_err());
                assert_eq!(record.deactivation, DeactivationState::Pending);
            }
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn only_bad_nonce_is_retried_with_a_fresh_signature() {
    let (server, service, store, key) = fixture(local_options()).await;
    Mock::given(method("POST"))
        .and(path("/account/1"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("Replay-Nonce", "retry")
                .set_body_json(serde_json::json!({"type":"urn:ietf:params:acme:error:badNonce"})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/account/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "done")
                .set_body_json(serde_json::json!({"status":"deactivated"})),
        )
        .with_priority(10)
        .mount(&server)
        .await;
    service.deactivate(&key).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    let posts = posts(&requests);
    assert_eq!(posts.len(), 2);
    let first: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
    let retry: FlattenedJws = serde_json::from_slice(&posts[1].body).unwrap();
    assert_eq!(first.payload, retry.payload);
    assert_ne!(first.signature, retry.signature);
    assert_eq!(
        store.record.lock().await.as_ref().unwrap().deactivation,
        DeactivationState::Confirmed
    );
}
