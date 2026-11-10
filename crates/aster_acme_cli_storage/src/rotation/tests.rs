//! Actual file transactions against a loopback ACME server, including restart boundaries.
use super::*;
use aster_acme::account::{AccountKeyStore, AccountStore};
use aster_acme::{
    account::{AccountService, AccountTimes},
    transport::{AcmeClient, TransportOptions},
};
use aster_acme_core::{
    account::{AccountRecordState, DeactivationState, KeyRotation},
    protocol::AccountStatus,
};
use aster_acme_protocol::{
    account::AccountObject,
    directory::{Directory, DirectoryMeta},
    jws::FlattenedJws,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::Duration;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct Fixture {
    temp: tempfile::TempDir,
    server: MockServer,
    store: Arc<CliAccountStore>,
    service: Arc<AccountService>,
    before: AccountRecord,
}

async fn setup(endpoint: bool, timeout: Duration) -> Fixture {
    let server = MockServer::start().await;
    let url = |path: &str| AcmeUrl::new(&format!("{}{path}", server.uri())).unwrap();
    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "response_nonce")
                .set_body_json(Directory {
                    new_order: None,
                    new_nonce: url("/nonce"),
                    new_account: url("/unused"),
                    renewal_info: None,
                    revoke_cert: None,
                    key_change: endpoint.then(|| url("/vendor/rollover")),
                    meta: DirectoryMeta::default(),
                }),
        )
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "fresh"))
        .mount(&server)
        .await;
    let directory = url("/directory");
    let temp = tempfile::tempdir().unwrap();
    let store =
        Arc::new(CliAccountStore::open(temp.path(), "work", Duration::from_secs(1)).unwrap());
    let key = store.signer(&directory, "work", true).await.unwrap();
    let thumb = thumbprint(key.as_ref()).unwrap();
    let mut before = store.load(&directory, &thumb).await.unwrap().unwrap();
    before.state = AccountRecordState::Registered;
    before.account_url = Some(url("/account/%41?exact=%2f"));
    before.last_status = Some(AccountStatus::Valid);
    let at = time::OffsetDateTime::from_unix_timestamp(100).unwrap();
    before.times = AccountTimes {
        registered_at: Some(at),
        last_status_at: Some(at),
        last_used_at: Some(at),
    };
    before.contacts = vec!["mailto:local@example.org".into()];
    before.user_agent = Some("account-custom/1".into());
    before.server_contacts = None;
    before.deactivation = DeactivationState::NotRequested;
    store.save(&before).await.unwrap();
    let client = AcmeClient::discover(
        directory,
        TransportOptions {
            request_timeout: timeout,
            allow_loopback_http: true,
            ..TransportOptions::default()
        },
    )
    .await
    .unwrap();
    Fixture {
        temp,
        server,
        service: Arc::new(AccountService::new(Arc::new(client), store.clone())),
        store,
        before,
    }
}

fn post_count(requests: &[wiremock::Request], suffix: &str) -> usize {
    requests
        .iter()
        .filter(|request| request.method == "POST" && request.url.path() == suffix)
        .count()
}

#[tokio::test]
async fn empty_success_commits_both_keys_preserving_account_identity_and_status_time() {
    let fixture = setup(true, Duration::from_secs(30)).await;
    Mock::given(method("POST"))
        .and(path("/vendor/rollover"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "response_nonce"))
        .expect(1)
        .mount(&fixture.server)
        .await;
    let result = fixture
        .service
        .rotate_key(fixture.store.as_ref())
        .await
        .unwrap();
    assert_ne!(result.key_thumbprint, fixture.before.key_thumbprint);
    assert_eq!(result.account_id, fixture.before.account_id);
    assert_eq!(result.account_url, fixture.before.account_url);
    assert_eq!(result.contacts, fixture.before.contacts);
    assert_eq!(result.user_agent, fixture.before.user_agent);
    assert_eq!(result.server_contacts, fixture.before.server_contacts);
    assert_eq!(
        result.times.registered_at,
        fixture.before.times.registered_at
    );
    assert_eq!(
        result.times.last_status_at,
        fixture.before.times.last_status_at
    );
    assert!(result.times.last_used_at > fixture.before.times.last_used_at);
    assert_eq!(result.key_rotation, None);
    let restarted =
        CliAccountStore::open(fixture.temp.path(), "work", Duration::from_secs(1)).unwrap();
    let signer = restarted
        .signer(&result.directory_url, "work", false)
        .await
        .unwrap();
    assert_eq!(thumbprint(signer.as_ref()).unwrap(), result.key_thumbprint);
    assert_eq!(
        restarted
            .load(&result.directory_url, &result.key_thumbprint)
            .await
            .unwrap(),
        Some(result)
    );
    assert_eq!(fs::read_dir(restarted.account_slot()).unwrap().count(), 2);
    let requests = fixture.server.received_requests().await.unwrap();
    let post = requests
        .iter()
        .find(|request| request.method == "POST")
        .unwrap();
    let outer: FlattenedJws = serde_json::from_slice(&post.body).unwrap();
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(outer.protected).unwrap()).unwrap();
    let inner: FlattenedJws =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(outer.payload).unwrap()).unwrap();
    let inner_header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(inner.protected).unwrap()).unwrap();
    assert_eq!(
        header["kid"],
        fixture.before.account_url.as_ref().unwrap().as_str()
    );
    assert_eq!(header["url"], inner_header["url"]);
    assert!(inner_header.get("nonce").is_none());
}

#[tokio::test]
async fn cancelled_request_reconciles_saved_new_key_without_replaying_rollover() {
    let fixture = setup(true, Duration::from_secs(30)).await;
    Mock::given(method("POST"))
        .and(path("/vendor/rollover"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "response_nonce")
                .set_delay(Duration::from_secs(10)),
        )
        .expect(1)
        .mount(&fixture.server)
        .await;
    let task = tokio::spawn({
        let service = fixture.service.clone();
        let store = fixture.store.clone();
        async move { service.rotate_key(store.as_ref()).await }
    });
    for _ in 0..200 {
        if post_count(
            &fixture.server.received_requests().await.unwrap(),
            "/vendor/rollover",
        ) > 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        post_count(
            &fixture.server.received_requests().await.unwrap(),
            "/vendor/rollover"
        ),
        1
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let pending = fixture
        .store
        .load(
            &fixture.before.directory_url,
            &fixture.before.key_thumbprint,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pending.key_rotation.as_ref().unwrap().phase,
        KeyRotationPhase::Pending
    );
    assert!(
        fixture
            .store
            .account_slot()
            .join("account-key.next.pk8")
            .exists()
    );
    let object = AccountObject {
        status: AccountStatus::Valid,
        contact: Some(vec![]),
        external_account_binding: None,
    };
    Mock::given(method("POST"))
        .and(path("/account/%41"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "response_nonce")
                .set_body_json(object),
        )
        .expect(1)
        .mount(&fixture.server)
        .await;
    let result = fixture
        .service
        .rotate_key(fixture.store.as_ref())
        .await
        .unwrap();
    assert_eq!(
        result.key_thumbprint,
        pending.key_rotation.unwrap().new_thumbprint
    );
    assert_eq!(
        post_count(
            &fixture.server.received_requests().await.unwrap(),
            "/vendor/rollover"
        ),
        1
    );
    assert_eq!(
        result.times.registered_at,
        fixture.before.times.registered_at
    );
}

#[tokio::test]
async fn explicit_rejections_and_pending_unauthorized_never_replace_primary_key() {
    for status in [400, 409, 429, 503] {
        let fixture = setup(true, Duration::from_secs(30)).await;
        let primary = fixture.store.account_slot().join("account-key.pk8");
        let before = fs::read(&primary).unwrap();
        Mock::given(method("POST"))
            .and(path("/vendor/rollover"))
            .respond_with(ResponseTemplate::new(status))
            .expect(1)
            .mount(&fixture.server)
            .await;
        assert!(
            fixture
                .service
                .rotate_key(fixture.store.as_ref())
                .await
                .is_err()
        );
        assert_eq!(fs::read(&primary).unwrap(), before);
        Mock::given(method("POST"))
            .and(path("/account/%41"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&fixture.server)
            .await;
        assert!(matches!(
            fixture.service.rotate_key(fixture.store.as_ref()).await,
            Err(aster_acme::account::AccountError::KeyRotationUncertain)
        ));
        assert_eq!(
            post_count(
                &fixture.server.received_requests().await.unwrap(),
                "/vendor/rollover"
            ),
            1
        );
        assert_eq!(fs::read(primary).unwrap(), before);
    }
}

#[tokio::test]
async fn confirmed_partial_local_swap_resumes_without_a_key_change_endpoint() {
    let fixture = setup(false, Duration::from_secs(30)).await;
    let session = fixture
        .store
        .rotation(&fixture.before.directory_url)
        .await
        .unwrap();
    let new = session.stage().await.unwrap();
    let mut confirmed = fixture.before.clone();
    confirmed.key_rotation = Some(KeyRotation {
        new_thumbprint: thumbprint(new.as_ref()).unwrap(),
        phase: KeyRotationPhase::Confirmed,
    });
    session.save(&confirmed).await.unwrap();
    let slot = fixture.store.account_slot();
    atomic_write(
        &slot.join("account-key.previous.pk8"),
        &fs::read(slot.join("account-key.pk8")).unwrap(),
    )
    .unwrap();
    atomic_write(
        &slot.join("account-key.pk8"),
        &fs::read(slot.join("account-key.next.pk8")).unwrap(),
    )
    .unwrap();
    drop(session);
    let record = fixture
        .service
        .rotate_key(fixture.store.as_ref())
        .await
        .unwrap();
    assert_eq!(record.key_thumbprint, thumbprint(new.as_ref()).unwrap());
    assert_eq!(
        post_count(
            &fixture.server.received_requests().await.unwrap(),
            "/vendor/rollover"
        ),
        0
    );
    assert_eq!(record.account_id, fixture.before.account_id);
}

#[tokio::test]
async fn missing_endpoint_missing_stage_and_same_key_fail_before_post() {
    let fixture = setup(false, Duration::from_secs(30)).await;
    assert!(matches!(
        fixture.service.rotate_key(fixture.store.as_ref()).await,
        Err(aster_acme::account::AccountError::KeyChangeUnavailable)
    ));
    assert!(
        !fixture
            .store
            .account_slot()
            .join("account-key.next.pk8")
            .exists()
    );
    let fixture = setup(true, Duration::from_secs(30)).await;
    let mut record = fixture.before.clone();
    record.key_rotation = Some(KeyRotation {
        new_thumbprint: "x".repeat(43),
        phase: KeyRotationPhase::Pending,
    });
    fixture.store.save(&record).await.unwrap();
    assert!(
        fixture
            .service
            .rotate_key(fixture.store.as_ref())
            .await
            .is_err()
    );
    assert_eq!(
        post_count(
            &fixture.server.received_requests().await.unwrap(),
            "/vendor/rollover"
        ),
        0
    );
    record.key_rotation = Some(KeyRotation {
        new_thumbprint: record.key_thumbprint.clone(),
        phase: KeyRotationPhase::Pending,
    });
    fixture.store.save(&record).await.unwrap();
    let slot = fixture.store.account_slot();
    atomic_write(
        &slot.join("account-key.next.pk8"),
        &fs::read(slot.join("account-key.pk8")).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        fixture.service.rotate_key(fixture.store.as_ref()).await,
        Err(aster_acme::account::AccountError::IdentityMismatch)
    ));
    assert_eq!(
        post_count(
            &fixture.server.received_requests().await.unwrap(),
            "/vendor/rollover"
        ),
        0
    );
}

#[tokio::test]
async fn timeout_keeps_both_keys_and_never_automatically_reposts_key_change() {
    let fixture = setup(true, Duration::from_millis(250)).await;
    let primary = fixture.store.account_slot().join("account-key.pk8");
    let original = fs::read(&primary).unwrap();
    Mock::given(method("POST"))
        .and(path("/vendor/rollover"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "late")
                .set_delay(Duration::from_secs(1)),
        )
        .expect(1)
        .mount(&fixture.server)
        .await;
    assert!(
        fixture
            .service
            .rotate_key(fixture.store.as_ref())
            .await
            .is_err()
    );
    let record = fixture
        .store
        .load(
            &fixture.before.directory_url,
            &fixture.before.key_thumbprint,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.key_rotation.unwrap().phase,
        KeyRotationPhase::Pending
    );
    assert_eq!(fs::read(&primary).unwrap(), original);
    Mock::given(method("POST"))
        .and(path("/account/%41"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&fixture.server)
        .await;
    assert!(matches!(
        fixture.service.rotate_key(fixture.store.as_ref()).await,
        Err(aster_acme::account::AccountError::KeyRotationUncertain)
    ));
    assert_eq!(
        post_count(
            &fixture.server.received_requests().await.unwrap(),
            "/vendor/rollover"
        ),
        1
    );
    assert_eq!(fs::read(primary).unwrap(), original);
}

#[tokio::test]
async fn bad_nonce_retries_only_the_outer_signature_with_the_same_durable_new_key() {
    let fixture = setup(true, Duration::from_secs(30)).await;
    Mock::given(method("POST"))
        .and(path("/vendor/rollover"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("Replay-Nonce", "replacement_nonce")
                .set_body_json(serde_json::json!({"type":"urn:ietf:params:acme:error:badNonce"})),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&fixture.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/vendor/rollover"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "success_nonce"))
        .with_priority(10)
        .expect(1)
        .mount(&fixture.server)
        .await;
    let result = fixture
        .service
        .rotate_key(fixture.store.as_ref())
        .await
        .unwrap();
    let requests = fixture.server.received_requests().await.unwrap();
    let posts: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "POST")
        .collect();
    assert_eq!(posts.len(), 2);
    let first: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
    let second: FlattenedJws = serde_json::from_slice(&posts[1].body).unwrap();
    assert_eq!(first.payload, second.payload);
    assert_ne!(first.signature, second.signature);
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(second.protected).unwrap()).unwrap();
    assert_eq!(header["nonce"], "replacement_nonce");
    assert_ne!(result.key_thumbprint, fixture.before.key_thumbprint);
}

#[tokio::test]
async fn definitive_conflict_problem_preserves_old_identity_and_allows_later_operations() {
    let fixture = setup(true, Duration::from_secs(30)).await;
    Mock::given(method("POST")).and(path("/vendor/rollover"))
        .respond_with(ResponseTemplate::new(409).insert_header("Location",format!("{}/other-account",fixture.server.uri()))
            .set_body_json(serde_json::json!({"type":"urn:ietf:params:acme:error:malformed","detail":"key already in use"})))
        .expect(1).mount(&fixture.server).await;
    assert!(
        fixture
            .service
            .rotate_key(fixture.store.as_ref())
            .await
            .is_err()
    );
    let record = fixture
        .store
        .load(
            &fixture.before.directory_url,
            &fixture.before.key_thumbprint,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record, fixture.before);
    let key = fixture
        .store
        .signer(&fixture.before.directory_url, "work", false)
        .await
        .unwrap();
    assert_eq!(
        thumbprint(key.as_ref()).unwrap(),
        fixture.before.key_thumbprint
    );
    assert!(
        !fixture
            .store
            .account_slot()
            .join("account-key.next.pk8")
            .exists()
    );
}

#[tokio::test]
async fn rotation_commit_rejects_changed_identity_and_unconfirmed_journal() {
    let fixture = setup(true, Duration::from_secs(30)).await;
    let session = fixture
        .store
        .rotation(&fixture.before.directory_url)
        .await
        .unwrap();
    let new = session.stage().await.unwrap();
    let mut record = fixture.before.clone();
    record.key_rotation = Some(KeyRotation {
        new_thumbprint: thumbprint(new.as_ref()).unwrap(),
        phase: KeyRotationPhase::Pending,
    });
    session.save(&record).await.unwrap();
    assert!(session.commit(&record).await.is_err());
    record.account_id = "x".repeat(43);
    assert!(session.save(&record).await.is_err());
    assert!(session.commit(&record).await.is_err());
    assert_eq!(
        thumbprint(
            load_key(&fixture.store.account_slot().join("account-key.pk8"))
                .unwrap()
                .as_ref()
        )
        .unwrap(),
        fixture.before.key_thumbprint
    );
}
