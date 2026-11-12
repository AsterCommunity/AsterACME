//! Controlled wall-clock tests of successful observations and failure/no-I/O paths.
use crate::account::tests::*;
use crate::crypto::key_algorithm::KeyAlgorithm;
use std::sync::atomic::AtomicI64;

struct Clock(AtomicI64);
impl AccountClock for Clock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst))
            .unwrap()
            .to_offset(time::UtcOffset::from_hms(8, 0, 0).unwrap())
    }
}

#[tokio::test]
async fn first_confirmation_is_stable_success_updates_and_failures_do_not_touch_times() {
    let (server, client) = server(local_options()).await;
    let store = Arc::new(MemoryStore::default());
    let clock = Arc::new(Clock(AtomicI64::new(10)));
    let service = AccountService::new(Arc::new(client), store.clone()).with_clock(clock.clone());
    let key = AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    Mock::given(method("POST"))
        .and(path("/account"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "lookup")
                .insert_header("Location", format!("{}/account/1", server.uri()))
                .set_body_json(aster_acme_protocol::account::AccountObject {
                    status: AccountStatus::Valid,
                    contact: None,
                    external_account_binding: None,
                }),
        )
        .mount(&server)
        .await;
    let recovered = service.recover(&key).await.unwrap();
    let first = time::OffsetDateTime::from_unix_timestamp(10).unwrap();
    assert_eq!(recovered.times.registered_at, Some(first));
    assert_eq!(recovered.times.last_used_at, Some(first));
    assert_eq!(
        recovered.times.last_status_at.unwrap().offset(),
        time::UtcOffset::UTC
    );
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/account/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "read")
                .set_body_json(aster_acme_protocol::account::AccountObject {
                    status: AccountStatus::Valid,
                    contact: None,
                    external_account_binding: None,
                }),
        )
        .mount(&server)
        .await;
    clock.0.store(20, Ordering::SeqCst);
    let inspected = service.inspect(&key).await.unwrap();
    assert_eq!(inspected.times.registered_at, Some(first));
    assert_eq!(inspected.times.last_status_at.unwrap().unix_timestamp(), 20);
    assert_eq!(inspected.times.last_used_at.unwrap().unix_timestamp(), 20);
    let before = store.record.lock().await.clone();
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/account/1"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("Replay-Nonce", "denied")
                .set_body_string(r#"{"type":"urn:ietf:params:acme:error:unauthorized"}"#),
        )
        .mount(&server)
        .await;
    clock.0.store(30, Ordering::SeqCst);
    assert!(service.inspect(&key).await.is_err());
    assert_eq!(*store.record.lock().await, before);
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/account/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "done")
                .set_body_json(aster_acme_protocol::account::AccountObject {
                    status: AccountStatus::Deactivated,
                    contact: None,
                    external_account_binding: None,
                }),
        )
        .expect(1)
        .mount(&server)
        .await;
    let deactivated = service.deactivate(&key).await.unwrap();
    assert_eq!(deactivated.times.registered_at, Some(first));
    assert_eq!(deactivated.times.last_used_at.unwrap().unix_timestamp(), 30);
    clock.0.store(40, Ordering::SeqCst);
    assert_eq!(
        service.deactivate(&key).await.unwrap().times,
        deactivated.times
    );
    server.verify().await;
}

#[test]
fn timestamps_serialize_rfc3339_and_unknown_values_stay_unknown() {
    let encoded = serde_json::to_string(&AccountTimes::default()).unwrap();
    assert!(encoded.contains("\"registered_at\":null"));
    let at = time::OffsetDateTime::from_unix_timestamp(0).unwrap();
    let times = AccountTimes {
        registered_at: Some(at),
        last_status_at: Some(at),
        last_used_at: Some(at),
    };
    assert!(
        serde_json::to_string(&times)
            .unwrap()
            .contains("1970-01-01T00:00:00Z")
    );
    assert_eq!(
        serde_json::from_str::<AccountTimes>(&serde_json::to_string(&times).unwrap()).unwrap(),
        times
    );
    assert!(serde_json::from_str::<AccountTimes>(r#"{"last_status_at":"bad date"}"#).is_err());
}
