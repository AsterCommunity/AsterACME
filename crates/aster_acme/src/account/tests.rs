//! Account registration, persisted-intent and failure/recovery contract tests.
use aster_acme_protocol::jws::FlattenedJws;
mod deactivation;
mod timestamps;
mod update;
use super::*;
use crate::{
    crypto::AccountKey,
    transport::tests::{local_options, server},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

#[derive(Default)]
struct MemoryStore {
    record: Mutex<Option<AccountRecord>>,
    fail_save: AtomicBool,
}

#[tokio::test]
async fn account_requests_follow_custom_directory_and_location_urls() {
    use aster_acme_protocol::{
        account::AccountObject,
        directory::{Directory, DirectoryMeta},
    };
    let server = wiremock::MockServer::start().await;
    let resource = |path: &str| AcmeUrl::new(&format!("{}{path}", server.uri())).unwrap();
    let new_account = resource("/vendor/custom-create?version=9");
    let account_url = resource("/tenant/arbitrary-identity?token=%41");
    Mock::given(method("GET"))
        .and(path("/entry-point"))
        .respond_with(ResponseTemplate::new(200).set_body_json(Directory {
            new_order: None,
            renewal_info: None,
            revoke_cert: None,
            key_change: None,
            new_nonce: resource("/vendor/replay"),
            new_account: new_account.clone(),
            meta: DirectoryMeta::default(),
        }))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(path("/vendor/replay"))
        .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "initial"))
        .mount(&server)
        .await;
    let object = || AccountObject {
        status: AccountStatus::Valid,
        contact: None,
        external_account_binding: None,
    };
    Mock::given(method("POST"))
        .and(path("/vendor/custom-create"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "lookup")
                .insert_header("Location", account_url.as_str())
                .set_body_json(object()),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tenant/arbitrary-identity"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "read")
                .set_body_json(object()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let client = crate::transport::HttpPool::default()
        .discover(resource("/entry-point"), local_options())
        .await
        .unwrap();
    let service = AccountService::new(Arc::new(client), Arc::new(MemoryStore::default()));
    let key = AccountKey::generate().unwrap();
    assert_eq!(
        service.recover(&key).await.unwrap().account_url,
        account_url
    );
    service.inspect(&key).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    let posts: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "POST")
        .collect();
    for (request, exact_url) in posts.iter().zip([&new_account, &account_url]) {
        let jws: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.protected).unwrap()).unwrap();
        assert_eq!(header["url"], exact_url.as_str());
    }
}

#[tokio::test]
async fn ca_contact_is_optional_and_never_erases_local_registration_input() {
    for server_contacts in [
        None,
        Some(vec![]),
        Some(vec!["mailto:ca@example.com".to_owned()]),
    ] {
        let (server, client) = server(local_options()).await;
        let store = Arc::new(MemoryStore::default());
        let service = AccountService::new(Arc::new(client), store.clone());
        let key = AccountKey::generate().unwrap();
        let directory = service.client.directory_url().clone();
        let thumbprint = key.jwk().unwrap().thumbprint().unwrap();
        // Model the named file adapter's durable initialization before registration begins.
        *store.record.lock().await = Some(AccountRecord {
            user_agent: None,
            times: crate::account::AccountTimes::default(),
            account_id: account_id(&directory, &thumbprint),
            directory_url: directory,
            key_thumbprint: thumbprint,
            account_url: None,
            contacts: vec![],
            server_contacts: None,
            last_status: None,
            deactivation: aster_acme_core::account::DeactivationState::NotRequested,
            key_rotation: None,
            accepted_terms_url: None,
            state: AccountRecordState::RegistrationPending,
        });
        Mock::given(method("POST"))
            .and(path("/account"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("Replay-Nonce", "lookup")
                    .set_body_json(serde_json::json!({"type":ProblemKind::AccountDoesNotExist})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let mut body = serde_json::json!({"status":"valid"});
        if let Some(contacts) = &server_contacts {
            body["contact"] = serde_json::json!(contacts);
        }
        Mock::given(method("POST"))
            .and(path("/account"))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("Replay-Nonce", "created")
                    .insert_header("Location", format!("{}/account/1", server.uri()))
                    .set_body_json(body),
            )
            .with_priority(10)
            .mount(&server)
            .await;
        let account = service
            .register_or_recover(
                &key,
                RegistrationOptions {
                    contacts: vec!["mailto:local@example.com".into()],
                    ..RegistrationOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            account.contacts,
            server_contacts.clone().unwrap_or_default()
        );
        let record = store.record.lock().await.clone().unwrap();
        assert_eq!(record.contacts, ["mailto:local@example.com"]);
        assert_eq!(record.server_contacts, server_contacts);
        let requests = server.received_requests().await.unwrap();
        let posts: Vec<_> = requests
            .iter()
            .filter(|request| request.method == "POST")
            .collect();
        let jws: FlattenedJws = serde_json::from_slice(&posts[1].body).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
        assert_eq!(
            payload["contact"],
            serde_json::json!(["mailto:local@example.com"])
        );
    }
}

#[tokio::test]
async fn consent_records_the_current_url_and_changed_terms_require_new_acceptance() {
    let (_server, mut client) = server(local_options()).await;
    let first = AcmeUrl::new("https://ca.example/terms/v1").unwrap();
    client.directory.meta.terms_of_service = Some(first.clone());
    let store = Arc::new(MemoryStore::default());
    let directory = client.directory_url().clone();
    let mut service = AccountService::new(Arc::new(client), store.clone());
    let thumbprint = AccountKey::generate()
        .unwrap()
        .jwk()
        .unwrap()
        .thumbprint()
        .unwrap();
    let accepted = RegistrationOptions {
        terms_accepted: true,
        ..RegistrationOptions::default()
    };
    let record = service
        .load_or_prepare(&directory, &thumbprint, &accepted)
        .await
        .unwrap();
    assert_eq!(record.accepted_terms_url, Some(first));
    assert!(
        service
            .load_or_prepare(&directory, &thumbprint, &RegistrationOptions::default())
            .await
            .is_ok()
    );
    let second = AcmeUrl::new("https://ca.example/terms/v2").unwrap();
    Arc::get_mut(&mut service.client)
        .unwrap()
        .directory
        .meta
        .terms_of_service = Some(second.clone());
    let changed = service;
    assert!(matches!(
        changed
            .load_or_prepare(&directory, &thumbprint, &RegistrationOptions::default())
            .await,
        Err(AccountError::TermsRequired(_))
    ));
    let record = changed
        .load_or_prepare(&directory, &thumbprint, &accepted)
        .await
        .unwrap();
    assert_eq!(record.accepted_terms_url, Some(second));
    assert_eq!(*store.record.lock().await, Some(record));
}
#[async_trait]
impl AccountStore for MemoryStore {
    async fn lock_account(
        &self,
        _directory: &AcmeUrl,
        _thumbprint: &str,
    ) -> Result<Box<dyn AccountLease>, AccountStoreError> {
        Ok(Box::new(()))
    }
    async fn load(
        &self,
        _directory: &AcmeUrl,
        _thumbprint: &str,
    ) -> Result<Option<AccountRecord>, AccountStoreError> {
        Ok(self.record.lock().await.clone())
    }
    async fn save(&self, record: &AccountRecord) -> Result<(), AccountStoreError> {
        if self.fail_save.load(Ordering::SeqCst) {
            return Err(AccountStoreError {
                message: "injected disk failure".into(),
            });
        }
        *self.record.lock().await = Some(record.clone());
        Ok(())
    }
}

#[tokio::test]
async fn registration_is_recovered_after_lost_response_and_reuses_the_same_identity() {
    let (server, client) = server(local_options()).await;
    let store = Arc::new(MemoryStore::default());
    let service = AccountService::new(Arc::new(client), store.clone());
    let key = AccountKey::generate().unwrap();
    // A missing account lookup must never create one; subsequent create returns the account.
    Mock::given(method("POST"))
        .and(path("/account"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("Replay-Nonce", "lookup_nonce")
                .set_body_json(serde_json::json!({"type":ProblemKind::AccountDoesNotExist})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/account"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("Replay-Nonce", "create_nonce")
                .insert_header("Location", format!("{}/account/1", server.uri()))
                .set_body_json(serde_json::json!({"status":"valid","contact":[]})),
        )
        .with_priority(10)
        .mount(&server)
        .await;
    let account = service
        .register_or_recover(&key, RegistrationOptions::default())
        .await
        .unwrap();
    assert!(!account.recovered);
    assert_eq!(
        account.status,
        aster_acme_core::protocol::AccountStatus::Valid
    );
    let record = store.record.lock().await.clone().unwrap();
    assert_eq!(record.state, AccountRecordState::Registered);
    let requests = server.received_requests().await.unwrap();
    let posts: Vec<_> = requests.iter().filter(|r| r.method == "POST").collect();
    assert_eq!(posts.len(), 2);
    let first: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &URL_SAFE_NO_PAD.decode(first.payload).unwrap()
        )
        .unwrap(),
        serde_json::json!({"onlyReturnExisting":true})
    );
    // Simulate persisted intent surviving a crash before the successful response was saved.
    let mut pending = record.clone();
    pending.account_url = None;
    pending.state = AccountRecordState::RegistrationPending;
    *store.record.lock().await = Some(pending);
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/account"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "recovered_nonce")
                .insert_header("Location", format!("{}/account/1", server.uri()))
                .set_body_json(serde_json::json!({"status":"valid"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let recovered = service
        .register_or_recover(&key, RegistrationOptions::default())
        .await
        .unwrap();
    assert!(recovered.recovered);
    assert_eq!(recovered.account_id, account.account_id);
    assert_eq!(recovered.account_url, account.account_url);
    // Already registered account queries use kid + POST-as-GET and preserve real server status.
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/account/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "read_nonce")
                .set_body_json(serde_json::json!({"status":"deactivated"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let account = service
        .register_or_recover(&key, RegistrationOptions::default())
        .await
        .unwrap();
    assert_eq!(
        account.status,
        aster_acme_core::protocol::AccountStatus::Deactivated
    );
    let requests = server.received_requests().await.unwrap();
    let request: FlattenedJws = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(request.payload, "");
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(request.protected).unwrap()).unwrap();
    assert_eq!(header["kid"], account.account_url.as_str());
    assert!(header.get("jwk").is_none());
}

#[tokio::test]
async fn consent_eab_and_contacts_fail_before_post_or_persisted_registration() {
    let (server, mut client) = server(local_options()).await;
    let terms = AcmeUrl::new("https://ca.example/terms").unwrap();
    client.directory.meta.terms_of_service = Some(terms.clone());
    let store = Arc::new(MemoryStore::default());
    let key = AccountKey::generate().unwrap();
    let service = AccountService::new(Arc::new(client), store.clone());
    assert!(matches!(
        service
            .register_or_recover(&key, RegistrationOptions::default())
            .await,
        Err(AccountError::TermsRequired(_))
    ));
    let options = RegistrationOptions {
        contacts: vec!["mailto:a@example.com?subject=x".into()],
        terms_accepted: true,
        ..RegistrationOptions::default()
    };
    assert!(matches!(
        service.register_or_recover(&key, options).await,
        Err(AccountError::InvalidContact)
    ));
    assert!(store.record.lock().await.is_none());
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count(),
        0
    );
}

#[tokio::test]
async fn eab_requirement_is_explicit_and_only_return_existing_does_not_send_eab() {
    let (server, mut client) = server(local_options()).await;
    client.directory.meta.external_account_required = true;
    let service = AccountService::new(Arc::new(client), Arc::new(MemoryStore::default()));
    let key = AccountKey::generate().unwrap();
    assert!(matches!(
        service
            .register_or_recover(&key, RegistrationOptions::default())
            .await,
        Err(AccountError::ExternalAccountRequired)
    ));
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("Replay-Nonce", "next")
                .set_body_json(serde_json::json!({"type":ProblemKind::AccountDoesNotExist})),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert!(
        matches!(service.recover(&key).await,Err(AccountError::Transport(error)) if error.is_problem(&ProblemKind::AccountDoesNotExist))
    );
}

#[tokio::test]
async fn failed_intent_persistence_prevents_any_remote_mutation() {
    let (server, client) = server(local_options()).await;
    let store = Arc::new(MemoryStore::default());
    store.fail_save.store(true, Ordering::SeqCst);
    let service = AccountService::new(Arc::new(client), store);
    assert!(matches!(
        service
            .register_or_recover(
                &AccountKey::generate().unwrap(),
                RegistrationOptions::default()
            )
            .await,
        Err(AccountError::Store(_))
    ));
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count(),
        0
    );
}

#[tokio::test]
async fn timeout_and_bad_response_preserve_original_key_and_pending_intent() {
    for response in [
        ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(500)),
        ResponseTemplate::new(200)
            .insert_header("Replay-Nonce", "next")
            .set_body_json(serde_json::json!({"status":"valid"})),
    ] {
        let (server, client) = server(crate::transport::TransportOptions {
            request_timeout: std::time::Duration::from_millis(150),
            ..local_options()
        })
        .await;
        Mock::given(method("POST"))
            .respond_with(response)
            .mount(&server)
            .await;
        let store = Arc::new(MemoryStore::default());
        let key = AccountKey::generate().unwrap();
        let thumb = key.jwk().unwrap().thumbprint().unwrap();
        let service = AccountService::new(Arc::new(client), store.clone());
        assert!(
            service
                .register_or_recover(&key, RegistrationOptions::default())
                .await
                .is_err()
        );
        let record = store.record.lock().await.clone().unwrap();
        assert_eq!(record.key_thumbprint, thumb);
        assert_eq!(record.state, AccountRecordState::RegistrationPending);
        assert!(record.account_url.is_none());
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "POST")
                .count(),
            1
        );
    }
}

#[test]
fn contact_boundaries_reject_headers_multiple_addresses_and_control_characters() {
    assert!(validate_contacts(&[]).is_ok());
    assert!(validate_contacts(&["mailto:a@example.com".into()]).is_ok());
    for invalid in [
        "mailto:",
        "mailto:a@example.com,b@example.com",
        "mailto:a@example.com%2Cb@example.com",
        "mailto:a@example.com?subject=x",
        "mailto:a@example.com#fragment",
        "mailto:a%0Ab@example.com",
        "https://example.com",
        "not-a-uri",
    ] {
        assert!(validate_contacts(&[invalid.into()]).is_err(), "{invalid}");
    }
    assert!(validate_contacts(&vec!["mailto:a@example.com".into(); 33]).is_err());
}

#[tokio::test]
async fn eab_registration_requires_confirmation_and_exact_payload() {
    for confirmed in [false, true] {
        let (server, client) = server(local_options()).await;
        let store = Arc::new(MemoryStore::default());
        let service = AccountService::new(Arc::new(client), store.clone());
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("Replay-Nonce", "lookup_nonce")
                    .set_body_json(serde_json::json!({"type":ProblemKind::AccountDoesNotExist})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let location = format!("{}/account/1", server.uri());
        Mock::given(method("POST"))
            .respond_with(move |request: &wiremock::Request| {
                let jws: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
                let payload: serde_json::Value =
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
                let mut account = serde_json::json!({"status":"valid"});
                if confirmed {
                    account["externalAccountBinding"] = payload["externalAccountBinding"].clone();
                }
                ResponseTemplate::new(201)
                    .insert_header("Replay-Nonce", "created_nonce")
                    .insert_header("Location", location.clone())
                    .set_body_json(account)
            })
            .with_priority(10)
            .mount(&server)
            .await;
        let options = RegistrationOptions {
            external_account: Some(
                ExternalAccountCredentials::new("external-id", &URL_SAFE_NO_PAD.encode([1_u8; 32]))
                    .unwrap(),
            ),
            ..RegistrationOptions::default()
        };
        let result = service
            .register_or_recover(&AccountKey::generate().unwrap(), options)
            .await;
        if confirmed {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(AccountError::ExternalAccountNotConfirmed)
            ));
            assert_eq!(
                store.record.lock().await.as_ref().unwrap().state,
                AccountRecordState::RegistrationPending
            );
        }
    }
}

#[tokio::test]
async fn cancellation_leaves_intent_and_no_retry_and_corrupt_identity_never_posts() {
    let (server, client) = server(local_options()).await;
    let store = Arc::new(MemoryStore::default());
    let service = AccountService::new(Arc::new(client), store.clone());
    let key = AccountKey::generate().unwrap();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(1)))
        .mount(&server)
        .await;
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            service.register_or_recover(&key, RegistrationOptions::default())
        )
        .await
        .is_err()
    );
    let mut record = store.record.lock().await.clone().unwrap();
    assert_eq!(record.state, AccountRecordState::RegistrationPending);
    record.directory_url = AcmeUrl::new("https://other.example/directory").unwrap();
    *store.record.lock().await = Some(record);
    server.reset().await;
    assert!(matches!(
        service
            .register_or_recover(&key, RegistrationOptions::default())
            .await,
        Err(AccountError::IdentityMismatch)
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}
