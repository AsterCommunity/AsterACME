//! Contact replacement, clearing, failures and observation boundaries.
use crate::account::tests::*;
use crate::transport::TransportOptions;
use std::time::Duration;

#[tokio::test]
async fn update_replaces_or_clears_contacts_without_touching_identity() {
    for contacts in [vec![], vec!["mailto:new@example.org".into()]] {
        let (server, service, store, key) = deactivation::fixture(local_options()).await;
        let before = store.record.lock().await.clone().unwrap();
        Mock::given(method("POST"))
            .and(path("/account/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Replay-Nonce", "response_nonce")
                    .set_body_json(serde_json::json!({"status":"valid"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        service
            .update_contacts(&key, contacts.clone())
            .await
            .unwrap();
        let record = store.record.lock().await.clone().unwrap();
        assert_eq!(record.contacts, contacts);
        assert_eq!(record.server_contacts, None);
        assert_eq!(record.account_id, before.account_id);
        assert_eq!(record.key_thumbprint, before.key_thumbprint);
        assert_eq!(record.account_url, before.account_url);
        assert!(record.times.last_used_at.is_some());
        let requests = server.received_requests().await.unwrap();
        let post = requests
            .iter()
            .find(|request| request.method == "POST")
            .unwrap();
        let jws: FlattenedJws = serde_json::from_slice(&post.body).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
        assert_eq!(payload, serde_json::json!({"contact":contacts}));
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.protected).unwrap()).unwrap();
        assert_eq!(header["kid"], before.account_url.unwrap().as_str());
        assert!(header.get("jwk").is_none());
    }
}

#[tokio::test]
async fn failed_updates_preserve_local_intent_and_previous_observation_without_replay() {
    for response in [
        ResponseTemplate::new(503),
        ResponseTemplate::new(429),
        ResponseTemplate::new(200)
            .insert_header("Replay-Nonce", "response_nonce")
            .set_body_string("bad"),
        ResponseTemplate::new(201),
        ResponseTemplate::new(200)
            .insert_header("Replay-Nonce", "response_nonce")
            .set_delay(Duration::from_secs(2)),
    ] {
        let (server, service, store, key) = deactivation::fixture(TransportOptions {
            request_timeout: Duration::from_secs(1),
            ..local_options()
        })
        .await;
        let before = store.record.lock().await.clone().unwrap();
        Mock::given(method("POST"))
            .and(path("/account/1"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let error = service
            .update_contacts(&key, vec!["mailto:new@example.org".into()])
            .await
            .unwrap_err();
        assert!(
            matches!(error, ContactUpdateError::Unconfirmed(_)),
            "{error}"
        );
        let record = store.record.lock().await.clone().unwrap();
        assert_eq!(record.contacts, ["mailto:new@example.org"]);
        assert_eq!(record.times, before.times);
        assert_eq!(record.server_contacts, before.server_contacts);
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|request| request.method == "POST")
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn invalid_or_inactive_updates_and_failed_intent_never_post() {
    for case in 0..5 {
        let (server, service, store, key) = deactivation::fixture(local_options()).await;
        match case {
            0 => {}
            1 => {
                store.record.lock().await.as_mut().unwrap().last_status =
                    Some(AccountStatus::Deactivated);
            }
            2 => {
                store.record.lock().await.as_mut().unwrap().state =
                    AccountRecordState::RegistrationPending;
            }
            3 => store.fail_save.store(true, Ordering::SeqCst),
            4 => {
                store.record.lock().await.as_mut().unwrap().key_rotation = Some(KeyRotation {
                    new_thumbprint: "x".repeat(43),
                    phase: KeyRotationPhase::Pending,
                });
            }
            _ => unreachable!(),
        }
        let contact = if case == 0 {
            "bad"
        } else {
            "mailto:a@example.org"
        };
        let error = service
            .update_contacts(&key, vec![contact.into()])
            .await
            .unwrap_err();
        assert!(
            matches!(error, ContactUpdateError::NotSubmitted(_)),
            "{error}"
        );
        assert!(
            !server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.method == "POST")
        );
    }
}

#[tokio::test]
async fn accepted_contacts_remain_distinct_from_failed_local_observation_persistence() {
    for after_replacement in [false, true] {
        let (server, service, store, key) = deactivation::fixture(local_options()).await;
        let response_store = store.clone();
        Mock::given(method("POST"))
            .and(path("/account/1"))
            .respond_with(move |_: &wiremock::Request| {
                if after_replacement {
                    response_store.save_then_fail.store(true, Ordering::SeqCst);
                } else {
                    response_store.fail_save.store(true, Ordering::SeqCst);
                }
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "status":"valid", "contact":["mailto:accepted@example.org"]
                }))
            })
            .expect(1)
            .mount(&server)
            .await;
        let error = service
            .update_contacts(&key, vec!["mailto:accepted@example.org".into()])
            .await
            .unwrap_err();
        assert!(
            matches!(error, ContactUpdateError::Persistence(_)),
            "{error}"
        );
        let record = store.record.lock().await.clone().unwrap();
        assert_eq!(record.contacts, ["mailto:accepted@example.org"]);
        assert_eq!(
            record.server_contacts,
            if after_replacement {
                Some(vec!["mailto:accepted@example.org".into()])
            } else {
                Some(vec![])
            }
        );
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

#[tokio::test]
async fn only_definitive_acme_problems_establish_contact_rejection() {
    for status in [400, 403, 408, 429, 500] {
        let (server, service, _store, key) = deactivation::fixture(local_options()).await;
        Mock::given(method("POST"))
            .and(path("/account/1"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "type":"urn:ietf:params:acme:error:unauthorized"
                })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let error = service.update_contacts(&key, vec![]).await.unwrap_err();
        if matches!(status, 400 | 403) {
            assert!(matches!(error, ContactUpdateError::Rejected(_)), "{error}");
        } else {
            assert!(
                matches!(error, ContactUpdateError::Unconfirmed(_)),
                "{error}"
            );
        }
    }
}

#[tokio::test]
async fn nonce_failure_before_contact_post_is_not_submission() {
    for response in [
        ResponseTemplate::new(503),
        ResponseTemplate::new(400)
            .set_body_json(serde_json::json!({"type":"urn:ietf:params:acme:error:unauthorized"})),
    ] {
        let (server, service, _store, key) = deactivation::fixture(local_options()).await;
        // Discovery has no saved nonce; a failing HEAD never authorizes a contact POST.
        Mock::given(method("HEAD"))
            .respond_with(response)
            .with_priority(1)
            .mount(&server)
            .await;
        let error = service.update_contacts(&key, vec![]).await.unwrap_err();
        assert!(
            matches!(error, ContactUpdateError::NotSubmitted(_)),
            "{error}"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method != "POST")
        );
    }
}
