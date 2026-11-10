//! Contact replacement, clearing, failures and observation boundaries.
use super::*;
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
            .set_delay(Duration::from_millis(500)),
    ] {
        let (server, service, store, key) = deactivation::fixture(TransportOptions {
            request_timeout: Duration::from_millis(200),
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
        assert!(
            service
                .update_contacts(&key, vec!["mailto:new@example.org".into()])
                .await
                .is_err()
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
        assert!(
            service
                .update_contacts(&key, vec![contact.into()])
                .await
                .is_err()
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
