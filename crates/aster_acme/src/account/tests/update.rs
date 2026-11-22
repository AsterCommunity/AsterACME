//! Contact replacement, clearing, failures and observation boundaries.
use crate::account::tests::*;
use crate::transport::TransportOptions;
use std::time::Duration;

struct FailingAttemptSigner<'a> {
    key: &'a SoftwareSigningKey,
    attempts: std::sync::atomic::AtomicUsize,
    fail_on: usize,
}

impl JwsSigner for FailingAttemptSigner<'_> {
    fn algorithm(&self) -> KeyAlgorithm {
        self.key.algorithm()
    }
    fn jwk(&self) -> Result<crate::crypto::jwk::Jwk, crate::crypto::CryptoError> {
        self.key.jwk()
    }
    fn sign(&self, input: &[u8]) -> Result<Vec<u8>, crate::crypto::CryptoError> {
        if self.attempts.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_on {
            Err(crate::crypto::CryptoError::Signing)
        } else {
            self.key.sign(input)
        }
    }
}

#[tokio::test]
async fn bad_nonce_without_a_retry_nonce_keeps_the_ca_rejection() {
    for retries in [0, 1, 5] {
        for nonce in [None, Some("invalid nonce")] {
            let (server, service, store, key) = deactivation::fixture(TransportOptions {
                bad_nonce_retries: retries,
                ..local_options()
            })
            .await;
            let before = store.record.lock().await.clone().unwrap();
            let mut response = ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({"type":ProblemKind::BadNonce}));
            if let Some(nonce) = nonce {
                response = response.insert_header("Replay-Nonce", nonce);
            }
            Mock::given(method("POST"))
                .and(path("/account/1"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            let error = service.update_contacts(&key, vec![]).await.unwrap_err();
            let ContactUpdateError::Rejected(source) = error else {
                panic!("expected CA rejection");
            };
            let AccountError::Transport(source) = source.as_ref() else {
                panic!("expected transport evidence");
            };
            if retries == 0 {
                assert!(source.is_problem(&ProblemKind::BadNonce));
            } else {
                let crate::transport::TransportError::RetryPreparation { rejection, source } =
                    source
                else {
                    panic!("expected the rejected POST and the retry failure");
                };
                assert!(rejection.is_problem(&ProblemKind::BadNonce));
                assert!(matches!(
                    source.as_ref(),
                    crate::transport::TransportError::MissingNonce
                ));
            }
            let saved = store.record.lock().await.clone().unwrap();
            assert_eq!(saved.contacts, Vec::<String>::new());
            assert_eq!(saved.server_contacts, before.server_contacts);
            assert_eq!(saved.times, before.times);
        }
    }
}

#[tokio::test]
async fn signing_failure_distinguishes_before_first_post_from_after_bad_nonce() {
    for fail_on in [1, 2] {
        let (server, service, _store, key) = deactivation::fixture(local_options()).await;
        Mock::given(method("POST"))
            .and(path("/account/1"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("Replay-Nonce", "new_nonce")
                    .set_body_json(serde_json::json!({"type":ProblemKind::BadNonce})),
            )
            .expect(u64::try_from(fail_on - 1).unwrap())
            .mount(&server)
            .await;
        let signer = FailingAttemptSigner {
            key: &key,
            attempts: std::sync::atomic::AtomicUsize::new(0),
            fail_on,
        };
        let error = service.update_contacts(&signer, vec![]).await.unwrap_err();
        if fail_on == 1 {
            assert!(matches!(error, ContactUpdateError::NotSubmitted(_)));
        } else {
            let ContactUpdateError::Rejected(source) = error else {
                panic!("expected rejected first POST");
            };
            let AccountError::Transport(crate::transport::TransportError::RetryPreparation {
                rejection,
                source,
            }) = source.as_ref()
            else {
                panic!("expected preparation error");
            };
            assert!(rejection.is_problem(&ProblemKind::BadNonce));
            assert!(matches!(
                source.as_ref(),
                crate::transport::TransportError::Crypto(crate::crypto::CryptoError::Signing)
            ));
        }
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "POST")
                .count(),
            fail_on - 1
        );
    }
}

#[tokio::test]
async fn submitted_retry_uses_its_own_remote_result() {
    for (response, succeeds) in [
        (ResponseTemplate::new(503), false),
        (ResponseTemplate::new(200).set_body_string("broken"), false),
        (
            ResponseTemplate::new(200).set_delay(Duration::from_secs(2)),
            false,
        ),
        (
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"status":"valid"})),
            true,
        ),
    ] {
        let (server, service, _store, key) = deactivation::fixture(TransportOptions {
            request_timeout: Duration::from_secs(1),
            ..local_options()
        })
        .await;
        Mock::given(method("POST"))
            .and(path("/account/1"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("Replay-Nonce", "retry_nonce")
                    .set_body_json(serde_json::json!({"type":ProblemKind::BadNonce})),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/account/1"))
            .respond_with(response)
            .with_priority(10)
            .expect(1)
            .mount(&server)
            .await;
        let result = service.update_contacts(&key, vec![]).await;
        if succeeds {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(ContactUpdateError::Unconfirmed(_))));
        }
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "POST")
                .count(),
            2
        );
    }
}

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
async fn uncertain_bad_nonce_response_is_never_replayed() {
    for status in [408, 429, 500, 503] {
        for nonce in [None, Some("retry_nonce")] {
            let (server, service, _store, key) = deactivation::fixture(local_options()).await;
            let mut response = ResponseTemplate::new(status)
                .set_body_json(serde_json::json!({"type": ProblemKind::BadNonce}));
            if let Some(nonce) = nonce {
                response = response.insert_header("Replay-Nonce", nonce);
            }
            Mock::given(method("POST"))
                .and(path("/account/1"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            assert!(matches!(
                service.update_contacts(&key, vec![]).await,
                Err(ContactUpdateError::Unconfirmed(_))
            ));
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
