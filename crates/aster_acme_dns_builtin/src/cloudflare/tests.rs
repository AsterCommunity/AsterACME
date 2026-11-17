use crate::cloudflare::{BACKEND_ID, Cloudflare, CloudflareConfig};
use aster_acme_dns::{
    CleanupRequest, CleanupStatus, DnsRecord, ProviderErrorCode, RecordOwnership, SideEffect,
    operation::{
        HttpFailure, HttpResponse, OperationFactory, ProviderAction, ProviderEffect, ProviderEvent,
        ProviderOperation, ProviderOutcome, RecoveryState,
    },
};
use serde_json::{Value, json};

const ZONE: &str = "0123456789abcdef0123456789abcdef";
fn factory() -> Cloudflare {
    Cloudflare::new(CloudflareConfig {
        zone_id: ZONE.into(),
        api_token: Some("sensitive-sentinel".into()),
        token_file: None,
    })
    .unwrap()
}
fn record() -> DnsRecord {
    DnsRecord {
        publication_id: "publication-1".into(),
        challenge_name: "_acme-challenge.example.com.".into(),
        cname_chain: vec!["_acme-challenge.example.com.".into()],
        name: "_acme-challenge.example.com.".into(),
        value: "txt-value".into(),
        ttl_seconds: Some(120),
    }
}
fn response(result: Value) -> ProviderEvent {
    let mut body = json!({"success":true,"result_info":{"page":1,"total_pages":1}});
    body["result"] = result;
    ProviderEvent::Http(Ok(HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }))
}

fn zone() -> ProviderEvent {
    response(json!({"id":ZONE,"name":"example.com"}))
}
fn remote(comment: Option<&str>, value: &str) -> Value {
    json!({"id":"11111111111111111111111111111111","name":"_acme-challenge.example.com","type":"TXT","content":value,"comment":comment})
}
fn absolute_token_path() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::path::PathBuf::from(r"C:\absolute\token")
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/absolute/token")
    }
}
fn http(effect: ProviderEffect, method: &str) -> aster_acme_dns::operation::HttpRequest {
    let ProviderEffect::Http(request) = effect else {
        panic!("expected HTTP")
    };
    assert_eq!(request.method, method);
    assert!(
        request
            .headers
            .iter()
            .any(|(key, value)| key == "Authorization" && value == "Bearer sensitive-sentinel")
    );
    request
}
fn begin(saved: Option<RecoveryState>) -> Box<dyn ProviderOperation> {
    let mut machine = factory()
        .start(ProviderAction::Present(record()), saved)
        .unwrap();
    http(machine.advance(ProviderEvent::Start).unwrap(), "GET");
    http(machine.advance(zone()).unwrap(), "GET");
    machine
}
fn intent(machine: &mut dyn ProviderOperation) -> RecoveryState {
    let ProviderEffect::Checkpoint(saved) = machine.advance(response(json!([]))).unwrap() else {
        panic!("write must checkpoint")
    };
    let request = http(
        machine.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "POST",
    );
    assert!(request.mutation);
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["comment"], "asteracme:publication-1");
    assert_eq!(body["content"], "txt-value");
    assert!(
        !serde_json::to_string(&saved)
            .unwrap()
            .contains("sensitive-sentinel")
    );
    saved
}

#[test]
fn creates_only_after_intent_and_cleans_exact_owned_record() {
    let mut machine = begin(None);
    let saved = intent(machine.as_mut());
    let ProviderEffect::Complete(ProviderOutcome::Presented(receipt)) = machine
        .advance(response(remote(
            Some("asteracme:publication-1"),
            "txt-value",
        )))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(receipt.ownership, RecordOwnership::Created);
    let mut cleanup = factory()
        .start(
            ProviderAction::Cleanup(CleanupRequest {
                publication_id: record().publication_id.clone(),
                record: record(),
                receipt,
            }),
            Some(saved),
        )
        .unwrap();
    http(cleanup.advance(ProviderEvent::Start).unwrap(), "GET");
    http(cleanup.advance(zone()).unwrap(), "GET");
    assert!(matches!(
        cleanup
            .advance(response(remote(
                Some("asteracme:publication-1"),
                "txt-value"
            )))
            .unwrap(),
        ProviderEffect::Checkpoint(_)
    ));
    http(
        cleanup.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "DELETE",
    );
    assert!(matches!(
        cleanup
            .advance(response(json!({"id":"11111111111111111111111111111111"})))
            .unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Removed))
    ));
}

#[test]
fn lost_create_response_reconciles_tag_without_repeating_post() {
    let mut first = begin(None);
    let saved = intent(first.as_mut());
    let Err(error) = first.advance(ProviderEvent::Http(Err(HttpFailure {
        code: ProviderErrorCode::ProviderTimeout,
        side_effect: SideEffect::Unknown,
    }))) else {
        panic!()
    };
    assert_eq!(error.side_effect, SideEffect::Unknown);
    let mut restored = begin(Some(saved));
    assert!(
        matches!(restored.advance(response(json!([remote(Some("asteracme:publication-1"),"txt-value")]))).unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Presented(receipt)) if receipt.ownership == RecordOwnership::Created)
    );
}

#[test]
fn publication_id_respects_cloudflare_comment_length_limit() {
    let mut publication = record();
    publication.publication_id = "a".repeat(90);
    assert!(
        factory()
            .start(ProviderAction::Present(publication.clone()), None)
            .is_ok()
    );
    publication.publication_id.push('a');
    assert!(
        factory()
            .start(ProviderAction::Present(publication), None)
            .is_err()
    );
}

#[test]
fn preexisting_values_are_retained_and_other_publications_cannot_be_borrowed() {
    for comment in [
        None,
        Some("user comment"),
        Some("asteracme:another-publication"),
    ] {
        let mut machine = begin(None);
        let outcome = machine.advance(response(json!([remote(comment, "txt-value")])));
        if comment == Some("asteracme:another-publication") {
            assert!(
                matches!(outcome,Err(error) if error.code == ProviderErrorCode::RecordConflict)
            );
        } else {
            let Ok(ProviderEffect::Complete(ProviderOutcome::Presented(receipt))) = outcome else {
                panic!()
            };
            assert_eq!(receipt.ownership, RecordOwnership::Preexisting);
            let mut cleanup = factory()
                .start(
                    ProviderAction::Cleanup(CleanupRequest {
                        publication_id: record().publication_id.clone(),
                        record: record(),
                        receipt,
                    }),
                    None,
                )
                .unwrap();
            assert!(matches!(
                cleanup.advance(ProviderEvent::Start).unwrap(),
                ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Retained))
            ));
        }
    }
}

#[test]
fn pagination_is_complete_before_creating_and_ambiguous_records_fail_closed() {
    let mut machine = begin(None);
    let page = ProviderEvent::Http(Ok(HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(
            &json!({"success":true,"result":[],"result_info":{"page":1,"total_pages":2}}),
        )
        .unwrap(),
    }));
    let request = http(machine.advance(page).unwrap(), "GET");
    assert!(request.url.ends_with("page=2"));
    let page=ProviderEvent::Http(Ok(HttpResponse {status:200,headers:vec![],body:serde_json::to_vec(&json!({"success":true,"result":[remote(Some("asteracme:publication-1"),"txt-value")],"result_info":{"page":2,"total_pages":2}})).unwrap()}));
    assert!(matches!(
        machine.advance(page).unwrap(),
        ProviderEffect::Complete(_)
    ));
    let mut machine = begin(None);
    assert!(
        matches!(machine.advance(response(json!([remote(None,"txt-value"),remote(None,"txt-value")]))),Err(error) if error.code==ProviderErrorCode::RecordConflict)
    );
}

#[test]
fn changed_record_or_publication_tag_never_authorizes_delete_or_create() {
    let mut machine = begin(None);
    assert!(
        matches!(machine.advance(response(json!([remote(Some("asteracme:publication-1"),"changed")]))),Err(error) if error.code==ProviderErrorCode::RecordConflict)
    );
    let mut machine = begin(None);
    let saved = intent(machine.as_mut());
    let ProviderEffect::Complete(ProviderOutcome::Presented(receipt)) = machine
        .advance(response(remote(
            Some("asteracme:publication-1"),
            "txt-value",
        )))
        .unwrap()
    else {
        panic!()
    };
    for record in [
        remote(None, "txt-value"),
        remote(Some("asteracme:publication-1"), "changed"),
    ] {
        let mut cleanup = factory()
            .start(
                ProviderAction::Cleanup(CleanupRequest {
                    publication_id: record_for_id(),
                    record: crate::cloudflare::tests::record(),
                    receipt: receipt.clone(),
                }),
                Some(saved.clone()),
            )
            .unwrap();
        http(cleanup.advance(ProviderEvent::Start).unwrap(), "GET");
        http(cleanup.advance(zone()).unwrap(), "GET");
        assert!(
            matches!(cleanup.advance(response(record)),Err(error) if error.code==ProviderErrorCode::RecordNotOwned)
        );
    }
}
fn record_for_id() -> String {
    record().publication_id
}

#[test]
fn errors_are_redacted_rate_limits_preserved_and_wrong_zones_rejected() {
    let mut machine = begin(None);
    let Err(error) = machine.advance(ProviderEvent::Http(Ok(HttpResponse {
        status: 429,
        headers: vec![("Retry-After".into(), b"17".to_vec())],
        body: br#"{"success":false,"errors":[{"message":"sensitive-sentinel"}]}"#.to_vec(),
    }))) else {
        panic!()
    };
    assert_eq!(error.retry_after_seconds, Some(17));
    assert!(!error.to_string().contains("sensitive-sentinel"));
    let mut machine = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    http(machine.advance(ProviderEvent::Start).unwrap(), "GET");
    assert!(
        matches!(machine.advance(response(json!({"id":ZONE,"name":"wrong.example"}))),Err(error) if error.code==ProviderErrorCode::ZoneNotFound)
    );
    let registry = aster_acme_dns::backend::ProviderRegistry::linked().unwrap();
    assert!(
        registry
            .descriptors()
            .iter()
            .any(|descriptor| descriptor.id == BACKEND_ID)
    );
}

#[test]
fn invalid_configuration_and_recovery_versions_fail_before_http() {
    for (zone, token, file) in [
        ("bad", Some("valid"), None),
        (ZONE, None, None),
        (ZONE, Some(""), None),
        (ZONE, Some("line\nbreak"), None),
        (ZONE, None, Some("relative")),
        (ZONE, Some("valid"), Some("/absolute/token")),
    ] {
        assert!(
            Cloudflare::new(CloudflareConfig {
                zone_id: zone.into(),
                api_token: token.map(str::to_owned),
                token_file: file.map(Into::into)
            })
            .is_err()
        );
    }
    for state in [
        RecoveryState {
            version: 2,
            data: json!({"create_intent":true}),
        },
        RecoveryState {
            version: 1,
            data: json!({"unrecognized":true}),
        },
        RecoveryState {
            version: 1,
            data: json!({"delete_intent":true}),
        },
    ] {
        assert!(
            factory()
                .start(ProviderAction::Present(record()), Some(state))
                .is_err()
        );
    }
    let file = Cloudflare::new(CloudflareConfig {
        zone_id: ZONE.into(),
        api_token: None,
        token_file: Some(absolute_token_path()),
    })
    .unwrap();
    let mut machine = file.start(ProviderAction::Present(record()), None).unwrap();
    assert!(matches!(
        machine.advance(ProviderEvent::Start).unwrap(),
        ProviderEffect::ReadSecret(_)
    ));
    assert!(
        matches!(machine.advance(ProviderEvent::Secret("bad\ntoken".into())),Err(error) if error.code==ProviderErrorCode::CredentialsUnavailable)
    );
}

#[test]
fn configuration_errors_identify_invalid_field_without_revealing_credentials() {
    for (zone, token, file, expected) in [
        ("bad", Some("sentinel"), None, "zone_id"),
        ("", None, None, "requires api_token or token_file"),
        ("", Some("sentinel"), Some("/token"), "only one"),
        ("", Some("sentinel with space"), None, "without spaces"),
        ("", None, Some("relative"), "absolute path"),
    ] {
        let err = CloudflareConfig {
            zone_id: zone.into(),
            api_token: token.map(str::to_owned),
            token_file: file.map(Into::into),
        }
        .validate()
        .unwrap_err();
        assert!(err.message.contains(expected));
        assert!(!err.message.contains("sentinel"));
    }
}

#[test]
fn cleanup_absence_requires_a_structured_missing_record_error() {
    let mut machine = begin(None);
    let saved = intent(machine.as_mut());
    let ProviderEffect::Complete(ProviderOutcome::Presented(receipt)) = machine
        .advance(response(remote(
            Some("asteracme:publication-1"),
            "txt-value",
        )))
        .unwrap()
    else {
        panic!()
    };
    for confirmed in [false, true] {
        let mut cleanup = factory()
            .start(
                ProviderAction::Cleanup(CleanupRequest {
                    publication_id: record().publication_id.clone(),
                    record: record(),
                    receipt: receipt.clone(),
                }),
                Some(saved.clone()),
            )
            .unwrap();
        cleanup.advance(ProviderEvent::Start).unwrap();
        cleanup.advance(zone()).unwrap();
        let body = if confirmed {
            serde_json::to_vec(&json!({"success":false,"errors":[{"code":81044}]})).unwrap()
        } else {
            b"proxy returned 404".to_vec()
        };
        let outcome = cleanup.advance(ProviderEvent::Http(Ok(HttpResponse {
            status: 404,
            headers: vec![],
            body,
        })));
        if confirmed {
            assert!(matches!(
                outcome,
                Ok(ProviderEffect::Complete(ProviderOutcome::Cleaned(
                    CleanupStatus::AlreadyAbsent
                )))
            ));
        } else {
            assert!(outcome.is_err());
        }
    }
}

#[test]
fn incomplete_pagination_invalid_create_receipt_and_invalid_zone_never_claim_success() {
    let mut machine = begin(None);
    assert!(
        machine
            .advance(ProviderEvent::Http(Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: br#"{"success":true,"result":[]}"#.to_vec()
            })))
            .is_err()
    );
    let mut machine = begin(None);
    intent(machine.as_mut());
    assert!(
        machine
            .advance(response(remote(None, "txt-value")))
            .is_err()
    );
}

#[test]
fn unknown_creation_without_a_visible_tag_never_replays_post() {
    let saved = RecoveryState {
        version: 1,
        data: json!({"create_intent":true}),
    };
    for records in [json!([]), json!([remote(None, "txt-value")])] {
        let mut machine = begin(Some(saved.clone()));
        assert!(
            matches!(machine.advance(response(records)),Err(error) if error.code==ProviderErrorCode::RecordNotOwned && error.side_effect==SideEffect::Unknown)
        );
    }
}

#[test]
fn a_proved_create_rejection_is_checkpointed_before_a_later_attempt_is_allowed() {
    let mut machine = begin(None);
    intent(machine.as_mut());
    let rejected = ProviderEvent::Http(Ok(HttpResponse {
        status: 403,
        headers: vec![],
        body: br#"{"success":false,"errors":[]}"#.to_vec(),
    }));
    let ProviderEffect::Checkpoint(state) = machine.advance(rejected).unwrap() else {
        panic!()
    };
    assert!(
        matches!(machine.advance(ProviderEvent::CheckpointSaved),Err(error) if error.code==ProviderErrorCode::AuthorizationDenied)
    );
    let mut restored = begin(Some(state));
    assert!(matches!(
        restored.advance(response(json!([]))).unwrap(),
        ProviderEffect::Checkpoint(_)
    ));
}

#[test]
fn unknown_backend_config_version_is_not_interpreted_as_current() {
    use aster_acme_dns::backend::{BackendConfig, DnsBackend};
    let config = BackendConfig {
        version: 2,
        custom: serde_json::from_value(json!({"zone_id":ZONE,"api_token":"valid-token"})).unwrap(),
        ..BackendConfig::default()
    };
    assert!(
        crate::cloudflare::CloudflareBackend
            .validate(&config)
            .is_err()
    );
}

#[test]
fn automatic_zone_discovery_uses_delegated_target_and_persists_for_recovery() {
    let factory = Cloudflare::new(CloudflareConfig {
        zone_id: String::new(),
        api_token: Some("sensitive-sentinel".into()),
        token_file: None,
    })
    .unwrap();
    let mut delegated = record();
    delegated.name = "delegated.validation.net.".into();
    delegated.cname_chain.push(delegated.name.clone());
    let mut op = factory
        .start(ProviderAction::Present(delegated.clone()), None)
        .unwrap();
    let req = http(op.advance(ProviderEvent::Start).unwrap(), "GET");
    assert!(req.url.contains("name=delegated.validation.net"));
    let req = http(op.advance(response(json!([]))).unwrap(), "GET");
    assert!(req.url.contains("name=validation.net"));
    let ProviderEffect::Checkpoint(zone_state) = op
        .advance(response(json!([{"id":ZONE,"name":"validation.net"}])))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(zone_state.data["zone_id"], ZONE);
    let req = http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    assert!(req.url.ends_with(ZONE));
    http(
        op.advance(response(json!({"id":ZONE,"name":"validation.net"})))
            .unwrap(),
        "GET",
    );
    let ProviderEffect::Checkpoint(intent) = op.advance(response(json!([]))).unwrap() else {
        panic!()
    };
    assert_eq!(intent.data["zone_id"], ZONE);
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "POST");
    let mut recovered = factory
        .start(ProviderAction::Present(delegated), Some(intent))
        .unwrap();
    let req = http(recovered.advance(ProviderEvent::Start).unwrap(), "GET");
    assert!(req.url.ends_with(ZONE));
    http(
        recovered
            .advance(response(json!({"id":ZONE,"name":"validation.net"})))
            .unwrap(),
        "GET",
    );
    let err = recovered.advance(response(json!([]))).err().unwrap();
    assert_eq!(err.side_effect, SideEffect::Unknown);
}

#[test]
fn automatic_zone_discovery_rejects_ambiguous_or_invalid_results() {
    let factory = Cloudflare::new(CloudflareConfig {
        zone_id: String::new(),
        api_token: Some("sensitive-sentinel".into()),
        token_file: None,
    })
    .unwrap();
    for result in [
        json!([{"id":ZONE,"name":"example.com"},{"id":ZONE,"name":"example.com"}]),
        json!([{"id":ZONE,"name":"other.example.com"}]),
        json!([{"id":"bad","name":"example.com"}]),
    ] {
        let mut op = factory
            .start(ProviderAction::Present(record()), None)
            .unwrap();
        http(op.advance(ProviderEvent::Start).unwrap(), "GET");
        http(op.advance(response(json!([]))).unwrap(), "GET");
        assert!(op.advance(response(result)).is_err());
    }
    let mut op = factory
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    http(op.advance(ProviderEvent::Start).unwrap(), "GET");
    http(op.advance(response(json!([]))).unwrap(), "GET");
    assert!(op.advance(response(json!([]))).is_err());
}
