use crate::provider::vendors::google_cloud_dns::{
    Config, GoogleCloudDnsBackend, ServiceAccount, api, auth, operation::Factory,
};
use aster_acme_dns::{
    CleanupRequest, CleanupStatus, DnsRecord, ProviderErrorCode, SideEffect,
    backend::{BackendConfig, DnsBackend},
    operation::{
        HttpFailure, HttpResponse, OperationFactory, ProviderAction, ProviderEffect, ProviderEvent,
        ProviderOperation, ProviderOutcome, RecoveryState,
    },
};
use aws_lc_rs::{
    encoding::AsDer as _,
    rsa::{KeyPair, KeySize},
    signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

fn config() -> Config {
    static PEM: OnceLock<String> = OnceLock::new();
    Config {
        service_account: ServiceAccount {
            kind: "service_account".into(),
            project_id: "test-project".into(),
            client_email: "dns@test-project.iam.gserviceaccount.com".into(),
            private_key_id: "key-1".into(),
            token_uri: auth::TOKEN_URL.into(),
            private_key: PEM
                .get_or_init(|| {
                    let key = KeyPair::generate(KeySize::Rsa2048).unwrap();
                    format!(
                        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                        STANDARD.encode(key.as_der().unwrap().as_ref())
                    )
                })
                .clone(),
        },
    }
}

fn input() -> BackendConfig {
    let c = config();
    let a = &c.service_account;
    BackendConfig { custom: serde_json::from_value(json!({"service_account":{"type":"service_account","project_id":a.project_id,"client_email":a.client_email,"private_key_id":a.private_key_id,"private_key":a.private_key,"token_uri":a.token_uri}})).unwrap(), ..BackendConfig::default() }
}

fn factory() -> Factory {
    Factory {
        config: config(),
        token: Arc::new(Mutex::new(Some(auth::Token {
            value: zeroize::Zeroizing::new("test-token".into()),
            expires: Instant::now() + Duration::from_secs(3600),
        }))),
    }
}

fn record() -> DnsRecord {
    DnsRecord {
        publication_id: "publication-1".into(),
        challenge_name: "_acme-challenge.example.com.".into(),
        name: "delegated.validation.net.".into(),
        value: "our-value".into(),
        ttl_seconds: Some(120),
        cname_chain: vec![
            "_acme-challenge.example.com.".into(),
            "delegated.validation.net.".into(),
        ],
    }
}

fn response(value: &Value) -> ProviderEvent {
    ProviderEvent::Http(Ok(HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(value).unwrap(),
    }))
}

fn http(effect: ProviderEffect, method: &str) -> aster_acme_dns::operation::HttpRequest {
    let ProviderEffect::Http(request) = effect else {
        panic!("expected HTTP")
    };
    assert_eq!(request.method.as_str(), method);
    request
}

fn cp(effect: ProviderEffect) -> RecoveryState {
    let ProviderEffect::Checkpoint(state) = effect else {
        panic!("expected checkpoint")
    };
    state
}

fn rrset(values: &[&str]) -> Value {
    json!({"name":record().name,"type":"TXT","ttl":300,"rrdatas":values,"kind":"dns#resourceRecordSet","futureMetadata":"keep"})
}

fn begin(f: &Factory) -> Box<dyn ProviderOperation> {
    let mut op = f.start(ProviderAction::Present(record()), None).unwrap();
    let req = http(op.advance(ProviderEvent::Start).unwrap(), "GET");
    assert!(req.url.contains("managedZones"));
    let next = http(op.advance(response(&json!({"managedZones":[{"id":"parent","dnsName":"net.","visibility":"public"}],"nextPageToken":"page two"}))).unwrap(), "GET");
    assert!(next.url.contains("pageToken=page+two"));
    let state = cp(op.advance(response(&json!({"managedZones":[{"id":"private","dnsName":"delegated.validation.net.","visibility":"private"},{"id":"zone-1","dnsName":"validation.net.","visibility":"public"}]}))).unwrap());
    assert_eq!(state.data["zone"]["id"], "zone-1");
    let req = http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    assert!(req.url.contains("/zone-1/rrsets?"));
    op
}

fn submit(op: &mut dyn ProviderOperation, values: &[Value]) -> (RecoveryState, Value) {
    let intent = cp(op.advance(response(&json!({"rrsets":values}))).unwrap());
    assert_eq!(intent.data["phase"], "present_intent");
    let req = http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "POST");
    assert!(req.mutation);
    (intent, serde_json::from_slice(&req.body).unwrap())
}

fn applied(op: &mut dyn ProviderOperation, plan: &Value, id: &str) -> RecoveryState {
    let mut change = plan.clone();
    change["id"] = json!(id);
    change["status"] = json!("done");
    let state = cp(op.advance(response(&change.clone())).unwrap());
    assert_eq!(state.data["change_id"], id);
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    http(op.advance(response(&change)).unwrap(), "GET");
    state
}

#[test]
fn jwt_is_rs256_verifiable_and_endpoint_is_pinned() {
    let c = config();
    let req = auth::request(&c.service_account, 1234).unwrap();
    assert_eq!(req.url, auth::TOKEN_URL);
    assert!(!req.mutation);
    let form: std::collections::HashMap<_, _> = url::form_urlencoded::parse(&req.body)
        .into_owned()
        .collect();
    let parts: Vec<_> = form["assertion"].split('.').collect();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(claims["exp"], 4834);
    assert_eq!(claims["aud"], auth::TOKEN_URL);
    assert_eq!(
        claims["scope"],
        "https://www.googleapis.com/auth/ndev.clouddns.readwrite"
    );
    let key = auth::key(&c.service_account).unwrap();
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key().as_ref())
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
        .unwrap();
    let mut input = input();
    input.custom["service_account"]["token_uri"] = json!("https://attacker.invalid");
    assert!(GoogleCloudDnsBackend.validate(&input).is_err());
}

#[test]
fn token_expiration_refresh_and_shared_cache() {
    let f = factory();
    f.token.lock().unwrap().as_mut().unwrap().expires = Instant::now();
    let mut op = f.start(ProviderAction::Present(record()), None).unwrap();
    assert_eq!(
        http(op.advance(ProviderEvent::Start).unwrap(), "POST").url,
        auth::TOKEN_URL
    );
    http(
        op.advance(response(
            &json!({"access_token":"new-token","token_type":"Bearer","expires_in":3600}),
        ))
        .unwrap(),
        "GET",
    );
    let mut other = f.start(ProviderAction::Present(record()), None).unwrap();
    let req = http(other.advance(ProviderEvent::Start).unwrap(), "GET");
    assert!(
        req.headers
            .contains(&("Authorization".into(), "Bearer new-token".into()))
    );
    for body in [
        json!({"access_token":"invalid token","token_type":"Bearer","expires_in":3600}),
        json!({"access_token":"token","token_type":"Bearer","expires_in":30}),
    ] {
        assert!(auth::token(&serde_json::to_vec(&body).unwrap()).is_err());
    }
}

#[test]
fn merge_and_cleanup_preserve_other_values_metadata_and_current_ttl() {
    let f = factory();
    let mut op = begin(&f);
    let (_, plan) = submit(op.as_mut(), &[rrset(&["\"existing\""])]);
    assert_eq!(plan["deletions"][0], rrset(&["\"existing\""]));
    assert_eq!(plan["additions"][0]["futureMetadata"], "keep");
    applied(op.as_mut(), &plan, "change-1");
    let saved = cp(op
        .advance(response(
            &json!({"rrsets":[rrset(&["\"existing\"","\"our-value\""])]}),
        ))
        .unwrap());
    let ProviderEffect::Complete(ProviderOutcome::Presented(receipt)) =
        op.advance(ProviderEvent::CheckpointSaved).unwrap()
    else {
        panic!()
    };
    assert_eq!(receipt.effective_ttl_seconds, Some(300));
    let mut cleanup = f
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
    let mut current = rrset(&["\"existing\"", "\"our-value\"", "\"later\""]);
    current["ttl"] = json!(600);
    cp(cleanup
        .advance(response(&json!({"rrsets":[current]})))
        .unwrap());
    let req = http(
        cleanup.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "POST",
    );
    let plan: Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(
        plan["additions"][0]["rrdatas"],
        json!(["\"existing\"", "\"later\""])
    );
    assert_eq!(plan["additions"][0]["ttl"], 600);
    applied(cleanup.as_mut(), &plan, "change-2");
    cp(cleanup
        .advance(response(
            &json!({"rrsets":[rrset(&["\"existing\"","\"later\""])]}),
        ))
        .unwrap());
    assert!(matches!(
        cleanup.advance(ProviderEvent::CheckpointSaved).unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Removed))
    ));
}

#[test]
fn unknown_submit_never_replays_or_adopts_existing_value() {
    let f = factory();
    let mut op = begin(&f);
    let (intent, _) = submit(op.as_mut(), &[]);
    let error = op
        .advance(ProviderEvent::Http(Err(HttpFailure {
            code: ProviderErrorCode::ProviderTimeout,
            side_effect: SideEffect::Unknown,
        })))
        .err()
        .unwrap();
    assert_eq!(error.side_effect, SideEffect::Unknown);
    let mut resumed = f
        .start(ProviderAction::Present(record()), Some(intent))
        .unwrap();
    assert_eq!(
        resumed.advance(ProviderEvent::Start).err().unwrap().code,
        ProviderErrorCode::RecordNotOwned
    );
    let mut other = begin(&f);
    assert_eq!(
        other
            .advance(response(&json!({"rrsets":[rrset(&["\"our-value\""])]})))
            .err()
            .unwrap()
            .code,
        ProviderErrorCode::RecordConflict
    );
}

#[test]
fn saved_change_id_recovers_by_reading_change_without_another_write() {
    let f = factory();
    let mut op = begin(&f);
    let (_, plan) = submit(op.as_mut(), &[]);
    let mut change = plan.clone();
    change["id"] = json!("42");
    change["status"] = json!("pending");
    let saved = cp(op.advance(response(&change.clone())).unwrap());
    let mut resumed = f
        .start(ProviderAction::Present(record()), Some(saved.clone()))
        .unwrap();
    let req = http(resumed.advance(ProviderEvent::Start).unwrap(), "GET");
    assert!(req.url.ends_with("/changes/42"));
    assert!(matches!(
        resumed.advance(response(&change.clone())).unwrap(),
        ProviderEffect::WaitUntil(_)
    ));
    http(resumed.advance(ProviderEvent::Timer).unwrap(), "GET");
    change["status"] = json!("done");
    http(resumed.advance(response(&change)).unwrap(), "GET");
    let state = cp(resumed
        .advance(response(&json!({"rrsets":[rrset(&["\"our-value\""])]})))
        .unwrap());
    assert_eq!(state.data["phase"], "presented");
    let mut forged = saved;
    forged.data["plan"]["additions"][0]["rrdatas"] = json!(["\"another-value\""]);
    assert!(
        f.start(ProviderAction::Present(record()), Some(forged))
            .is_err()
    );
}

#[test]
fn rate_limit_is_redacted_persisted_and_enforced_on_restart() {
    let f = factory();
    let mut op = begin(&f);
    submit(op.as_mut(), &[]);
    let limited = ProviderEvent::Http(Ok(HttpResponse {
        status: 429,
        headers: vec![("Retry-After".into(), b"120".to_vec())],
        body:
            br#"{"error":{"message":"secret-sentinel","errors":[{"reason":"rateLimitExceeded"}]}}"#
                .to_vec(),
    }));
    let saved = cp(op.advance(limited).unwrap());
    let err = op.advance(ProviderEvent::CheckpointSaved).err().unwrap();
    assert_eq!(err.code, ProviderErrorCode::RateLimited);
    assert!(!err.message.contains("secret-sentinel"));
    assert!(
        !serde_json::to_string(&saved)
            .unwrap()
            .contains("test-token")
    );
    let mut resumed = f
        .start(ProviderAction::Present(record()), Some(saved))
        .unwrap();
    assert_eq!(
        resumed.advance(ProviderEvent::Start).err().unwrap().code,
        ProviderErrorCode::RateLimited
    );
}

#[test]
fn rejected_conflict_rechecks_current_values_before_retry() {
    let f = factory();
    let mut op = begin(&f);
    submit(op.as_mut(), &[]);
    cp(op
        .advance(ProviderEvent::Http(Ok(HttpResponse {
            status: 412,
            headers: vec![],
            body: br#"{"error":{"errors":[{"reason":"preconditionFailed"}]}}"#.to_vec(),
        })))
        .unwrap());
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    let (_, plan) = submit(op.as_mut(), &[rrset(&["\"concurrent\""])]);
    assert_eq!(plan["deletions"][0]["rrdatas"], json!(["\"concurrent\""]));
}

#[test]
fn malformed_rrsets_and_duplicate_logical_txt_fail_closed() {
    for set in [
        rrset(&["\"our-value\"", "\"our-\" \"value\""]),
        json!({"name":record().name,"type":"TXT","ttl":120,"rrdatas":["bad"]}),
        json!({"name":record().name,"type":"TXT","ttl":120,"rrdatas":["\"other\""],"routingPolicy":{}}),
    ] {
        let f = factory();
        let mut op = begin(&f);
        assert!(op.advance(response(&json!({"rrsets":[set]}))).is_err());
    }
    for (status, code) in [
        (400, ProviderErrorCode::InvalidRequest),
        (403, ProviderErrorCode::AuthorizationDenied),
        (500, ProviderErrorCode::ProviderUnavailable),
    ] {
        let err = api::failure(
            &HttpResponse {
                status,
                headers: vec![],
                body: b"private-key-sentinel".to_vec(),
            },
            true,
        );
        assert_eq!(err.code, code);
        assert!(!err.message.contains("private-key-sentinel"));
        assert_eq!(err.side_effect, SideEffect::Unknown);
    }
}

#[test]
fn rejected_bearer_invalidates_only_the_ephemeral_token() {
    let f = factory();
    let mut op = begin(&f);
    let failure = op
        .advance(ProviderEvent::Http(Ok(HttpResponse {
            status: 401,
            headers: vec![],
            body: b"secret-sentinel".to_vec(),
        })))
        .err()
        .unwrap();
    assert_eq!(failure.code, ProviderErrorCode::AuthenticationFailed);
    assert!(!failure.message.contains("secret-sentinel"));
    assert!(f.token.lock().unwrap().is_none());
    let mut next = f.start(ProviderAction::Present(record()), None).unwrap();
    assert_eq!(
        http(next.advance(ProviderEvent::Start).unwrap(), "POST").url,
        auth::TOKEN_URL
    );
}

#[test]
fn duplicate_wire_values_and_zone_pages_are_rejected() {
    let f = factory();
    let mut op = begin(&f);
    assert!(
        op.advance(response(
            &json!({"rrsets":[rrset(&["\"same\"","\"same\""])]})
        ))
        .is_err()
    );
    let mut op = f.start(ProviderAction::Present(record()), None).unwrap();
    http(op.advance(ProviderEvent::Start).unwrap(), "GET");
    http(
        op.advance(response(
            &json!({"managedZones":[],"nextPageToken":"repeat"}),
        ))
        .unwrap(),
        "GET",
    );
    assert!(
        op.advance(response(
            &json!({"managedZones":[],"nextPageToken":"repeat"})
        ))
        .is_err()
    );
}

#[test]
fn nonreusable_change_plan_and_unknown_checkpoint_version_fail_closed() {
    let f = factory();
    let mut op = begin(&f);
    let (intent, _) = submit(op.as_mut(), &[rrset(&["\"existing\""])]);
    let mut changed = intent.clone();
    changed.version = 2;
    assert!(
        f.start(ProviderAction::Present(record()), Some(changed))
            .is_err()
    );
    let mut changed = intent.clone();
    changed.data["plan"]["additions"][0]["ttl"] = json!(999);
    assert!(
        f.start(ProviderAction::Present(record()), Some(changed))
            .is_err()
    );
    let mut changed = intent;
    changed.data["zone"]["dnsName"] = json!("elsewhere.example.");
    assert!(
        f.start(ProviderAction::Present(record()), Some(changed))
            .is_err()
    );
}

#[test]
fn completed_cleanup_never_reads_or_deletes_a_recreated_value() {
    let f = factory();
    let mut op = begin(&f);
    let (_, plan) = submit(op.as_mut(), &[]);
    applied(op.as_mut(), &plan, "first");
    let saved = cp(op
        .advance(response(&json!({"rrsets":[rrset(&["\"our-value\""])]})))
        .unwrap());
    let ProviderEffect::Complete(ProviderOutcome::Presented(receipt)) =
        op.advance(ProviderEvent::CheckpointSaved).unwrap()
    else {
        panic!()
    };
    let action = ProviderAction::Cleanup(CleanupRequest {
        publication_id: record().publication_id.clone(),
        record: record(),
        receipt,
    });
    let mut cleanup = f.start(action.clone(), Some(saved)).unwrap();
    http(cleanup.advance(ProviderEvent::Start).unwrap(), "GET");
    cp(cleanup
        .advance(response(&json!({"rrsets":[rrset(&["\"our-value\""])]})))
        .unwrap());
    let request = http(
        cleanup.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "POST",
    );
    let plan: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(plan["additions"], json!([]));
    applied(cleanup.as_mut(), &plan, "second");
    let cleaned = cp(cleanup.advance(response(&json!({"rrsets":[]}))).unwrap());
    assert!(matches!(
        cleanup.advance(ProviderEvent::CheckpointSaved).unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Removed))
    ));
    let mut repeated = f.start(action, Some(cleaned.clone())).unwrap();
    assert!(matches!(
        repeated.advance(ProviderEvent::Start).unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Removed))
    ));
    assert!(
        f.start(ProviderAction::Present(record()), Some(cleaned))
            .is_err()
    );
}

#[test]
fn failed_token_refresh_before_dns_write_persists_not_sent_evidence() {
    let f = factory();
    let mut op = begin(&f);
    cp(op.advance(response(&json!({"rrsets":[]}))).unwrap());
    f.token.lock().unwrap().as_mut().unwrap().expires = Instant::now();
    assert_eq!(
        http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "POST").url,
        auth::TOKEN_URL
    );
    let saved = cp(op
        .advance(ProviderEvent::Http(Err(HttpFailure {
            code: ProviderErrorCode::ProviderTimeout,
            side_effect: SideEffect::None,
        })))
        .unwrap());
    assert_eq!(saved.data["phase"], "resolved");
    assert_eq!(
        op.advance(ProviderEvent::CheckpointSaved)
            .err()
            .unwrap()
            .side_effect,
        SideEffect::None
    );
    let mut resumed = f
        .start(ProviderAction::Present(record()), Some(saved))
        .unwrap();
    assert_eq!(
        http(resumed.advance(ProviderEvent::Start).unwrap(), "POST").url,
        auth::TOKEN_URL
    );
    let request = http(
        resumed
            .advance(response(
                &json!({"access_token":"refreshed-token","token_type":"Bearer","expires_in":3600}),
            ))
            .unwrap(),
        "GET",
    );
    assert!(request.url.contains("/rrsets?"));
}
