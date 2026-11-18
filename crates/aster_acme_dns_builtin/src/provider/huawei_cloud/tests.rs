use crate::provider::huawei_cloud::{
    BACKEND_ID, Config, HuaweiCloudBackend,
    api::{SignedRequest, canonical_query, canonical_uri},
    operation::Factory,
    txt::{add_marker, remove_marker, txt_decode, txt_encode},
};
use aster_acme_dns::{
    CleanupRequest, CleanupStatus, DnsRecord, ProviderErrorCode, RecordOwnership, SideEffect,
    backend::{BackendConfig, DnsBackend},
    operation::{
        HttpFailure, HttpResponse, OperationFactory, ProviderAction, ProviderEffect, ProviderEvent,
        ProviderOperation, ProviderOutcome, RecoveryState,
    },
};
use serde_json::{Value, json};

fn config() -> Config {
    Config {
        access_key_id: "AccessKey".into(),
        access_key_secret: "SecretKey".into(),
        region: "cn-north-4".into(),
        project_id: Some("0123456789abcdef0123456789abcdef".into()),
    }
}
fn record() -> DnsRecord {
    DnsRecord {
        publication_id: "publication-1".into(),
        challenge_name: "_acme-challenge.example.com.".into(),
        cname_chain: vec![
            "_acme-challenge.example.com.".into(),
            "delegated.validation.net.".into(),
        ],
        name: "delegated.validation.net.".into(),
        value: "our-value".into(),
        ttl_seconds: Some(120),
    }
}
fn factory() -> Factory {
    Factory { config: config() }
}
fn auto_project_factory() -> Factory {
    let mut config = config();
    config.project_id = None;
    Factory { config }
}
fn http(effect: ProviderEffect, method: &str) -> aster_acme_dns::operation::HttpRequest {
    let ProviderEffect::Http(request) = effect else {
        panic!("expected {method} request");
    };
    assert_eq!(request.method.as_str(), method);
    assert_eq!(request.mutation, method != "GET");
    request
}
fn reply(
    op: &mut dyn ProviderOperation,
    status: u16,
    body: impl Into<Value>,
) -> Result<ProviderEffect, aster_acme_dns::ProviderError> {
    op.advance(ProviderEvent::Http(Ok(HttpResponse {
        status,
        headers: vec![],
        body: body.into().to_string().into_bytes(),
    })))
}
fn checkpoint(effect: ProviderEffect, phase: &str) -> RecoveryState {
    let ProviderEffect::Checkpoint(cp) = effect else {
        panic!("expected checkpoint");
    };
    assert_eq!(cp.data["phase"], phase);
    assert!(!serde_json::to_string(&cp).unwrap().contains("SecretKey"));
    cp
}
fn zone() -> Value {
    json!({"id":"zone-child","name":"validation.net."})
}
fn row(values: &[&str], description: &str) -> Value {
    json!({"id":"recordset-1","name":"delegated.validation.net.","type":"TXT",
        "records":values.iter().map(|value| txt_encode(value)).collect::<Vec<_>>(),"description":description,"ttl":300, "zone_id":"zone-child","status":"ACTIVE"})
}
fn listing(values: Vec<Value>) -> Value {
    json!({"recordsets": Value::Array(values)})
}
fn initial(op: &mut dyn ProviderOperation) -> RecoveryState {
    let req = http(op.advance(ProviderEvent::Start).unwrap(), "GET");
    assert!(req.url.contains("/v2/zones?"));
    checkpoint(
        reply(op, 200, json!({"zones":[zone()]})).unwrap(),
        "zone_resolved",
    )
}
fn intent(op: &mut dyn ProviderOperation, values: Vec<Value>) -> RecoveryState {
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    checkpoint(reply(op, 200, listing(values)).unwrap(), "present_intent")
}
fn receipt(op: &mut dyn ProviderOperation) -> aster_acme_dns::PublicationReceipt {
    let ProviderEffect::Complete(ProviderOutcome::Presented(receipt)) =
        op.advance(ProviderEvent::CheckpointSaved).unwrap()
    else {
        panic!("expected receipt");
    };
    receipt
}
#[test]
fn official_hws_get_and_post_signatures_use_exact_wire_bytes() {
    let get = SignedRequest {
        endpoint: "https://example.huaweicloud.com",
        method: aster_acme_dns::operation::HttpMethod::Get,
        path: "/path",
        query: &[("limit", "1")],
        body: &[],
        mutation: false,
        project_id: None,
    }
    .sign("AccessKey", "SecretKey", "20060102T150405Z")
    .unwrap();
    assert_eq!(
        get.headers.last().unwrap().1,
        "SDK-HMAC-SHA256 Access=AccessKey, SignedHeaders=x-sdk-date, Signature=5a2ce64c865e0e6046321c6f3d5a77ba8413eeaf355c3166c03d58d02ac79624"
    );
    let post = SignedRequest {
        endpoint: "https://example.huaweicloud.com",
        method: aster_acme_dns::operation::HttpMethod::Post,
        path: "/path",
        query: &[("key", "value")],
        body: b"{\"Name\":\"test\",\"Id\":1}\n",
        mutation: true,
        project_id: None,
    }
    .sign("AccessKey", "SecretKey", "20060102T150405Z")
    .unwrap();
    assert_eq!(
        post.headers.last().unwrap().1,
        "SDK-HMAC-SHA256 Access=AccessKey, SignedHeaders=x-sdk-date, Signature=cecc2af119b18ab70b4d094c0750f3b42c02f254903179a0fc2cc72fc9db4f59"
    );
    assert_eq!(canonical_uri("/v2/path x"), "/v2/path%20x/");
    assert_eq!(
        canonical_query(&[
            ("test", "一 (&=?!#%.*)"),
            ("path", "/tmp/123"),
            ("enable", "true")
        ]),
        "enable=true&path=%2Ftmp%2F123&test=%E4%B8%80%20%28%26%3D%3F%21%23%25.%2A%29"
    );
}
#[test]
fn descriptor_is_explicitly_best_effort_and_keys_are_sensitive() {
    let backend = HuaweiCloudBackend;
    let config = BackendConfig {
        custom: serde_json::from_value(json!({
        "access_key_id":"AccessKey","access_key_secret":"SecretKey","project_id":"0123456789abcdef0123456789abcdef"}))
        .unwrap(),
        ..BackendConfig::default()
    };
    backend.validate(&config).unwrap();
    assert_eq!(
        backend.binding(&config).unwrap(),
        "cn-north-4:0123456789abcdef0123456789abcdef:best-effort"
    );
    let descriptor = backend.descriptor();
    assert_eq!(descriptor.id, BACKEND_ID);
    assert_eq!(
        serde_json::to_value(descriptor.mutation_model).unwrap(),
        "best_effort_rrsets"
    );
    assert!(
        descriptor
            .fields
            .iter()
            .filter(|field| field.name.starts_with("access_"))
            .all(|field| field.sensitive)
    );
    let automatic = BackendConfig {
        custom: serde_json::from_value(json!({
            "access_key_id":"AccessKey", "access_key_secret":"SecretKey"
        }))
        .unwrap(),
        ..BackendConfig::default()
    };
    backend.validate(&automatic).unwrap();
    assert_eq!(
        backend.binding(&automatic).unwrap(),
        "cn-north-4:auto:best-effort"
    );
}

#[test]
fn missing_project_id_discovers_the_unique_region_project_and_persists_it_before_dns() {
    let mut op = auto_project_factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    let request = http(op.advance(ProviderEvent::Start).unwrap(), "GET");
    assert!(
        request
            .url
            .starts_with("https://iam.cn-north-4.myhuaweicloud.com/v3/projects?")
    );
    assert!(request.url.contains("name=cn-north-4"));
    assert!(
        !request
            .headers
            .iter()
            .any(|(name, _)| name == "x-project-id")
    );
    let saved = checkpoint(
        reply(
            op.as_mut(),
            200,
            json!({"projects":[{"id":"0123456789abcdef0123456789abcdef","name":"cn-north-4"}]}),
        )
        .unwrap(),
        "project_resolved",
    );
    assert_eq!(
        saved.data["resolved_project_id"],
        "0123456789abcdef0123456789abcdef"
    );
    let request = http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    assert!(request.headers.iter().any(|(name, value)| {
        name == "x-project-id" && value == "0123456789abcdef0123456789abcdef"
    }));
    let mut resumed = auto_project_factory()
        .start(ProviderAction::Present(record()), Some(saved.clone()))
        .unwrap();
    let request = http(resumed.advance(ProviderEvent::Start).unwrap(), "GET");
    assert!(
        request
            .url
            .starts_with("https://dns.cn-north-4.myhuaweicloud.com/")
    );
    assert!(
        request
            .headers
            .iter()
            .any(|(name, value)| name == "x-project-id"
                && value == "0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn missing_project_id_rejects_zero_or_ambiguous_iam_matches() {
    for projects in [
        json!([]),
        json!([{"id":"0123456789abcdef0123456789abcdef","name":"cn-north-4"},
               {"id":"fedcba9876543210fedcba9876543210","name":"cn-north-4"}]),
    ] {
        let mut op = auto_project_factory()
            .start(ProviderAction::Present(record()), None)
            .unwrap();
        http(op.advance(ProviderEvent::Start).unwrap(), "GET");
        let error = reply(op.as_mut(), 200, json!({"projects":projects}))
            .err()
            .unwrap();
        assert_eq!(error.code, ProviderErrorCode::RecordConflict);
        assert_eq!(error.side_effect, SideEffect::None);
    }
}
#[test]
fn publication_merges_current_values_and_cleanup_preserves_later_values() {
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(op.as_mut());
    intent(op.as_mut(), vec![row(&["user-value"], "user description")]);
    let request = http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "PUT");
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(
        body["records"],
        json!([txt_encode("our-value"), txt_encode("user-value")])
    );
    assert_eq!(
        body["description"],
        format!("user description;{}", marker("publication-1", "our-value"))
    );
    checkpoint(
        reply(
            op.as_mut(),
            200,
            row(
                &["our-value", "user-value"],
                &format!("user description;{}", marker("publication-1", "our-value")),
            ),
        )
        .unwrap(),
        "present_intent",
    );
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    let saved = checkpoint(
        reply(
            op.as_mut(),
            200,
            listing(vec![row(
                &["our-value", "user-value"],
                &format!("user description;{}", marker("publication-1", "our-value")),
            )]),
        )
        .unwrap(),
        "presented",
    );
    let receipt = receipt(op.as_mut());
    assert_eq!(receipt.record_id, "recordset-1");
    assert_eq!(receipt.ownership, RecordOwnership::Created);
    let request = CleanupRequest {
        publication_id: record().publication_id.clone(),
        receipt,
        record: record(),
    };
    let mut cleanup = factory()
        .start(ProviderAction::Cleanup(request), Some(saved))
        .unwrap();
    http(cleanup.advance(ProviderEvent::Start).unwrap(), "GET");
    checkpoint(
        reply(
            cleanup.as_mut(),
            200,
            listing(vec![row(
                &["our-value", "user-value", "later-value"],
                &format!("user description;{}", marker("publication-1", "our-value")),
            )]),
        )
        .unwrap(),
        "cleanup_intent",
    );
    let update = http(
        cleanup.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "PUT",
    );
    let body: Value = serde_json::from_slice(&update.body).unwrap();
    assert_eq!(
        body["records"],
        json!([txt_encode("later-value"), txt_encode("user-value")])
    );
    assert_eq!(body["description"], "user description");
}
#[test]
fn lost_create_reconciles_marker_and_unknown_unmarked_value_never_becomes_owned() {
    let mut first = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(first.as_mut());
    let saved = intent(first.as_mut(), vec![]);
    http(
        first.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "POST",
    );
    assert_eq!(
        first
            .advance(ProviderEvent::Http(Err(HttpFailure {
                code: ProviderErrorCode::ProviderTimeout,
                side_effect: SideEffect::Unknown,
            })))
            .err()
            .unwrap()
            .side_effect,
        SideEffect::Unknown
    );
    let mut recovered = factory()
        .start(ProviderAction::Present(record()), Some(saved.clone()))
        .unwrap();
    http(recovered.advance(ProviderEvent::Start).unwrap(), "GET");
    checkpoint(
        reply(
            recovered.as_mut(),
            200,
            listing(vec![row(
                &["our-value"],
                &marker("publication-1", "our-value"),
            )]),
        )
        .unwrap(),
        "presented",
    );
    assert_eq!(
        receipt(recovered.as_mut()).ownership,
        RecordOwnership::Created
    );
    for values in [vec![], vec![row(&["our-value"], "operator")]] {
        let mut recovered = factory()
            .start(ProviderAction::Present(record()), Some(saved.clone()))
            .unwrap();
        http(recovered.advance(ProviderEvent::Start).unwrap(), "GET");
        assert_eq!(
            reply(recovered.as_mut(), 200, listing(values))
                .err()
                .unwrap()
                .code,
            ProviderErrorCode::RecordNotOwned
        );
    }
}
#[test]
fn preexisting_same_value_is_retained_and_foreign_marker_is_rejected() {
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(op.as_mut());
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    checkpoint(
        reply(op.as_mut(), 200, listing(vec![row(&["our-value"], "user")])).unwrap(),
        "presented",
    );
    assert_eq!(receipt(op.as_mut()).ownership, RecordOwnership::Preexisting);
    let mut foreign = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(foreign.as_mut());
    http(
        foreign.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "GET",
    );
    assert_eq!(
        reply(
            foreign.as_mut(),
            200,
            listing(vec![row(&["our-value"], &marker("other", "our-value"))])
        )
        .err()
        .unwrap()
        .code,
        ProviderErrorCode::RecordConflict
    );
}
#[test]
fn descriptions_preserve_user_text_and_bound_markers() {
    assert_eq!(
        add_marker("user", "asteracme:p").unwrap(),
        "user;asteracme:p"
    );
    assert_eq!(
        remove_marker("user;asteracme:p;asteracme:q", "asteracme:p"),
        "user;asteracme:q"
    );
    assert!(add_marker(&"x".repeat(255), "asteracme:p").is_err());
}

fn marker(id: &str, value: &str) -> String {
    format!(
        "asteracme:{id}={}",
        crate::provider::rpc::sha256(value.as_bytes())
    )
}

#[test]
fn txt_wire_representation_roundtrips_quotes_backslashes_utf8_and_chunk_boundaries() {
    for value in ["normal", "a\"b\\c", "一\n\0", ""] {
        assert_eq!(txt_decode(&txt_encode(value)).unwrap(), value.as_bytes());
    }
    assert_eq!(txt_decode(r#""our-" "value""#).unwrap(), b"our-value");
    assert_eq!(txt_decode(r#""\111ur-value""#).unwrap(), b"our-value");
    for input in ["raw", "\"unterminated", r#""\999""#, r#""\1""#, ""] {
        assert!(txt_decode(input).is_none());
    }
    assert!(txt_decode(&format!("\"{}\"", "a".repeat(256))).is_none());
}

fn presented_checkpoint(
    values: &[&str],
    description: &str,
) -> (RecoveryState, aster_acme_dns::PublicationReceipt) {
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(op.as_mut());
    intent(op.as_mut(), vec![]);
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "POST");
    checkpoint(
        reply(op.as_mut(), 202, row(values, description)).unwrap(),
        "present_intent",
    );
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    let state = checkpoint(
        reply(op.as_mut(), 200, listing(vec![row(values, description)])).unwrap(),
        "presented",
    );
    (state, receipt(op.as_mut()))
}

#[test]
fn cleanup_last_value_deletes_only_after_checkpoint_then_confirms_absence_and_is_terminal() {
    let (state, receipt) =
        presented_checkpoint(&["our-value"], &marker("publication-1", "our-value"));
    let request = CleanupRequest {
        record: record(),
        receipt,
        publication_id: record().publication_id,
    };
    let mut op = factory()
        .start(ProviderAction::Cleanup(request.clone()), Some(state))
        .unwrap();
    http(op.advance(ProviderEvent::Start).unwrap(), "GET");
    checkpoint(
        reply(
            op.as_mut(),
            200,
            listing(vec![row(
                &["our-value"],
                &marker("publication-1", "our-value"),
            )]),
        )
        .unwrap(),
        "cleanup_intent",
    );
    let delete = http(
        op.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "DELETE",
    );
    assert!(
        delete
            .url
            .ends_with("/zones/zone-child/recordsets/recordset-1")
    );
    http(reply(op.as_mut(), 202, json!({})).unwrap(), "GET");
    let state = checkpoint(reply(op.as_mut(), 200, listing(vec![])).unwrap(), "cleaned");
    assert!(matches!(
        op.advance(ProviderEvent::CheckpointSaved).unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Removed))
    ));
    let mut restored = factory()
        .start(ProviderAction::Cleanup(request), Some(state.clone()))
        .unwrap();
    assert!(matches!(
        restored.advance(ProviderEvent::Start).unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Removed))
    ));
    assert!(
        factory()
            .start(ProviderAction::Present(record()), Some(state))
            .is_err()
    );
}

#[test]
fn cleanup_rejects_changed_id_tuple_marker_or_receipt_without_a_mutation() {
    let mark = marker("publication-1", "our-value");
    let (state, receipt) = presented_checkpoint(&["our-value"], &mark);
    let request = CleanupRequest {
        record: record(),
        receipt: receipt.clone(),
        publication_id: record().publication_id,
    };
    for (field, replacement) in [
        ("id", json!("replacement")),
        ("description", json!("user")),
        ("zone_id", json!("other-zone")),
        ("status", json!("DISABLE")),
    ] {
        let mut op = factory()
            .start(
                ProviderAction::Cleanup(request.clone()),
                Some(state.clone()),
            )
            .unwrap();
        http(op.advance(ProviderEvent::Start).unwrap(), "GET");
        let mut set = row(&["our-value"], &mark);
        set[field] = replacement;
        assert!(reply(op.as_mut(), 200, listing(vec![set])).is_err());
    }
    assert!(
        factory()
            .start(ProviderAction::Cleanup(request.clone()), None)
            .is_err()
    );
    let mut changed = request;
    changed.publication_id = "different".into();
    assert!(
        factory()
            .start(ProviderAction::Cleanup(changed), Some(state))
            .is_err()
    );
}

#[test]
fn root_and_wildcard_can_share_rrset_with_separate_markers_and_cleanup_preserves_the_other() {
    let first_marker = marker("publication-1", "our-value");
    let other_marker = marker("publication-2", "wildcard-value");
    let mut wildcard = record();
    wildcard.publication_id = "publication-2".into();
    wildcard.value = "wildcard-value".into();
    let mut op = factory()
        .start(ProviderAction::Present(wildcard), None)
        .unwrap();
    initial(op.as_mut());
    intent(op.as_mut(), vec![row(&["our-value"], &first_marker)]);
    let put = http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "PUT");
    let body: Value = serde_json::from_slice(&put.body).unwrap();
    assert_eq!(
        body["description"],
        format!("{first_marker};{other_marker}")
    );
    assert_eq!(
        body["records"],
        json!([txt_encode("our-value"), txt_encode("wildcard-value")])
    );
    assert!(body.get("ttl").is_none());
    let (state, receipt) = presented_checkpoint(&["our-value"], &first_marker);
    let mut cleanup = factory()
        .start(
            ProviderAction::Cleanup(CleanupRequest {
                record: record(),
                publication_id: record().publication_id,
                receipt,
            }),
            Some(state),
        )
        .unwrap();
    http(cleanup.advance(ProviderEvent::Start).unwrap(), "GET");
    checkpoint(
        reply(
            cleanup.as_mut(),
            200,
            listing(vec![row(
                &["our-value", "wildcard-value"],
                &format!("{first_marker};{other_marker}"),
            )]),
        )
        .unwrap(),
        "cleanup_intent",
    );
    let put = http(
        cleanup.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "PUT",
    );
    let body: Value = serde_json::from_slice(&put.body).unwrap();
    assert_eq!(body["description"], other_marker);
    assert_eq!(body["records"], json!([txt_encode("wildcard-value")]));
}

#[test]
fn marker_pagination_discovers_longest_zone_and_fully_reads_the_rrset() {
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    http(op.advance(ProviderEvent::Start).unwrap(), "GET");
    let next = "https://dns.cn-north-4.myhuaweicloud.com/v2/zones?marker=first";
    let page = http(
        reply(
            op.as_mut(),
            200,
            json!({"zones":[{"id":"parent", "name":"net."}], "links":{"next":next}}),
        )
        .unwrap(),
        "GET",
    );
    assert!(page.url.contains("marker=first"));
    let saved = checkpoint(
        reply(op.as_mut(), 200, json!({"zones":[zone()]})).unwrap(),
        "zone_resolved",
    );
    assert_eq!(saved.data["zone_id"], "zone-child");
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    let next =
        "https://dns.cn-north-4.myhuaweicloud.com/v2/zones/zone-child/recordsets?marker=second";
    let page = http(
        reply(
            op.as_mut(),
            200,
            json!({"recordsets":[], "links":{"next":next}}),
        )
        .unwrap(),
        "GET",
    );
    assert!(page.url.contains("marker=second"));
    let state = checkpoint(
        reply(
            op.as_mut(),
            200,
            listing(vec![row(&["user"], "description")]),
        )
        .unwrap(),
        "present_intent",
    );
    assert_eq!(state.data["recordset_id"], "recordset-1");
}

#[test]
fn invalid_saved_scopes_pagination_duplicates_and_unrecognized_errors_fail_closed() {
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    let state = initial(op.as_mut());
    for (field, value) in [
        ("zone_id", json!("../invalid")),
        ("zone_name", json!("other.net.")),
        ("phase", json!("future")),
    ] {
        let mut changed = state.clone();
        changed.data[field] = value;
        assert!(
            factory()
                .start(ProviderAction::Present(record()), Some(changed))
                .is_err()
        );
    }
    for next in [
        "https://evil.example/?marker=one",
        "https://dns.cn-north-4.myhuaweicloud.com/v2/zones",
        "not a URL",
    ] {
        let mut op = factory()
            .start(ProviderAction::Present(record()), None)
            .unwrap();
        http(op.advance(ProviderEvent::Start).unwrap(), "GET");
        assert!(
            reply(
                op.as_mut(),
                200,
                json!({"zones":[zone()], "links":{"next":next}})
            )
            .is_err()
        );
    }
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(op.as_mut());
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    assert!(
        reply(
            op.as_mut(),
            200,
            listing(vec![row(&["user"], ""), row(&["user"], "")])
        )
        .is_err()
    );
}

#[test]
fn structured_conflicts_are_checkpointed_and_reread_with_a_four_write_limit() {
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(op.as_mut());
    for attempt in 0..4 {
        intent(op.as_mut(), vec![]);
        http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "POST");
        checkpoint(
            reply(
                op.as_mut(),
                409,
                json!({"code":"DNS.0312", "message":"SecretKey"}),
            )
            .unwrap(),
            "rejected",
        );
        if attempt == 3 {
            let error = op.advance(ProviderEvent::CheckpointSaved).err().unwrap();
            assert_eq!(error.code, ProviderErrorCode::RecordConflict);
            assert_eq!(error.side_effect, SideEffect::None);
            assert!(!format!("{error:?}").contains("SecretKey"));
        }
    }
}

#[test]
fn rate_limit_floor_is_retained_and_malformed_write_response_never_fabricates_an_id() {
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(op.as_mut());
    intent(op.as_mut(), vec![]);
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "POST");
    let response = HttpResponse {
        status: 429,
        headers: vec![("retry-after".into(), b"83".to_vec())],
        body: serde_json::to_vec(&json!({"error_code":"APIG.0308", "error_msg":"SecretKey"}))
            .unwrap(),
    };
    checkpoint(
        op.advance(ProviderEvent::Http(Ok(response))).unwrap(),
        "rejected",
    );
    let error = op.advance(ProviderEvent::CheckpointSaved).err().unwrap();
    assert_eq!(error.code, ProviderErrorCode::RateLimited);
    assert_eq!(error.retry_after_seconds, Some(83));
    assert!(!format!("{error:?}").contains("SecretKey"));
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(op.as_mut());
    intent(op.as_mut(), vec![]);
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "POST");
    let error = reply(op.as_mut(), 200, json!({})).err().unwrap();
    assert_eq!(error.side_effect, SideEffect::Unknown);
}

#[test]
fn pending_rrset_is_polled_without_claiming_success_or_sending_writes() {
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(op.as_mut());
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    let mut pending = row(&["user"], "");
    pending["status"] = json!("PENDING_UPDATE");
    for _ in 0..8 {
        assert!(matches!(
            reply(op.as_mut(), 200, listing(vec![pending.clone()])).unwrap(),
            ProviderEffect::WaitUntil(_)
        ));
        http(op.advance(ProviderEvent::Timer).unwrap(), "GET");
    }
    assert_eq!(
        reply(op.as_mut(), 200, listing(vec![pending]))
            .err()
            .unwrap()
            .code,
        ProviderErrorCode::ProviderUnavailable
    );
}

#[test]
fn stale_read_cannot_protect_an_external_write_and_the_backend_does_not_send_fake_cas() {
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(op.as_mut());
    intent(op.as_mut(), vec![row(&["operator-before-read"], "")]);
    // The cloud can receive another client's change after our last observation.
    let concurrent = row(&["operator-before-read", "external-after-read"], "");
    assert!(
        concurrent["records"]
            .as_array()
            .unwrap()
            .contains(&json!(txt_encode("external-after-read")))
    );
    let put = http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "PUT");
    let payload: Value = serde_json::from_slice(&put.body).unwrap();
    assert!(
        !payload["records"]
            .as_array()
            .unwrap()
            .contains(&json!(txt_encode("external-after-read")))
    );
    assert!(
        !put.headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("if-match"))
    );
    assert!(payload.get("revision").is_none());
    // This is the concrete lost-update window documented for best_effort_rrsets.
}

#[test]
fn two_real_length_publication_markers_fit_but_a_third_refuses_to_truncate_description() {
    let first = marker(&"a".repeat(43), "root-value");
    let second = marker(&"b".repeat(43), "wildcard-value");
    let two = add_marker(&first, &second).unwrap();
    assert!(two.len() <= 255);
    let third = marker(&"c".repeat(43), "other-value");
    assert!(add_marker(&two, &third).is_err());
}

#[test]
fn successful_write_is_not_a_receipt_until_active_remote_readback_matches() {
    let mut op = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(op.as_mut());
    intent(op.as_mut(), vec![]);
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "POST");
    let mut pending = row(&["our-value"], &marker("publication-1", "our-value"));
    pending["status"] = json!("PENDING_CREATE");
    checkpoint(
        reply(op.as_mut(), 202, pending.clone()).unwrap(),
        "present_intent",
    );
    http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
    assert!(matches!(
        reply(op.as_mut(), 200, listing(vec![pending])).unwrap(),
        ProviderEffect::WaitUntil(_)
    ));
    http(op.advance(ProviderEvent::Timer).unwrap(), "GET");
    checkpoint(
        reply(
            op.as_mut(),
            200,
            listing(vec![row(
                &["our-value"],
                &marker("publication-1", "our-value"),
            )]),
        )
        .unwrap(),
        "presented",
    );
    assert_eq!(receipt(op.as_mut()).effective_ttl_seconds, Some(300));
}

#[test]
fn unknown_or_truncated_publication_markers_never_authorize_borrowing() {
    for description in ["asteracme:another", "asteracme:another=truncated"] {
        let mut op = factory()
            .start(ProviderAction::Present(record()), None)
            .unwrap();
        initial(op.as_mut());
        http(op.advance(ProviderEvent::CheckpointSaved).unwrap(), "GET");
        let failure = reply(
            op.as_mut(),
            200,
            listing(vec![row(&["our-value"], description)]),
        )
        .err()
        .unwrap();
        assert_eq!(failure.code, ProviderErrorCode::RecordConflict);
    }
}
