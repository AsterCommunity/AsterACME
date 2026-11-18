use crate::provider::{
    individual::IndividualFactory,
    tencent_cloud::{Keys, payload},
    tests::{cleanup, fail, http, receipt, record, reply, response, saved},
};
use aster_acme_dns::{
    CleanupStatus, ProviderErrorCode, RecordOwnership, SideEffect,
    operation::{
        HttpFailure, OperationFactory, ProviderAction, ProviderEffect, ProviderEvent,
        ProviderOperation, ProviderOutcome, RecoveryState,
    },
};
use serde_json::{Value, json};
use std::sync::Arc;

fn keys() -> Keys {
    Keys {
        secret_id: "AKID-example".into(),
        secret_key: "dummysecret".into(),
    }
}
fn factory() -> IndividualFactory<Keys> {
    IndividualFactory(Arc::new(keys()))
}

fn ok(mut value: Value) -> Value {
    value["RequestId"] = json!("request");
    json!({"Response":value})
}

fn row(id: u64, marker: Option<&str>) -> Value {
    json!({"RecordId":id,"Name":"target","Type":"TXT","Value":"challenge-value",
        "Remark":marker,"TTL":600,"Status":"ENABLE","LineId":"0"})
}

fn list(records: Vec<Value>) -> Value {
    ok(
        json!({"RecordCountInfo":{"TotalCount":records.len(),"ListCount":records.len()},"RecordList":Value::Array(records)}),
    )
}

fn inspected() -> Value {
    ok(
        json!({"RecordInfo":{"DomainId":42,"Id":123,"SubDomain":"target","RecordType":"TXT",
        "Value":"challenge-value","Remark":"asteracme:publication-1","TTL":600,"Enabled":1,"RecordLineId":"0"}}),
    )
}

fn resolved() -> RecoveryState {
    RecoveryState {
        version: 1,
        data: json!({"zone":{"id":"42","name":"child.validation.net."},"phase":{"state":"resolved"}}),
    }
}

fn start(machine: &mut dyn ProviderOperation) {
    let request = http(
        machine.advance(ProviderEvent::Start).unwrap(),
        "x-tc-action",
        "DescribeRecordList",
        false,
    );
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["DomainId"], 42);
    assert_eq!(body["SubDomain"], "target");
    assert_eq!(body["ErrorOnEmpty"], "no");
}

fn intent(machine: &mut dyn ProviderOperation) -> RecoveryState {
    start(machine);
    let cp = saved(reply(machine, &list(vec![])).unwrap(), "create_intent");
    let request = http(
        machine.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "x-tc-action",
        "CreateRecord",
        true,
    );
    assert_eq!(request.method, "POST");
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["Remark"], "asteracme:publication-1");
    assert_eq!(body["TTL"], 600);
    assert_eq!(body["RecordLineId"], "0");
    cp
}

#[test]
fn tc3_signs_the_exact_json_bytes_with_utc_date_scope() {
    // Independent Python hashlib/hmac reference, with non-ASCII and JSON escape bytes.
    let body = r#"{"Value":"前 +/=\"end"}"#.as_bytes();
    let authorization = keys()
        .authorization(
            "dnspod.tencentcloudapi.com",
            "dnspod",
            "CreateRecord",
            1_551_113_065,
            body,
        )
        .unwrap();
    assert_eq!(
        authorization,
        "TC3-HMAC-SHA256 Credential=AKID-example/2019-02-25/dnspod/tc3_request, SignedHeaders=content-type;host;x-tc-action, Signature=b18e43d156172ad009283b050d3fcca157142f57f74ce3fbf63cc353274138d6"
    );
    assert_ne!(
        authorization,
        keys()
            .authorization(
                "dnspod.tencentcloudapi.com",
                "dnspod",
                "CreateRecord",
                1_551_113_065,
                &[body, b"\n"].concat()
            )
            .unwrap()
    );
}

#[test]
fn paginated_discovery_prefers_longest_label_suffix_and_rejects_ambiguity_or_invalid_pages() {
    let factory = factory();
    let mut op = factory
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    let first = http(
        op.advance(ProviderEvent::Start).unwrap(),
        "x-tc-action",
        "DescribeDomainList",
        false,
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&first.body).unwrap()["Offset"],
        0
    );
    let mut first = vec![
        json!({"DomainId":11,"Name":"validation.net"}),
        json!({"DomainId":12,"Name":"ild.validation.net"}),
    ];
    first.extend((100..198).map(|id| json!({"DomainId":id,"Name":format!("zone{id}.net")})));
    let second = http(
        reply(
            op.as_mut(),
            &ok(json!({"DomainCountInfo":{"DomainTotal":101},"DomainList":first})),
        )
        .unwrap(),
        "x-tc-action",
        "DescribeDomainList",
        false,
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&second.body).unwrap()["Offset"],
        100
    );
    let cp = saved(reply(op.as_mut(), &ok(json!({"DomainCountInfo":{"DomainTotal":101},"DomainList":[{"DomainId":42,"Name":"CHILD.validation.net"}]}))).unwrap(), "resolved");
    assert_eq!(cp, resolved());

    for (total, zones, expected) in [
        (
            2,
            json!([{"DomainId":42,"Name":"child.validation.net"},{"DomainId":43,"Name":"child.validation.net"}]),
            ProviderErrorCode::ZoneAmbiguous,
        ),
        (
            1,
            json!([{"DomainId":52,"Name":"ild.validation.net"}]),
            ProviderErrorCode::ZoneNotFound,
        ),
        (1, json!([]), ProviderErrorCode::InternalError),
        (10_001, json!([]), ProviderErrorCode::InternalError),
    ] {
        let mut op = factory
            .start(ProviderAction::Present(record()), None)
            .unwrap();
        op.advance(ProviderEvent::Start).unwrap();
        assert_eq!(
            fail(reply(
                op.as_mut(),
                &ok(json!({"DomainCountInfo":{"DomainTotal":total},"DomainList":zones}))
            ))
            .code,
            expected
        );
    }
}

#[test]
fn matching_remark_recovers_lost_create_with_the_exact_id() {
    let factory = factory();
    let mut op = factory
        .start(ProviderAction::Present(record()), Some(resolved()))
        .unwrap();
    let cp = intent(op.as_mut());
    assert_eq!(
        fail(op.advance(ProviderEvent::Http(Err(HttpFailure {
            code: ProviderErrorCode::ProviderTimeout,
            side_effect: SideEffect::Unknown,
        }))))
        .side_effect,
        SideEffect::Unknown
    );
    for rows in [
        vec![],
        vec![row(123, None)],
        vec![row(123, Some("asteracme:other"))],
        vec![row(123, Some("asteracme:publication-1")), row(124, None)],
    ] {
        let mut op = factory
            .start(ProviderAction::Present(record()), Some(cp.clone()))
            .unwrap();
        start(op.as_mut());
        assert_eq!(
            fail(reply(op.as_mut(), &list(rows))).side_effect,
            SideEffect::Unknown
        );
    }
    let mut op = factory
        .start(ProviderAction::Present(record()), Some(cp))
        .unwrap();
    start(op.as_mut());
    let created = saved(
        reply(
            op.as_mut(),
            &list(vec![row(123, Some("asteracme:publication-1"))]),
        )
        .unwrap(),
        "created",
    );
    let inspect = http(
        op.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "x-tc-action",
        "DescribeRecord",
        false,
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&inspect.body).unwrap(),
        json!({"DomainId":42,"RecordId":123})
    );
    let receipt = receipt(reply(op.as_mut(), &inspected()).unwrap());
    assert_eq!(receipt.ownership, RecordOwnership::Created);
    assert_eq!(receipt.effective_ttl_seconds, Some(600));
    assert_eq!(created.data["phase"]["id"], "123");
}

#[test]
fn cleanup_rechecks_the_saved_id_and_publication_marker() {
    let factory = factory();
    let mut created = resolved();
    created.data["phase"] = json!({"state":"created","id":"123"});
    let mut op = factory
        .start(ProviderAction::Present(record()), Some(created.clone()))
        .unwrap();
    let inspect = http(
        op.advance(ProviderEvent::Start).unwrap(),
        "x-tc-action",
        "DescribeRecord",
        false,
    );
    let receipt = receipt(reply(op.as_mut(), &inspected()).unwrap());
    for (field, value) in [
        ("Remark", json!(null)),
        ("DomainId", json!(41)),
        ("Value", json!("edited")),
        ("RecordLineId", json!("1")),
    ] {
        let mut op = factory
            .start(
                ProviderAction::Cleanup(cleanup(receipt.clone())),
                Some(created.clone()),
            )
            .unwrap();
        http(
            op.advance(ProviderEvent::Start).unwrap(),
            "x-tc-action",
            "DescribeRecord",
            false,
        );
        let mut edited = inspected();
        edited["Response"]["RecordInfo"][field] = value;
        fail(reply(op.as_mut(), &edited));
    }
    let mut op = factory
        .start(
            ProviderAction::Cleanup(cleanup(receipt.clone())),
            Some(created.clone()),
        )
        .unwrap();
    http(
        op.advance(ProviderEvent::Start).unwrap(),
        "x-tc-action",
        "DescribeRecord",
        false,
    );
    let deleting = saved(reply(op.as_mut(), &inspected()).unwrap(), "delete_intent");
    let delete = http(
        op.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "x-tc-action",
        "DeleteRecord",
        true,
    );
    assert_eq!(delete.body, inspect.body);
    assert!(matches!(
        reply(op.as_mut(), &ok(json!({}))).unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Removed))
    ));
    let mut op = factory
        .start(ProviderAction::Cleanup(cleanup(receipt)), Some(deleting))
        .unwrap();
    op.advance(ProviderEvent::Start).unwrap();
    assert!(matches!(
        reply(
            op.as_mut(),
            &json!({"Response":{"Error":{"Code":"ResourceNotFound.NoDataOfRecord"}}})
        )
        .unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::AlreadyAbsent))
    ));
}

#[test]
fn unmarked_values_are_retained_and_other_publications_cannot_be_borrowed() {
    let factory = factory();
    let mut op = factory
        .start(ProviderAction::Present(record()), Some(resolved()))
        .unwrap();
    start(op.as_mut());
    let existing = saved(
        reply(op.as_mut(), &list(vec![row(13, Some("operator remark"))])).unwrap(),
        "preexisting",
    );
    let receipt = receipt(op.advance(ProviderEvent::CheckpointSaved).unwrap());
    assert_eq!(receipt.ownership, RecordOwnership::Preexisting);
    let mut cleanup = factory
        .start(ProviderAction::Cleanup(cleanup(receipt)), Some(existing))
        .unwrap();
    assert!(matches!(
        cleanup.advance(ProviderEvent::Start).unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Retained))
    ));

    for rows in [
        vec![row(123, Some("asteracme:another"))],
        vec![row(123, None), row(124, None)],
        vec![row(123, Some("asteracme:publication-1"))],
    ] {
        let mut op = factory
            .start(ProviderAction::Present(record()), Some(resolved()))
            .unwrap();
        start(op.as_mut());
        match reply(op.as_mut(), &list(rows)) {
            Ok(checkpoint) => {
                saved(checkpoint, "preexisting");
                assert_eq!(
                    fail(op.advance(ProviderEvent::CheckpointSaved)).code,
                    ProviderErrorCode::RecordConflict
                );
            }
            Err(failure) => assert_eq!(failure.code, ProviderErrorCode::RecordNotOwned),
        }
    }
}

#[test]
fn http_200_structured_throttling_is_durable_and_unrecognized_failures_are_uncertain() {
    let factory = factory();
    let mut op = factory
        .start(ProviderAction::Present(record()), Some(resolved()))
        .unwrap();
    intent(op.as_mut());
    let reply_body = json!({"Response":{"Error":{"Code":"RequestLimitExceeded.UinLimitExceeded","Message":"dummysecret"}}});
    let mut http_failure = response(200, &reply_body);
    http_failure.headers = vec![
        ("retry-after".into(), b"17".to_vec()),
        ("Retry-After".into(), b"79".to_vec()),
    ];
    let rejection = saved(
        op.advance(ProviderEvent::Http(Ok(http_failure))).unwrap(),
        "rejected",
    );
    let failure = fail(op.advance(ProviderEvent::CheckpointSaved));
    assert_eq!(failure.code, ProviderErrorCode::RateLimited);
    assert_eq!(failure.side_effect, SideEffect::None);
    assert_eq!(failure.retry_after_seconds, Some(79));
    assert!(!format!("{failure:?}").contains("dummysecret"));
    let mut op = factory
        .start(ProviderAction::Present(record()), Some(rejection))
        .unwrap();
    intent(op.as_mut());

    for (status, body) in [
        (500, reply_body),
        (200, json!(["dummysecret"])),
        (200, json!({"Response":{"Error":{"Code":"dummysecret"}}})),
        (404, json!({})),
    ] {
        let failure = payload(&response(status, &body), true).unwrap_err();
        assert_eq!(failure.side_effect, SideEffect::Unknown);
        assert!(!format!("{failure:?}").contains("dummysecret"));
    }
}
