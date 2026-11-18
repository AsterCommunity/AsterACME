use crate::provider::{
    aliyun::{Keys, payload},
    individual::{IndividualApi, IndividualFactory},
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
        access_key_id: "AKID-example".into(),
        access_key_secret: "dummysecret".into(),
    }
}

fn factory() -> IndividualFactory<Keys> {
    IndividualFactory(Arc::new(keys()))
}

#[test]
fn aliyun_marker_override_stays_within_the_fifty_character_limit() {
    let marker = keys().marker(&"a".repeat(43));
    assert_eq!(marker, format!("acme-{}", "a".repeat(43)));
    assert_eq!(marker.len(), 48);
}

fn zone(id: &str, name: &str) -> Value {
    json!({"DomainId":id, "DomainName":name, "MinTtl":300})
}

fn page(page: u32, total: u32, collection: &str, key: &str, entries: Vec<Value>) -> Value {
    json!({"PageNumber":page,"PageSize":100,"TotalCount":total,(collection):{(key):Value::Array(entries)}})
}

fn list(entries: Vec<Value>) -> Value {
    page(
        1,
        u32::try_from(entries.len()).unwrap(),
        "DomainRecords",
        "Record",
        entries,
    )
}

fn row(id: &str, value: &str) -> Value {
    json!({"RecordId":id,"DomainId":"child-id","DomainName":"child.validation.net",
           "RR":"target","Type":"TXT","Value":value,"TTL":300,"Status":"Enable","Line":"default"})
}

fn owned_row(id: &str, value: &str) -> Value {
    let mut row = row(id, value);
    row["Remark"] = json!("asteracme:publication-1");
    row
}

fn initial(machine: &mut dyn ProviderOperation) -> RecoveryState {
    let request = http(
        machine.advance(ProviderEvent::Start).unwrap(),
        "x-acs-action",
        "DescribeDomains",
        false,
    );
    assert!(request.url.ends_with("?PageNumber=1&PageSize=100"));
    let mut zones = vec![
        zone("parent-id", "validation.net"),
        zone("near-miss", "ild.validation.net"),
    ];
    zones.extend((2..100).map(|i| zone(&format!("unused-{i}"), &format!("zone{i}.example.com"))));
    let request = http(
        reply(machine, &page(1, 101, "Domains", "Domain", zones)).unwrap(),
        "x-acs-action",
        "DescribeDomains",
        false,
    );
    assert!(request.url.ends_with("?PageNumber=2&PageSize=100"));
    let cp = saved(
        reply(
            machine,
            &page(
                2,
                101,
                "Domains",
                "Domain",
                vec![zone("child-id", "CHILD.validation.net.")],
            ),
        )
        .unwrap(),
        "resolved",
    );
    assert_eq!(cp.data["zone"]["id"], "child-id");
    cp
}

fn read_zone(machine: &mut dyn ProviderOperation, event: ProviderEvent, next: &str) {
    let request = http(
        machine.advance(event).unwrap(),
        "x-acs-action",
        "DescribeDomainInfo",
        false,
    );
    assert!(
        request
            .url
            .ends_with("?DomainName=child.validation.net&NeedDetailAttributes=true")
    );
    http(
        reply(machine, &zone("child-id", "child.validation.net")).unwrap(),
        "x-acs-action",
        next,
        false,
    );
}

fn intent(machine: &mut dyn ProviderOperation) -> RecoveryState {
    initial(machine);
    read_zone(
        machine,
        ProviderEvent::CheckpointSaved,
        "DescribeDomainRecords",
    );
    let cp = saved(
        reply(machine, &list(vec![row("51", "operator-value")])).unwrap(),
        "create_intent",
    );
    let request = http(
        machine.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "x-acs-action",
        "AddDomainRecord",
        true,
    );
    assert_eq!(request.method.as_str(), "GET");
    assert_eq!(request.body, [] as [u8; 0]);
    assert!(request.url.ends_with("DomainName=child.validation.net&Line=default&RR=target&TTL=300&Type=TXT&Value=challenge-value"));
    cp
}

fn mark_created(machine: &mut dyn ProviderOperation) -> RecoveryState {
    let remark_intent = saved(
        reply(machine, &json!({"RecordId":"64"})).unwrap(),
        "remark_intent",
    );
    assert_eq!(remark_intent.data["phase"]["id"], "64");
    let request = http(
        machine.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "x-acs-action",
        "UpdateDomainRecordRemark",
        true,
    );
    assert!(
        request
            .url
            .ends_with("?RecordId=64&Remark=acme-publication-1")
    );
    saved(
        reply(machine, &json!({"RequestId":"remark-request"})).unwrap(),
        "marked",
    )
}

#[test]
fn acs3_signs_exact_rfc3986_query_and_empty_wire_body() {
    // Independent Python hashlib/hmac + urllib reference based on the ACS3 canonical request.
    let request = keys().signed(
        crate::provider::aliyun::AliyunAction::AddDomainRecord,
        &[
            ("Value", "\"é +/=%~\""),
            ("RR", "_acme-challenge"),
            ("DomainName", "example.com"),
        ],
        "2023-10-26T10:22:32Z",
        "3156853299f313e23d1673dc12e1703d",
        true,
    );
    assert_eq!(
        request.url,
        "https://alidns.aliyuncs.com/?DomainName=example.com&RR=_acme-challenge&Value=%22%C3%A9%20%2B%2F%3D%25~%22"
    );
    assert_eq!(
        request.headers.last().unwrap().1,
        "ACS3-HMAC-SHA256 Credential=AKID-example,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version,Signature=56877d35ce2921e301e4ff9d9e982c6698a85bef565b668e342765f943c72f09"
    );
}

#[test]
fn returned_id_survives_restart_and_requires_exact_remote_identity_before_delete() {
    let factory = factory();
    let mut present = factory
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    intent(present.as_mut());
    let marked = mark_created(present.as_mut());
    let mut resumed = factory
        .start(ProviderAction::Present(record()), Some(marked.clone()))
        .unwrap();
    read_zone(
        resumed.as_mut(),
        ProviderEvent::Start,
        "DescribeDomainRecordInfo",
    );
    let receipt = receipt(reply(resumed.as_mut(), &owned_row("64", "challenge-value")).unwrap());
    assert_eq!(receipt.effective_ttl_seconds, Some(300));
    assert_eq!(receipt.ownership, RecordOwnership::Created);
    assert!(
        factory
            .start(ProviderAction::Cleanup(cleanup(receipt.clone())), None)
            .is_err()
    );
    for (field, value) in [
        ("Value", json!("user-edit")),
        ("RR", json!("other")),
        ("Type", json!("CAA")),
        ("RecordId", json!("65")),
        ("Line", json!("other")),
    ] {
        let mut op = factory
            .start(
                ProviderAction::Cleanup(cleanup(receipt.clone())),
                Some(marked.clone()),
            )
            .unwrap();
        read_zone(
            op.as_mut(),
            ProviderEvent::Start,
            "DescribeDomainRecordInfo",
        );
        let mut edited = owned_row("64", "challenge-value");
        edited[field] = value;
        assert_eq!(
            fail(reply(op.as_mut(), &edited)).code,
            ProviderErrorCode::RecordNotOwned
        );
    }
    let mut op = factory
        .start(
            ProviderAction::Cleanup(cleanup(receipt.clone())),
            Some(marked),
        )
        .unwrap();
    read_zone(
        op.as_mut(),
        ProviderEvent::Start,
        "DescribeDomainRecordInfo",
    );
    let deleting = saved(
        reply(op.as_mut(), &owned_row("64", "challenge-value")).unwrap(),
        "delete_intent",
    );
    let request = http(
        op.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "x-acs-action",
        "DeleteDomainRecord",
        true,
    );
    assert!(request.url.ends_with("?RecordId=64"));
    assert!(matches!(
        reply(op.as_mut(), &json!({"RecordId":"64"})).unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Removed))
    ));
    let mut op = factory
        .start(ProviderAction::Cleanup(cleanup(receipt)), Some(deleting))
        .unwrap();
    read_zone(
        op.as_mut(),
        ProviderEvent::Start,
        "DescribeDomainRecordInfo",
    );
    assert!(matches!(
        op.advance(ProviderEvent::Http(Ok(response(
            400,
            &json!({"Code":"InvalidRecordId.NotFound"})
        ))))
        .unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::AlreadyAbsent))
    ));
}

#[test]
fn remark_failure_retries_the_update_without_repeating_record_creation() {
    let factory = factory();
    let mut present = factory
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    intent(present.as_mut());
    let remark_intent = saved(
        reply(present.as_mut(), &json!({"RecordId":"64"})).unwrap(),
        "remark_intent",
    );
    let request = http(
        present.advance(ProviderEvent::CheckpointSaved).unwrap(),
        "x-acs-action",
        "UpdateDomainRecordRemark",
        true,
    );
    assert!(request.url.contains("RecordId=64"));
    let error = fail(present.advance(ProviderEvent::Http(Err(HttpFailure {
        code: ProviderErrorCode::ProviderTimeout,
        side_effect: SideEffect::Unknown,
    }))));
    assert_eq!(error.side_effect, SideEffect::Unknown);

    let mut resumed = factory
        .start(ProviderAction::Present(record()), Some(remark_intent))
        .unwrap();
    let request = http(
        resumed.advance(ProviderEvent::Start).unwrap(),
        "x-acs-action",
        "UpdateDomainRecordRemark",
        true,
    );
    assert!(request.url.contains("RecordId=64"));
    let marked = saved(
        reply(resumed.as_mut(), &json!({"RequestId":"remark-request"})).unwrap(),
        "marked",
    );
    read_zone(
        resumed.as_mut(),
        ProviderEvent::CheckpointSaved,
        "DescribeDomainRecordInfo",
    );
    let receipt = receipt(reply(resumed.as_mut(), &owned_row("64", "challenge-value")).unwrap());
    assert_eq!(receipt.record_id, "64");
    assert_eq!(marked.data["phase"]["id"], "64");
}

#[test]
fn preexisting_snapshot_refuses_borrowing_and_lost_response_never_adopts_a_new_id() {
    let factory = factory();
    let mut preexisting = factory
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    initial(preexisting.as_mut());
    read_zone(
        preexisting.as_mut(),
        ProviderEvent::CheckpointSaved,
        "DescribeDomainRecords",
    );
    let cp = saved(
        reply(
            preexisting.as_mut(),
            &list(vec![row("52", "challenge-value")]),
        )
        .unwrap(),
        "preexisting",
    );
    assert_eq!(cp.data["phase"]["ids"], json!(["52"]));
    assert_eq!(
        fail(preexisting.advance(ProviderEvent::CheckpointSaved)).code,
        ProviderErrorCode::RecordConflict
    );

    let mut first = factory
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    let cp = intent(first.as_mut());
    assert_eq!(
        fail(first.advance(ProviderEvent::Http(Err(HttpFailure {
            code: ProviderErrorCode::ProviderTimeout,
            side_effect: SideEffect::Unknown,
        }))))
        .side_effect,
        SideEffect::Unknown
    );
    for records in [vec![], vec![row("64", "challenge-value")]] {
        let mut restarted = factory
            .start(ProviderAction::Present(record()), Some(cp.clone()))
            .unwrap();
        read_zone(
            restarted.as_mut(),
            ProviderEvent::Start,
            "DescribeDomainRecords",
        );
        let failure = fail(reply(restarted.as_mut(), &list(records)));
        assert_eq!(failure.code, ProviderErrorCode::RecordNotOwned);
        assert_eq!(failure.side_effect, SideEffect::Unknown);
    }
}

#[test]
fn structured_throttle_saves_rejection_before_retry_and_never_echoes_raw_data() {
    let factory = factory();
    let mut op = factory
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    intent(op.as_mut());
    let mut failure = response(
        429,
        &json!({"Code":"Throttling.User","Message":"dummysecret","RequestId":"dummysecret"}),
    );
    failure.headers = vec![("retry-after".into(), b"73".to_vec())];
    let rejected = saved(
        op.advance(ProviderEvent::Http(Ok(failure))).unwrap(),
        "rejected",
    );
    let failure = fail(op.advance(ProviderEvent::CheckpointSaved));
    assert_eq!(failure.code, ProviderErrorCode::RateLimited);
    assert_eq!(failure.retry_after_seconds, Some(73));
    assert_eq!(failure.side_effect, SideEffect::None);
    assert!(!format!("{failure:?}").contains("dummysecret"));
    let mut restart = factory
        .start(ProviderAction::Present(record()), Some(rejected))
        .unwrap();
    read_zone(
        restart.as_mut(),
        ProviderEvent::Start,
        "DescribeDomainRecords",
    );
    saved(
        reply(restart.as_mut(), &list(vec![])).unwrap(),
        "create_intent",
    );

    for (status, body) in [
        (502, json!({"Code":"Throttling"})),
        (400, json!({"Code":"dummysecret"})),
        (408, json!({"Code":"Throttling"})),
    ] {
        let error = payload(&response(status, &body), true).unwrap_err();
        assert_eq!(error.side_effect, SideEffect::Unknown);
        assert!(!format!("{error:?}").contains("dummysecret"));
    }
}

#[test]
fn rejects_wrong_zone_before_using_a_saved_ali_dns_name() {
    let factory = factory();
    let mut op = factory
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    let resolved = initial(op.as_mut());
    let mut reopened = factory
        .start(ProviderAction::Present(record()), Some(resolved))
        .unwrap();
    http(
        reopened.advance(ProviderEvent::Start).unwrap(),
        "x-acs-action",
        "DescribeDomainInfo",
        false,
    );
    assert_eq!(
        fail(reply(
            reopened.as_mut(),
            &zone("replacement", "child.validation.net")
        ))
        .side_effect,
        SideEffect::None
    );
}

#[test]
fn detailed_domain_info_requires_a_valid_ttl_before_any_write() {
    use crate::provider::individual::{IndividualApi, Zone};
    let api = keys();
    let expected = Zone::new("child-id".into(), "child.validation.net").unwrap();
    for ttl in [1, 300, 86400] {
        let mut body = zone("child-id", "child.validation.net");
        body["MinTtl"] = json!(ttl);
        assert_eq!(
            api.checked_zone(response(200, &body), &expected).unwrap(),
            ttl
        );
    }
    for ttl in [
        json!(null),
        json!(0),
        json!(86401),
        json!(-1),
        json!("300"),
        json!(4_294_967_296_u64),
    ] {
        let mut body = zone("child-id", "child.validation.net");
        body["MinTtl"] = ttl;
        assert!(api.checked_zone(response(200, &body), &expected).is_err());
    }
    let mut body = zone("child-id", "child.validation.net");
    body.as_object_mut().unwrap().remove("MinTtl");
    assert!(api.checked_zone(response(200, &body), &expected).is_err());
}

#[test]
fn documented_record_statuses_and_unknown_values_control_readback_readiness() {
    use crate::provider::individual::{IndividualApi, Zone};
    let api = keys();
    let expected = Zone::new("child-id".into(), "child.validation.net").unwrap();
    for (status, enabled) in [
        ("Enable", true),
        ("ENABLE", true),
        ("Disable", false),
        ("DISABLE", false),
        ("future-status", false),
    ] {
        let mut body = row("64", "challenge-value");
        body["Status"] = json!(status);
        let record = api
            .inspected(response(200, &body), &expected)
            .unwrap()
            .unwrap();
        assert_eq!(record.enabled, enabled, "{status}");
    }
}

#[test]
fn live_record_info_without_domain_id_keeps_domain_and_record_identity_checks() {
    use crate::provider::individual::{IndividualApi, Zone};
    let api = keys();
    let expected = Zone::new("child-id".into(), "child.validation.net").unwrap();
    let mut body = row("64", "challenge-value");
    body.as_object_mut().unwrap().remove("DomainId");
    body["Status"] = json!("ENABLE");
    let record = api
        .inspected(response(200, &body), &expected)
        .unwrap()
        .unwrap();
    assert_eq!(record.id, "64");
    assert!(record.enabled);
    for (field, value) in [
        ("DomainId", json!("other-zone")),
        ("DomainId", json!(42)),
        ("DomainName", json!("other.example")),
    ] {
        let mut changed = body.clone();
        changed[field] = value;
        assert!(api.inspected(response(200, &changed), &expected).is_err());
    }
}

#[test]
fn saved_record_id_retries_only_readback_and_recovers_after_visibility_delay() {
    let factory = factory();
    let mut created = initial(
        factory
            .start(ProviderAction::Present(record()), None)
            .unwrap()
            .as_mut(),
    );
    created.data["phase"] = json!({"state":"created","id":"64"});
    let mut op = factory
        .start(ProviderAction::Present(record()), Some(created))
        .unwrap();
    read_zone(
        op.as_mut(),
        ProviderEvent::Start,
        "DescribeDomainRecordInfo",
    );
    let absent = response(400, &json!({"Code":"InvalidRR.NoExist"}));
    assert!(matches!(
        op.advance(ProviderEvent::Http(Ok(absent))).unwrap(),
        ProviderEffect::WaitUntil(_)
    ));
    let request = http(
        op.advance(ProviderEvent::Timer).unwrap(),
        "x-acs-action",
        "DescribeDomainRecordInfo",
        false,
    );
    assert!(request.url.ends_with("?RecordId=64"));
    let receipt = receipt(reply(op.as_mut(), &row("64", "challenge-value")).unwrap());
    assert_eq!(receipt.record_id, "64");
}

#[test]
fn missing_saved_record_exhausts_read_budget_without_creating_again() {
    let factory = factory();
    let mut created = initial(
        factory
            .start(ProviderAction::Present(record()), None)
            .unwrap()
            .as_mut(),
    );
    created.data["phase"] = json!({"state":"created","id":"64"});
    let mut op = factory
        .start(ProviderAction::Present(record()), Some(created))
        .unwrap();
    read_zone(
        op.as_mut(),
        ProviderEvent::Start,
        "DescribeDomainRecordInfo",
    );
    for _ in 0..6 {
        let absent = response(400, &json!({"Code":"InvalidRecordId.NotFound"}));
        assert!(matches!(
            op.advance(ProviderEvent::Http(Ok(absent))).unwrap(),
            ProviderEffect::WaitUntil(_)
        ));
        http(
            op.advance(ProviderEvent::Timer).unwrap(),
            "x-acs-action",
            "DescribeDomainRecordInfo",
            false,
        );
    }
    let absent = response(400, &json!({"Code":"InvalidRecordId.NotFound"}));
    let error = fail(op.advance(ProviderEvent::Http(Ok(absent))));
    assert_eq!(error.code, ProviderErrorCode::RecordNotOwned);
    assert_eq!(error.side_effect, SideEffect::Unknown);
}
