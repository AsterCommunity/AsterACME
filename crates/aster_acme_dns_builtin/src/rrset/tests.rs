use crate::rrset::{ConditionalRrsetFactory, ConditionalWrite, RrsetProtocol, RrsetSnapshot};
use aster_acme_dns::{
    CleanupRequest, CleanupStatus, DnsRecord, ProviderError, ProviderErrorCode, RecordOwnership,
    SideEffect,
    operation::{
        HttpFailure, HttpRequest, HttpResponse, OperationFactory, ProviderAction, ProviderEffect,
        ProviderEvent, ProviderOperation, ProviderOutcome, RecoveryState,
    },
};
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};
struct Protocol;
impl RrsetProtocol for Protocol {
    fn read(&self, _: &DnsRecord) -> Result<HttpRequest, ProviderError> {
        Ok(HttpRequest {
            method: "GET".into(),
            url: "https://dns.example/rrset".into(),
            headers: vec![],
            body: vec![],
            mutation: false,
        })
    }
    fn parse_read(&self, response: HttpResponse) -> Result<RrsetSnapshot, ProviderError> {
        Ok(serde_json::from_slice(&response.body).unwrap())
    }
    fn write(
        &self,
        _: &DnsRecord,
        snapshot: &RrsetSnapshot,
        values: &BTreeSet<String>,
    ) -> Result<HttpRequest, ProviderError> {
        Ok(HttpRequest {
            method: "PUT".into(),
            url: "https://dns.example/rrset".into(),
            headers: vec![("If-Match".into(), snapshot.revision.clone())],
            body: serde_json::to_vec(&json!({"values":values,"metadata":snapshot.metadata}))
                .unwrap(),
            mutation: true,
        })
    }
    fn parse_write(&self, response: HttpResponse) -> Result<ConditionalWrite, ProviderError> {
        Ok(if response.status == 412 {
            ConditionalWrite::Conflict
        } else {
            ConditionalWrite::Applied
        })
    }
}
fn record() -> DnsRecord {
    DnsRecord {
        publication_id: "pub-1".into(),
        challenge_name: "_acme-challenge.example.com.".into(),
        cname_chain: vec!["_acme-challenge.example.com.".into()],
        name: "_acme-challenge.example.com.".into(),
        value: "our-value".into(),
        ttl_seconds: Some(120),
    }
}
fn response(values: &[&str], revision: &str) -> ProviderEvent {
    ProviderEvent::Http(Ok(HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&RrsetSnapshot {
            values: values.iter().map(|s| (*s).into()).collect(),
            revision: revision.into(),
            metadata: json!({"ttl":300,"unknown":{"keep":true}}),
        })
        .unwrap(),
    }))
}
fn ack() -> ProviderEvent {
    ProviderEvent::Http(Ok(HttpResponse {
        status: 200,
        headers: vec![],
        body: vec![],
    }))
}
fn factory() -> ConditionalRrsetFactory {
    ConditionalRrsetFactory::new(Arc::new(Protocol))
}
fn checkpoint(effect: ProviderEffect) -> RecoveryState {
    let ProviderEffect::Checkpoint(state) = effect else {
        panic!()
    };
    state
}
fn write(machine: &mut dyn ProviderOperation) -> HttpRequest {
    let ProviderEffect::Http(request) = machine.advance(ProviderEvent::CheckpointSaved).unwrap()
    else {
        panic!()
    };
    request
}
fn finish(machine: &mut dyn ProviderOperation) -> (RecoveryState, ProviderOutcome) {
    let saved = checkpoint(machine.advance(ack()).unwrap());
    let ProviderEffect::Complete(result) = machine.advance(ProviderEvent::CheckpointSaved).unwrap()
    else {
        panic!()
    };
    (saved, result)
}
#[test]
fn present_and_cleanup_preserve_current_values_and_unknown_metadata() {
    let mut machine = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    assert!(matches!(
        machine.advance(ProviderEvent::Start).unwrap(),
        ProviderEffect::Http(_)
    ));
    checkpoint(machine.advance(response(&["user-value"], "rev1")).unwrap());
    let request = write(machine.as_mut());
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["values"], json!(["our-value", "user-value"]));
    assert_eq!(body["metadata"]["ttl"], 300);
    assert_eq!(body["metadata"]["unknown"]["keep"], true);
    assert_eq!(request.headers[0].1, "rev1");
    let (saved, outcome) = finish(machine.as_mut());
    let ProviderOutcome::Presented(receipt) = outcome else {
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
    cleanup.advance(ProviderEvent::Start).unwrap();
    checkpoint(
        cleanup
            .advance(response(
                &["user-value", "our-value", "later-value"],
                "rev3",
            ))
            .unwrap(),
    );
    let request = write(cleanup.as_mut());
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["values"], json!(["later-value", "user-value"]));
    let (_, outcome) = finish(cleanup.as_mut());
    assert!(matches!(
        outcome,
        ProviderOutcome::Cleaned(CleanupStatus::Removed)
    ));
}
#[test]
fn conditional_conflicts_reread_and_remerge_instead_of_replaying_stale_payload() {
    let mut machine = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    machine.advance(ProviderEvent::Start).unwrap();
    checkpoint(machine.advance(response(&["user"], "rev1")).unwrap());
    write(machine.as_mut());
    assert!(matches!(
        machine
            .advance(ProviderEvent::Http(Ok(HttpResponse {
                status: 412,
                headers: vec![],
                body: vec![]
            })))
            .unwrap(),
        ProviderEffect::Http(_)
    ));
    checkpoint(
        machine
            .advance(response(&["user", "concurrent-value"], "rev2"))
            .unwrap(),
    );
    let request = write(machine.as_mut());
    assert_eq!(request.headers[0].1, "rev2");
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(
        body["values"],
        json!(["concurrent-value", "our-value", "user"])
    );
}
#[test]
fn lost_write_response_does_not_turn_observed_presence_into_ownership() {
    let mut machine = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    machine.advance(ProviderEvent::Start).unwrap();
    let saved = checkpoint(machine.advance(response(&["user"], "rev1")).unwrap());
    write(machine.as_mut());
    assert!(
        machine
            .advance(ProviderEvent::Http(Err(HttpFailure {
                code: ProviderErrorCode::ProviderTimeout,
                side_effect: SideEffect::Unknown
            })))
            .is_err()
    );
    let mut restored = factory()
        .start(ProviderAction::Present(record()), Some(saved))
        .unwrap();
    restored.advance(ProviderEvent::Start).unwrap();
    assert!(
        matches!(restored.advance(response(&["user","our-value"],"rev2")),Err(error) if error.code==ProviderErrorCode::RecordNotOwned)
    );
}
#[test]
fn preexisting_values_are_not_owned_and_missing_conditional_support_refuses_writes() {
    let mut machine = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    machine.advance(ProviderEvent::Start).unwrap();
    checkpoint(
        machine
            .advance(response(&["user", "our-value"], "rev1"))
            .unwrap(),
    );
    let ProviderEffect::Complete(ProviderOutcome::Presented(receipt)) =
        machine.advance(ProviderEvent::CheckpointSaved).unwrap()
    else {
        panic!()
    };
    assert_eq!(receipt.ownership, RecordOwnership::Preexisting);
    let mut machine = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    machine.advance(ProviderEvent::Start).unwrap();
    assert!(machine.advance(response(&["user"], "")).is_err());
}

#[test]
fn repeated_revision_conflicts_stop_with_no_unconditional_write_fallback() {
    let mut machine = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    machine.advance(ProviderEvent::Start).unwrap();
    for attempt in 0..4 {
        checkpoint(
            machine
                .advance(response(&["user"], &format!("revision-{attempt}")))
                .unwrap(),
        );
        let request = write(machine.as_mut());
        assert!(request.headers.iter().any(|(key, _)| key == "If-Match"));
        let outcome = machine.advance(ProviderEvent::Http(Ok(HttpResponse {
            status: 412,
            headers: vec![],
            body: vec![],
        })));
        if attempt == 3 {
            let saved = checkpoint(outcome.unwrap());
            assert!(matches!(
                machine.advance(ProviderEvent::CheckpointSaved),
                Err(error) if error.code == ProviderErrorCode::RecordConflict
                    && error.side_effect == SideEffect::None
            ));
            let mut retry = factory()
                .start(ProviderAction::Present(record()), Some(saved))
                .unwrap();
            assert!(matches!(
                retry.advance(ProviderEvent::Start).unwrap(),
                ProviderEffect::Http(_)
            ));
        } else {
            assert!(matches!(outcome, Ok(ProviderEffect::Http(_))));
        }
    }
}

#[test]
fn completed_cleanup_restore_never_deletes_a_later_recreated_rrset_value() {
    let publication = record();
    let receipt = aster_acme_dns::PublicationReceipt {
        effective_ttl_seconds: None,
        record_id: identity_for_test(&publication),
        ownership: RecordOwnership::Created,
        record_name: publication.name.clone(),
        cname_chain: publication.cname_chain.clone(),
    };
    let action = ProviderAction::Cleanup(CleanupRequest {
        publication_id: publication.publication_id.clone(),
        record: publication,
        receipt,
    });
    let mut cleanup = factory()
        .start(
            action.clone(),
            Some(RecoveryState {
                version: 1,
                data: json!({"phase":"presented","created":true}),
            }),
        )
        .unwrap();
    cleanup.advance(ProviderEvent::Start).unwrap();
    checkpoint(cleanup.advance(response(&["our-value"], "rev1")).unwrap());
    write(cleanup.as_mut());
    let cleaned = checkpoint(cleanup.advance(ack()).unwrap());
    assert!(matches!(
        cleanup.advance(ProviderEvent::CheckpointSaved).unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Removed))
    ));

    let mut restored = factory().start(action, Some(cleaned)).unwrap();
    assert!(matches!(
        restored.advance(ProviderEvent::Start).unwrap(),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(CleanupStatus::Removed))
    ));
}

fn identity_for_test(record: &DnsRecord) -> String {
    format!("rrset:{}", record.publication_id)
}

#[test]
fn created_cleanup_requires_saved_ownership_and_exact_receipt_identity() {
    let record = record();
    let receipt = aster_acme_dns::PublicationReceipt {
        effective_ttl_seconds: None,
        record_id: format!("rrset:{}", record.publication_id),
        ownership: RecordOwnership::Created,
        record_name: record.name.clone(),
        cname_chain: record.cname_chain.clone(),
    };
    let action = ProviderAction::Cleanup(CleanupRequest {
        publication_id: record.publication_id.clone(),
        record,
        receipt,
    });
    assert!(factory().start(action.clone(), None).is_err());
    assert!(
        factory()
            .start(
                action,
                Some(RecoveryState {
                    version: 2,
                    data: json!({})
                })
            )
            .is_err()
    );
}

#[test]
fn unknown_write_with_absent_value_still_requires_reconciliation_instead_of_replay() {
    let mut first = factory()
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    first.advance(ProviderEvent::Start).unwrap();
    let saved = checkpoint(first.advance(response(&["user"], "rev1")).unwrap());
    write(first.as_mut());
    let mut restored = factory()
        .start(ProviderAction::Present(record()), Some(saved))
        .unwrap();
    restored.advance(ProviderEvent::Start).unwrap();
    assert!(
        matches!(restored.advance(response(&["user"],"rev2")),Err(error) if error.code==ProviderErrorCode::RecordNotOwned)
    );
}
