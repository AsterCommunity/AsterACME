use crate::provider::common::individual::{
    api::{IndividualApi, Page, Record, RecordMarking, Zone},
    lifecycle::IndividualFactory,
};
use aster_acme_dns::{
    CleanupRequest, DnsRecord, ProviderError, PublicationReceipt, RecordOwnership, SideEffect,
    operation::{
        HttpRequest, HttpResponse, OperationFactory, ProviderAction, ProviderEffect, ProviderEvent,
        ProviderOperation, ProviderOutcome, RecoveryState,
    },
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const ZONE: &str = "child.example.test.";
struct FakeApi {
    remote: Mutex<Option<Value>>,
    pending_create: Mutex<Option<Value>>,
}

impl FakeApi {
    fn new() -> Self {
        Self {
            remote: Mutex::new(None),
            pending_create: Mutex::new(None),
        }
    }

    fn request(action: &str, mutation: bool) -> HttpRequest {
        HttpRequest {
            operation: None,
            method: aster_acme_dns::operation::HttpMethod::Get,
            url: format!("https://provider.test/{action}"),
            headers: vec![("x-test-action".into(), action.into())],
            body: Vec::new(),
            mutation,
        }
    }

    fn record(value: &Value) -> Record {
        Record {
            id: value["id"].as_str().unwrap_or_default().to_owned(),
            relative_name: value["relative"].as_str().unwrap_or_default().to_owned(),
            kind: value["kind"].as_str().unwrap_or_default().to_owned(),
            value: value["value"].as_str().unwrap_or_default().to_owned(),
            marker: value["marker"].as_str().map(str::to_owned),
            ttl: u32::try_from(value["ttl"].as_u64().unwrap_or_default()).unwrap_or_default(),
            enabled: value["enabled"].as_bool().unwrap_or_default(),
            default_line: value["default_line"].as_bool().unwrap_or_default(),
        }
    }

    fn response(body: &Value) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: body.to_string().into_bytes(),
        }
    }
}

impl IndividualApi for FakeApi {
    const MARKING: RecordMarking = RecordMarking::Inline;

    fn discover(&self, _: u32) -> Result<HttpRequest, ProviderError> {
        Ok(Self::request("discover", false))
    }

    fn zones(&self, _: HttpResponse, _: u32) -> Result<Page<Zone>, ProviderError> {
        Ok(Page {
            entries: vec![Zone::new("zone-1".into(), ZONE)?],
            total: 1,
        })
    }

    fn list(&self, _: &Zone, _: &str, _: u32) -> Result<HttpRequest, ProviderError> {
        Ok(Self::request("list", false))
    }

    fn records(&self, _: HttpResponse, _: &Zone, _: u32) -> Result<Page<Record>, ProviderError> {
        let entries = self
            .remote
            .lock()
            .unwrap()
            .clone()
            .map(|record| Self::record(&record))
            .into_iter()
            .collect::<Vec<_>>();
        let total = u32::try_from(entries.len()).map_err(|_| {
            aster_acme_dns::backend::configuration_error("fake record count overflow")
        })?;
        Ok(Page { entries, total })
    }

    fn inspect(&self, _: &Zone, _: &str) -> Result<HttpRequest, ProviderError> {
        Ok(Self::request("inspect", false))
    }

    fn inspected(&self, _: HttpResponse, _: &Zone) -> Result<Option<Record>, ProviderError> {
        Ok(self.remote.lock().unwrap().as_ref().map(Self::record))
    }

    fn create(
        &self,
        _: &Zone,
        relative: &str,
        record: &DnsRecord,
        marker: &str,
        _: u32,
    ) -> Result<HttpRequest, ProviderError> {
        *self.pending_create.lock().unwrap() = Some(json!({
            "id":"123", "relative":relative, "kind":"TXT", "value":record.value,
            "marker":marker, "ttl":300, "enabled":true, "default_line":true
        }));
        Ok(Self::request("create", true))
    }

    fn created(&self, _: HttpResponse) -> Result<String, ProviderError> {
        *self.remote.lock().unwrap() = self.pending_create.lock().unwrap().take();
        Ok("123".into())
    }

    fn delete(&self, _: &Zone, _: &str) -> Result<HttpRequest, ProviderError> {
        Ok(Self::request("delete", true))
    }

    fn deleted(
        &self,
        _: HttpResponse,
        _: &str,
    ) -> Result<aster_acme_dns::CleanupStatus, ProviderError> {
        *self.remote.lock().unwrap() = None;
        Ok(aster_acme_dns::CleanupStatus::Removed)
    }
}

fn record() -> DnsRecord {
    DnsRecord {
        publication_id: "publication-test".into(),
        challenge_name: "_acme-challenge.example.test.".into(),
        cname_chain: vec!["_acme-challenge.example.test.".into(), ZONE.into()],
        name: "_acme-challenge.child.example.test.".into(),
        value: "challenge-value".into(),
        ttl_seconds: Some(120),
    }
}

fn advance_http(
    operation: &mut dyn ProviderOperation,
    event: ProviderEvent,
    action: &str,
    mutation: bool,
) -> HttpRequest {
    let ProviderEffect::Http(request) = operation.advance(event).unwrap() else {
        panic!("expected {action} request")
    };
    assert_eq!(
        request.headers,
        vec![("x-test-action".into(), action.into())]
    );
    assert_eq!(request.mutation, mutation);
    request
}

fn checkpoint(effect: ProviderEffect, state: &str) -> RecoveryState {
    let ProviderEffect::Checkpoint(saved) = effect else {
        panic!("expected {state} checkpoint")
    };
    assert_eq!(saved.data["phase"]["state"], state);
    saved
}

fn respond(operation: &mut dyn ProviderOperation, body: impl Into<Value>) -> ProviderEffect {
    let body = body.into();
    operation
        .advance(ProviderEvent::Http(Ok(FakeApi::response(&body))))
        .unwrap()
}

#[test]
fn shared_lifecycle_checkpoints_create_inspects_and_cleans_exact_record() {
    let factory = IndividualFactory(Arc::new(FakeApi::new()));
    let publication = record();
    let mut present = factory
        .start(ProviderAction::Present(publication.clone()), None)
        .unwrap();
    advance_http(present.as_mut(), ProviderEvent::Start, "discover", false);
    let resolved = checkpoint(respond(present.as_mut(), json!({})), "resolved");
    assert_eq!(resolved.data["zone"]["id"], "zone-1");
    advance_http(
        present.as_mut(),
        ProviderEvent::CheckpointSaved,
        "list",
        false,
    );
    let create_intent = checkpoint(respond(present.as_mut(), json!({})), "create_intent");
    advance_http(
        present.as_mut(),
        ProviderEvent::CheckpointSaved,
        "create",
        true,
    );
    let created = checkpoint(respond(present.as_mut(), json!({})), "created");
    assert_eq!(created.data["phase"]["id"], "123");
    let mut present = factory
        .start(
            ProviderAction::Present(publication.clone()),
            Some(created.clone()),
        )
        .unwrap();
    advance_http(present.as_mut(), ProviderEvent::Start, "inspect", false);
    let ProviderEffect::Complete(ProviderOutcome::Presented(receipt)) =
        respond(present.as_mut(), json!({}))
    else {
        panic!("expected receipt after owned record readback")
    };
    assert_eq!(receipt.record_id, "123");
    assert_eq!(receipt.ownership, RecordOwnership::Created);

    let cleanup = CleanupRequest {
        publication_id: publication.publication_id.clone(),
        record: publication,
        receipt: PublicationReceipt {
            record_id: "123".into(),
            ownership: RecordOwnership::Created,
            record_name: "_acme-challenge.child.example.test.".into(),
            cname_chain: vec!["_acme-challenge.example.test.".into(), ZONE.into()],
            effective_ttl_seconds: Some(300),
        },
    };
    let mut cleanup_op = factory
        .start(ProviderAction::Cleanup(cleanup), Some(created))
        .unwrap();
    advance_http(cleanup_op.as_mut(), ProviderEvent::Start, "inspect", false);
    let delete_intent = checkpoint(respond(cleanup_op.as_mut(), json!({})), "delete_intent");
    advance_http(
        cleanup_op.as_mut(),
        ProviderEvent::CheckpointSaved,
        "delete",
        true,
    );
    assert!(matches!(
        respond(cleanup_op.as_mut(), json!({})),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(
            aster_acme_dns::CleanupStatus::Removed
        ))
    ));
    let mut restored_cleanup = factory
        .start(
            ProviderAction::Cleanup(CleanupRequest {
                publication_id: "publication-test".into(),
                record: record(),
                receipt: PublicationReceipt {
                    record_id: "123".into(),
                    ownership: RecordOwnership::Created,
                    record_name: "_acme-challenge.child.example.test.".into(),
                    cname_chain: vec!["_acme-challenge.example.test.".into(), ZONE.into()],
                    effective_ttl_seconds: Some(300),
                },
            }),
            Some(delete_intent),
        )
        .unwrap();
    advance_http(
        restored_cleanup.as_mut(),
        ProviderEvent::Start,
        "inspect",
        false,
    );
    assert!(matches!(
        respond(restored_cleanup.as_mut(), json!({})),
        ProviderEffect::Complete(ProviderOutcome::Cleaned(
            aster_acme_dns::CleanupStatus::AlreadyAbsent
        ))
    ));
    assert_eq!(create_intent.data["phase"]["state"], "create_intent");
}

#[test]
fn rejected_checkpoint_resumes_by_listing_before_any_second_create() {
    let factory = IndividualFactory(Arc::new(FakeApi::new()));
    let mut operation = factory
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    advance_http(operation.as_mut(), ProviderEvent::Start, "discover", false);
    checkpoint(respond(operation.as_mut(), json!({})), "resolved");
    advance_http(
        operation.as_mut(),
        ProviderEvent::CheckpointSaved,
        "list",
        false,
    );
    checkpoint(respond(operation.as_mut(), json!({})), "create_intent");
    advance_http(
        operation.as_mut(),
        ProviderEvent::CheckpointSaved,
        "create",
        true,
    );
    let rejected = checkpoint(
        operation
            .advance(ProviderEvent::Http(Err(
                aster_acme_dns::operation::HttpFailure {
                    code: aster_acme_dns::ProviderErrorCode::InvalidRequest,
                    side_effect: SideEffect::None,
                },
            )))
            .unwrap(),
        "rejected",
    );
    assert!(operation.advance(ProviderEvent::CheckpointSaved).is_err());
    let mut recovered = factory
        .start(ProviderAction::Present(record()), Some(rejected))
        .unwrap();
    advance_http(recovered.as_mut(), ProviderEvent::Start, "list", false);
    let intent = checkpoint(respond(recovered.as_mut(), json!({})), "create_intent");
    advance_http(
        recovered.as_mut(),
        ProviderEvent::CheckpointSaved,
        "create",
        true,
    );
    assert_eq!(intent.data["phase"]["state"], "create_intent");
}

fn saved_phase(phase: impl Into<Value>) -> RecoveryState {
    let phase = phase.into();
    RecoveryState {
        version: 1,
        data: json!({"zone":{"id":"zone-1","name":ZONE},"phase":phase}),
    }
}

#[test]
fn invalid_recovery_and_receipts_are_rejected_before_effects() {
    let factory = IndividualFactory(Arc::new(FakeApi::new()));
    for phase in [
        json!({"state":"preexisting","ids":[]}),
        json!({"state":"preexisting","ids":["0"]}),
        json!({"state":"created","id":"0"}),
        json!({"state":"remark_intent","id":"123"}),
        json!({"state":"marked","id":"123"}),
        json!({"state":"delete_intent","id":"123"}),
    ] {
        assert!(
            factory
                .start(ProviderAction::Present(record()), Some(saved_phase(phase)))
                .is_err()
        );
    }
    for (field, value) in [
        ("id", "bad/id"),
        ("name", "other.example.test."),
        ("name", "CHILD.example.test."),
    ] {
        let mut saved = saved_phase(json!({"state":"resolved"}));
        saved.data["zone"][field] = json!(value);
        assert!(
            factory
                .start(ProviderAction::Present(record()), Some(saved))
                .is_err()
        );
    }
    for bad in ["", "bad id"] {
        let mut input = record();
        input.publication_id = bad.into();
        assert!(factory.start(ProviderAction::Present(input), None).is_err());
    }
    let mut op = factory
        .start(ProviderAction::Present(record()), None)
        .unwrap();
    assert!(op.advance(ProviderEvent::Timer).is_err());
    assert!(Zone::new("bad/id".into(), ZONE).is_err());
    assert_eq!(
        Zone::new("zone-1".into(), ZONE).unwrap().relative(ZONE),
        Some("@")
    );
}

#[test]
fn cleanup_retry_rereads_marker_and_never_deletes_changed_ownership() {
    let api = Arc::new(FakeApi::new());
    let factory = IndividualFactory(api.clone());
    let request = CleanupRequest {
        publication_id: record().publication_id,
        record: record(),
        receipt: PublicationReceipt {
            record_id: "123".into(),
            ownership: RecordOwnership::Created,
            record_name: record().name,
            cname_chain: record().cname_chain,
            effective_ttl_seconds: Some(300),
        },
    };
    for marker in [
        None,
        Some("operator note"),
        Some("asteracme-another-publication"),
    ] {
        *api.remote.lock().unwrap() = Some(json!({
            "id":"123", "relative":"_acme-challenge", "kind":"TXT", "value":"challenge-value",
            "marker":marker,"ttl":300,"enabled":true,"default_line":true
        }));
        let mut operation = factory
            .start(
                ProviderAction::Cleanup(request.clone()),
                Some(saved_phase(json!({"state":"delete_intent","id":"123"}))),
            )
            .unwrap();
        advance_http(operation.as_mut(), ProviderEvent::Start, "inspect", false);
        let failure = operation
            .advance(ProviderEvent::Http(Ok(FakeApi::response(&json!({})))))
            .err()
            .unwrap();
        assert_eq!(
            failure.code,
            aster_acme_dns::ProviderErrorCode::RecordNotOwned
        );
        assert!(api.remote.lock().unwrap().is_some());
    }
    let mut mismatched = request;
    mismatched.receipt.record_name = "other.example.test.".into();
    assert!(
        factory
            .start(
                ProviderAction::Cleanup(mismatched),
                Some(saved_phase(json!({"state":"created","id":"123"})))
            )
            .is_err()
    );
}
