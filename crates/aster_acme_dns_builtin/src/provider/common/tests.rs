use aster_acme_dns::{
    CleanupRequest, DnsRecord, ProviderError, PublicationReceipt,
    operation::{
        HttpRequest, HttpResponse, ProviderEffect, ProviderEvent, ProviderOperation,
        ProviderOutcome, RecoveryState,
    },
};
use serde_json::Value;

pub(in crate::provider) fn record() -> DnsRecord {
    DnsRecord {
        publication_id: "publication-1".into(),
        challenge_name: "_acme-challenge.example.com.".into(),
        cname_chain: vec![
            "_acme-challenge.example.com.".into(),
            "target.child.validation.net.".into(),
        ],
        name: "target.child.validation.net.".into(),
        value: "challenge-value".into(),
        ttl_seconds: Some(120),
    }
}

pub(in crate::provider) fn cleanup(receipt: PublicationReceipt) -> CleanupRequest {
    CleanupRequest {
        publication_id: record().publication_id,
        record: record(),
        receipt,
    }
}

pub(in crate::provider) fn response(status: u16, body: &Value) -> HttpResponse {
    HttpResponse {
        status,
        body: serde_json::to_vec(body).unwrap(),
        headers: vec![],
    }
}

pub(in crate::provider) fn reply(
    machine: &mut dyn ProviderOperation,
    body: &Value,
) -> Result<ProviderEffect, ProviderError> {
    machine.advance(ProviderEvent::Http(Ok(response(200, body))))
}

pub(in crate::provider) fn http(
    effect: ProviderEffect,
    action_header: &str,
    action: &str,
    mutation: bool,
) -> HttpRequest {
    let ProviderEffect::Http(request) = effect else {
        panic!("expected request for {action}");
    };
    assert_eq!(request.mutation, mutation, "{action}");
    assert!(
        request
            .headers
            .iter()
            .any(|(name, value)| name == action_header && value == action)
    );
    request
}

pub(in crate::provider) fn saved(effect: ProviderEffect, phase: &str) -> RecoveryState {
    let ProviderEffect::Checkpoint(state) = effect else {
        panic!("expected checkpoint for {phase}");
    };
    assert_eq!(state.version, 1);
    assert_eq!(state.data["phase"]["state"], phase);
    let wire = serde_json::to_vec(&state).unwrap();
    let loaded: RecoveryState = serde_json::from_slice(&wire).unwrap();
    assert_eq!(loaded, state);
    loaded
}

pub(in crate::provider) fn receipt(effect: ProviderEffect) -> PublicationReceipt {
    let ProviderEffect::Complete(ProviderOutcome::Presented(receipt)) = effect else {
        panic!("expected publication receipt");
    };
    receipt
}

pub(in crate::provider) fn fail(result: Result<ProviderEffect, ProviderError>) -> ProviderError {
    result.err().expect("expected typed provider failure")
}
