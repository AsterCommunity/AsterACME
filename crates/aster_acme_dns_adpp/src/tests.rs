use crate::{
    MAX_RECORDS, PROTOCOL_ID, PROTOCOL_VERSION, request, sanitize_response, validate_request,
    validate_response,
    wire::{Action, RecordResult, Response, WireError},
};
use aster_acme_dns::{DnsRecord, ProviderContext, ProviderErrorCode, RecordOwnership, SideEffect};
use std::collections::BTreeMap;
fn context() -> ProviderContext {
    ProviderContext {
        provider_instance_id: "prod".into(),
        provider_profile_version: 1,
        provider_custom: BTreeMap::new(),
    }
}
fn record() -> DnsRecord {
    DnsRecord {
        publication_id: "pub-1".into(),
        challenge_name: "_acme-challenge.example.com.".into(),
        cname_chain: vec!["_acme-challenge.example.com.".into()],
        name: "_acme-challenge.example.com.".into(),
        value: "value".into(),
        ttl_seconds: Some(120),
    }
}
fn result() -> RecordResult {
    RecordResult {
        publication_id: "pub-1".into(),
        status: "present".into(),
        record_id: Some("id-1".into()),
        ownership: Some(RecordOwnership::Created),
        error: None,
    }
}
fn response() -> (crate::wire::Request, Response) {
    let request = request(Action::Present, &context(), &[record()], &[]).unwrap();
    let response = Response {
        provider_name: None,
        provider_version: None,
        protocol: PROTOCOL_ID.into(),
        version: PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        action: Action::Present,
        results: vec![result()],
        error: None,
    };
    (request, response)
}
fn error() -> WireError {
    WireError {
        code: ProviderErrorCode::RateLimited,
        message: "retry later".into(),
        side_effect: SideEffect::None,
        retry_after_seconds: Some(30),
        provider_code: None,
    }
}
#[test]
fn requests_reject_duplicates_counts_names_ttl_and_invalid_context() {
    assert!(request(Action::Present, &context(), &[], &[]).is_err());
    let over = vec![record(); MAX_RECORDS + 1];
    assert!(request(Action::Present, &context(), &over, &[]).is_err());
    for mutate in [0, 1, 2, 3, 4, 5] {
        let (mut request, _) = response();
        match mutate {
            0 => request.records.push(request.records[0].clone()),
            1 => request.context.provider_instance_id = "../escape".into(),
            2 => request.records[0].record.as_mut().unwrap().name = "bad..name.".into(),
            3 => request.records[0].record.as_mut().unwrap().ttl_seconds = Some(0),
            4 => request.records[0].record.as_mut().unwrap().value = "x".repeat(256),
            _ => request.context.provider_profile_version = 2,
        }
        assert!(validate_request(&request).is_err(), "case {mutate}");
    }
}
#[test]
fn maximum_record_batch_and_dns01_value_are_accepted_exactly() {
    let records = (0..MAX_RECORDS)
        .map(|index| {
            let mut record = record();
            record.publication_id = format!("pub-{index}");
            record.value = "x".repeat(255);
            record.ttl_seconds = Some(2_147_483_647);
            record
        })
        .collect::<Vec<_>>();
    let request = request(Action::Present, &context(), &records, &[]).unwrap();
    validate_request(&request).unwrap();
    let mut invalid = request;
    invalid.records[0].record.as_mut().unwrap().ttl_seconds = Some(2_147_483_648);
    assert!(validate_request(&invalid).is_err());
}

#[test]
fn response_correlations_and_exact_result_set_are_required() {
    let (request, response) = response();
    validate_response(&request, &response).unwrap();
    for mutate in 0..8 {
        let mut response = response.clone();
        match mutate {
            0 => response.protocol = "adpp".into(),
            1 => response.version += 1,
            2 => response.request_id = "different".into(),
            3 => response.action = Action::Cleanup,
            4 => response.results.clear(),
            5 => response.results.push(result()),
            6 => response.results[0].publication_id = "other".into(),
            _ => response.results[0].status = "unknown".into(),
        }
        assert!(
            validate_response(&request, &response).is_err(),
            "case {mutate}"
        );
    }
}
#[test]
fn receipt_id_exact_limits_and_ownership_are_validated() {
    let (request, mut response) = response();
    for size in [1, 1024] {
        response.results[0].record_id = Some("x".repeat(size));
        validate_response(&request, &response).unwrap();
    }
    for value in [String::new(), "x".repeat(1025), "bad\nrecord".into()] {
        response.results[0].record_id = Some(value);
        assert!(validate_response(&request, &response).is_err());
    }
    response.results[0] = result();
    response.results[0].ownership = None;
    assert!(validate_response(&request, &response).is_err());
    response.results[0].ownership = Some(RecordOwnership::Preexisting);
    validate_response(&request, &response).unwrap();
}
#[test]
fn partial_results_preserve_error_structure_and_forbid_contradictions() {
    let (mut request, mut response) = response();
    let mut second = request.records[0].clone();
    second.publication_id = "pub-2".into();
    request.records.push(second);
    response.results.push(RecordResult {
        publication_id: "pub-2".into(),
        status: "error".into(),
        record_id: None,
        ownership: None,
        error: Some(error()),
    });
    validate_response(&request, &response).unwrap();
    response.error = Some(error());
    assert!(validate_response(&request, &response).is_err());
    response.results.clear();
    validate_response(&request, &response).unwrap();
    response.error.as_mut().unwrap().side_effect = SideEffect::Unknown;
    assert!(validate_response(&request, &response).is_err());
}
#[test]
fn error_retry_hint_bounds_and_message_limits_are_exact() {
    let (request, mut response) = response();
    response.results.clear();
    response.error = Some(error());
    for hint in [1, 86400] {
        response.error.as_mut().unwrap().retry_after_seconds = Some(hint);
        validate_response(&request, &response).unwrap();
    }
    for hint in [0, 86401] {
        response.error.as_mut().unwrap().retry_after_seconds = Some(hint);
        assert!(validate_response(&request, &response).is_err());
    }
    response.error.as_mut().unwrap().retry_after_seconds = None;
    response.error.as_mut().unwrap().message = "x".repeat(2048);
    validate_response(&request, &response).unwrap();
    response.error.as_mut().unwrap().message.push('x');
    assert!(validate_response(&request, &response).is_err());
    response.error.as_mut().unwrap().message = "retry".into();
    response.error.as_mut().unwrap().code = ProviderErrorCode::AuthenticationFailed;
    response.error.as_mut().unwrap().retry_after_seconds = Some(30);
    assert!(validate_response(&request, &response).is_err());
}
#[test]
fn all_custom_nested_values_are_redacted_from_error_diagnostics() {
    let (_, mut response) = response();
    response.error = Some(error());
    response.results.clear();
    response.error.as_mut().unwrap().message = "secret-one secret-two 12345".into();
    let mut context = context();
    context.provider_custom.insert(
        "nested".into(),
        serde_json::json!({"token":"secret-one", "array":["secret-two", 12345]}),
    );
    sanitize_response(&mut response, &context);
    let output = format!("{response:?}");
    for value in ["secret-one", "secret-two", "12345"] {
        assert!(!output.contains(value));
    }
}

#[test]
fn missing_required_response_fields_unknown_error_codes_and_duplicate_keys_fail() {
    let (_, response) = response();
    let value = serde_json::to_value(&response).unwrap();
    for field in [
        "protocol",
        "version",
        "request_id",
        "action",
        "results",
        "error",
    ] {
        let mut broken = value.clone();
        broken.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<Response>(broken).is_err(),
            "{field}"
        );
    }
    let broken = r#"{"code":"unregistered_error","message":"error","side_effect":"none"}"#;
    assert!(serde_json::from_str::<WireError>(broken).is_err());
    let encoded = serde_json::to_string(&response)
        .unwrap()
        .replacen('{', "{\"version\":1,", 1);
    assert!(serde_json::from_str::<Response>(&encoded).is_err());
}

#[test]
fn accepted_rfc_json_examples_match_the_implemented_wire_schema() {
    let rfc = include_str!(
        "../../../docs/rfc/dns-provider-protocol/0001-asteracme-dns-provider-protocol.md"
    );
    let mut count = 0;
    for block in rfc.split("```json\n").skip(1) {
        let text = block.split("```").next().unwrap();
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        if value.get("records").is_some() {
            let request: crate::wire::Request = serde_json::from_str(text).unwrap();
            validate_request(&request).unwrap();
        } else if value.get("results").is_some() {
            let _: Response = serde_json::from_str(text).unwrap();
        } else if value.get("code").is_some() {
            let _: WireError = serde_json::from_str(text).unwrap();
        } else if value.get("status").is_some() {
            let _: RecordResult = serde_json::from_str(text).unwrap();
        }
        count += 1;
    }
    assert_eq!(count, 7);
}
