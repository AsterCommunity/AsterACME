//! ADPP validation and infrastructure-to-product failure boundaries.

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

/// Construct platform-native statuses without starting a process.
fn process_exit_status(success: bool) -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        std::process::ExitStatus::from_raw(if success { 0 } else { 3 << 8 })
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt as _;
        std::process::ExitStatus::from_raw(if success { 0 } else { 3 })
    }
}

fn process_outcome(
    status: Result<std::process::ExitStatus, aster_forge_process::ProcessFailure>,
    started: bool,
) -> aster_forge_process::ProcessOutcome {
    aster_forge_process::ProcessOutcome {
        status,
        started,
        stdout: aster_forge_process::CapturedOutput::default(),
        stderr: aster_forge_process::CapturedOutput::default(),
        stdin_error: None,
        cleanup_error: None,
    }
}

#[test]
fn process_failures_preserve_host_codes_and_started_side_effects() {
    use aster_acme_dns::{HostErrorCode, ProviderFailure};
    use aster_forge_process::ProcessFailure;
    let cases = [
        (
            ProcessFailure::Spawn(std::io::ErrorKind::NotFound.into()),
            false,
            HostErrorCode::ProcessSpawnFailed,
        ),
        (
            ProcessFailure::CancelledBeforeStart,
            false,
            HostErrorCode::ProcessCancelled,
        ),
        (
            ProcessFailure::TimedOut,
            false,
            HostErrorCode::ProcessTimeout,
        ),
        (
            ProcessFailure::Cancelled,
            true,
            HostErrorCode::ProcessCancelled,
        ),
        (
            ProcessFailure::TimedOut,
            true,
            HostErrorCode::ProcessTimeout,
        ),
        (
            ProcessFailure::Wait(std::io::Error::other("private process error")),
            true,
            HostErrorCode::ProcessWaitFailed,
        ),
    ];
    for (failure, started, expected) in cases {
        let outcome = process_outcome(Err(failure), started);
        let error = crate::check_process_status(&outcome).unwrap_err();
        assert!(matches!(
            error,
            ProviderFailure::Host { code, side_effect }
                if code == expected && side_effect == if started { SideEffect::Unknown } else { SideEffect::None }
        ));
        assert!(!error.to_string().contains("private process error"));
    }
    assert!(
        crate::check_process_status(&process_outcome(Ok(process_exit_status(true)), true)).is_ok()
    );
    assert!(matches!(
        crate::check_process_status(&process_outcome(Ok(process_exit_status(false)), true)),
        Err(ProviderFailure::Host {
            code: HostErrorCode::ProcessExitNonzero,
            side_effect: SideEffect::Unknown,
        })
    ));
}

#[test]
fn incomplete_cleanup_overrides_success_cancellation_and_deadline() {
    use aster_acme_dns::{HostErrorCode, ProviderFailure};
    use aster_forge_process::ProcessFailure;
    for kind in [
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::PermissionDenied,
    ] {
        for status in [
            Ok(process_exit_status(true)),
            Ok(process_exit_status(false)),
            Err(ProcessFailure::Cancelled),
            Err(ProcessFailure::TimedOut),
            Err(ProcessFailure::Wait(std::io::Error::other("wait failed"))),
        ] {
            let mut outcome = process_outcome(status, true);
            outcome.cleanup_error = Some(std::io::Error::new(kind, "private cleanup error"));
            let error = crate::check_process_status(&outcome).unwrap_err();
            assert!(matches!(
                error,
                ProviderFailure::Host {
                    code: HostErrorCode::ProcessWaitFailed,
                    side_effect: SideEffect::Unknown,
                }
            ));
            assert!(!error.to_string().contains("private cleanup error"));
        }
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
    assert_eq!(validate_rfc_examples(rfc), 7);
    assert_eq!(validate_rfc_examples(&rfc.replace('\n', "\r\n")), 7);
}

fn validate_rfc_examples(rfc: &str) -> usize {
    let normalized = rfc.replace("\r\n", "\n").replace('\r', "\n");
    let mut count = 0;
    for block in normalized.split("```json\n").skip(1) {
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
    count
}

#[test]
fn explicit_target_is_sent_without_claiming_a_resolved_cname_chain() {
    let mut record = record();
    record.name = "delegated.example.net.".into();
    record.cname_chain.clear();
    let request = request(Action::Present, &context(), &[record], &[]).unwrap();
    validate_request(&request).unwrap();
    let value = serde_json::to_value(request).unwrap();
    assert_eq!(
        value["records"][0]["record"]["name"],
        "delegated.example.net."
    );
    assert!(value["records"][0].get("challenge_name").is_none());
    assert!(value["records"][0].get("cname_chain").is_none());
}
