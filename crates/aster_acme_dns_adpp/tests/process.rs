//! Self-hosted provider fixture: no shell, Python, public DNS, or API credentials.
use aster_acme_dns::{
    CleanupRequest, DnsProvider, DnsRecord, HostErrorCode, ProviderContext, ProviderErrorCode,
    ProviderExecution, ProviderFailure, RecordOwnership, SideEffect,
};
use aster_acme_dns_adpp::{AdppProvider, Executable, PROTOCOL_ID};
use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    time::{Duration, Instant},
};
fn main() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("--adpp-fixture") {
        let mode = args.next().expect("fixture mode");
        fixture(&mode);
        return;
    }
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(test_process_contract());
    println!(
        "ADPP process contract: success, partial results, cleared environment, malformed/large output, timeout and cancellation verified"
    );
}
fn fixture(mode: &str) {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let request: serde_json::Value = serde_json::from_str(&input).unwrap();
    assert!(std::env::var_os("PATH").is_none());
    if mode == "timeout" {
        std::thread::sleep(Duration::from_secs(10));
    }
    if mode == "invalid-json" {
        println!("not JSON");
        return;
    }
    if mode == "oversize" {
        std::io::stdout()
            .write_all(&vec![b'x'; 1024 * 1024 + 1])
            .unwrap();
        return;
    }
    if mode == "stderr" {
        std::io::stderr()
            .write_all(&vec![b's'; 1024 * 1024])
            .unwrap();
    }
    let action = request["action"].as_str().unwrap();
    let results = request["records"].as_array().unwrap().iter().enumerate().map(|(index, record)| {
        if mode == "partial" && index == 1 { return serde_json::json!({"publication_id": record["publication_id"],"status":"error","error":{"code":"provider_timeout","message":"secret-sentinel API timed out","side_effect":"unknown"}}); }
        if action == "present" { serde_json::json!({"publication_id":record["publication_id"],"status":"present","record_id":format!("record-{index}"),"ownership":if mode == "preexisting" {"preexisting"} else {"created"}}) }
        else { serde_json::json!({"publication_id":record["publication_id"],"status":"removed"}) }
    }).collect::<Vec<_>>();
    let mut response = serde_json::json!({"protocol": PROTOCOL_ID,"version":1,"request_id":request["request_id"],"action":request["action"],"results":results,"error":null});
    if mode == "mismatch" {
        response["request_id"] = "wrong-id".into();
    }
    println!("{response}");
    if mode == "nonzero" {
        std::process::exit(3);
    }
}
fn record(id: &str) -> DnsRecord {
    DnsRecord {
        publication_id: id.into(),
        challenge_name: "_acme-challenge.example.com.".into(),
        cname_chain: vec!["_acme-challenge.example.com.".into()],
        name: "_acme-challenge.example.com.".into(),
        value: "test-value".into(),
        ttl_seconds: Some(120),
    }
}
fn provider(mode: &str) -> AdppProvider {
    AdppProvider::new(Executable {
        program: std::env::current_exe().unwrap(),
        args: vec!["--adpp-fixture".into(), mode.into()],
        timeout: Duration::from_secs(2),
    })
}
fn execution() -> ProviderExecution {
    ProviderExecution {
        cancellation: tokio_util::sync::CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(5),
    }
}
async fn test_process_contract() {
    let context = ProviderContext {
        provider_instance_id: "prod".into(),
        provider_profile_version: 1,
        provider_custom: BTreeMap::from([("token".into(), serde_json::json!("secret-sentinel"))]),
    };
    let records = [record("one"), record("two")];
    for mode in ["success", "stderr", "preexisting"] {
        let results = provider(mode)
            .present(&context, &records, &execution())
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        let receipt = results[0].result.clone().unwrap();
        assert_eq!(
            receipt.ownership,
            if mode == "preexisting" {
                RecordOwnership::Preexisting
            } else {
                RecordOwnership::Created
            }
        );
        let cleanup = CleanupRequest {
            publication_id: "one".into(),
            receipt,
            record: records[0].clone(),
        };
        assert!(
            provider("success")
                .cleanup(&context, &[cleanup], &execution())
                .await
                .unwrap()[0]
                .result
                .is_ok()
        );
    }
    let results = provider("partial")
        .present(&context, &records, &execution())
        .await
        .unwrap();
    assert!(results[0].result.is_ok());
    assert_eq!(
        results[1].result.as_ref().unwrap_err().code,
        ProviderErrorCode::ProviderTimeout
    );
    assert!(
        !results[1]
            .result
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("secret-sentinel")
    );
    for (mode, expected) in [
        ("invalid-json", HostErrorCode::ResponseInvalidJson),
        ("mismatch", HostErrorCode::ResponseInvalid),
        ("oversize", HostErrorCode::ResponseTooLarge),
        ("nonzero", HostErrorCode::ProcessExitNonzero),
    ] {
        let error = provider(mode)
            .present(&context, &records, &execution())
            .await
            .unwrap_err();
        assert!(
            matches!(error, ProviderFailure::Host {code,side_effect:SideEffect::Unknown} if code == expected),
            "{mode}: {error:?}"
        );
    }
    let mut scope = execution();
    scope.deadline = Instant::now() + Duration::from_millis(100);
    assert!(matches!(
        provider("timeout")
            .present(&context, &records, &scope)
            .await,
        Err(ProviderFailure::Host {
            code: HostErrorCode::ProcessTimeout,
            side_effect: SideEffect::Unknown
        })
    ));
    let scope = execution();
    scope.cancellation.cancel();
    assert!(matches!(
        provider("success")
            .present(&context, &records, &scope)
            .await,
        Err(ProviderFailure::Host {
            code: HostErrorCode::ProcessCancelled,
            side_effect: SideEffect::None
        })
    ));
}
