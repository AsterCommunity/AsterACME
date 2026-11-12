//! Terminal evidence drives failed cleanup; resume exclusion alone is insufficient.
use crate::issuance::*;
fn record() -> IssueRecord {
    serde_json::from_value(serde_json::json!({"operation_id":"a".repeat(43),"name":"test","created_at":"2026-11-12T00:00:00Z","account_name":"default","account_id":"a".repeat(43),"directory":"https://ca.example/directory","account_url":"https://ca.example/account/1","account_thumbprint":"a".repeat(43),"key_algorithm":"ecdsa-p256","identifiers":["example.com"],"solver_id":"manual_dns","solver_config":{},"challenge":"dns-01","phase":"creating_order","creation_submitted":false,"authorizations":[],"finalize_submitted":"not_submitted"})).unwrap()
}
fn order(status: &str) -> OrderObject {
    serde_json::from_value(serde_json::json!({"status":status,"expires":"2026-11-12T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[],"finalize":"https://ca.example/finalize"})).unwrap()
}
#[test]
fn terminal_order_expiry_authorization_and_csr_failures_are_distinct_from_uncertainty() {
    let now = time::OffsetDateTime::parse(
        "2026-11-13T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let mut base = record();
    assert!(!base.failed_unresumable(now));
    base.creation_submitted = true;
    assert!(!base.failed_unresumable(now)); // lost newOrder response
    base.creation_submitted = false;
    for status in ["invalid", "pending", "processing", "ready"] {
        let mut saved = base.clone();
        saved.order = Some(order(status));
        assert!(saved.failed_unresumable(now)); // all expired, invalid also terminal
        saved.order.as_mut().unwrap().expires = Some(now + time::Duration::days(1));
        assert_eq!(saved.failed_unresumable(now), status == "invalid");
    }
    let mut saved = base.clone();
    saved.order = Some(order("valid"));
    saved.creation_failure = Some(RequestFailure {
        status: 400,
        problem: None,
        retry_at: None,
    });
    assert!(!saved.failed_unresumable(now)); // downloadable certificate retained
    saved = base.clone();
    saved.finalize_rejection = Some(RequestFailure {
        status: 403,
        problem: None,
        retry_at: None,
    });
    assert!(saved.failed_unresumable(now));
    saved.phase = aster_acme_core::workflow::IssuancePhase::Completed;
    assert!(!saved.failed_unresumable(now));
    saved = base.clone();
    saved.creation_failure = Some(RequestFailure {
        status: 400,
        problem: None,
        retry_at: None,
    });
    saved.certificate_not_after = Some(now);
    assert!(!saved.failed_unresumable(now)); // issued even if phase is damaged
    for status in ["invalid", "expired", "deactivated", "revoked"] {
        let mut saved = base.clone();
        saved.authorizations = serde_json::from_value(serde_json::json!([{"url":"https://ca.example/auth","resource":{"identifier":{"type":"dns","value":"example.com"},"status":status,"challenges":[]},"challenge_url":null,"validation":null,"cleanup_pending":false,"acknowledgement":"not_submitted"}])).unwrap();
        assert!(saved.failed_unresumable(now), "{status}");
    }
}
