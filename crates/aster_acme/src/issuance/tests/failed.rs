//! Terminal evidence drives failed cleanup; resume exclusion alone is insufficient.
use crate::issuance::*;
fn record() -> IssueRecord {
    serde_json::from_value(serde_json::json!({"operation_id":"a".repeat(43),"name":"test","created_at":"2026-11-12T00:00:00Z","account_name":"default","account_id":"a".repeat(43),"directory":"https://ca.example/directory","account_url":"https://ca.example/account/1","account_thumbprint":"a".repeat(43),"key_algorithm":"ecdsa-p256","identifiers":["example.com"],"solver_id":"manual_dns","solver_config":{},"challenge":"dns-01","phase":"creating_order","new_order_intent_saved":false,"authorizations":[],"finalize_submitted":"not_submitted"})).unwrap()
}

#[test]
fn retry_preserves_precision_ca_deadline_and_uncertainty_at_extremes() {
    let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::nanoseconds(123_456_789);
    let mut state =
        RenewalRetryState::after_failure(None, now, Some(now + time::Duration::hours(1)), None);
    assert_eq!(state.retry_at, Some(now + time::Duration::minutes(1)));
    for (failures, seconds) in [(2, 600), (3, 6000), (4, 86400), (5, 86400)] {
        state = RenewalRetryState::after_failure(Some(&state), now, None, None);
        assert_eq!(state.failures, failures);
        assert_eq!(state.retry_at, Some(now + time::Duration::seconds(seconds)));
        assert_eq!(state.ca_retry_at, Some(now + time::Duration::hours(1)));
    }
    state.failures = u32::MAX;
    state.blocked_reason = Some("uncertain mutation".into());
    let blocked = RenewalRetryState::after_failure(Some(&state), now, Some(now), None);
    assert_eq!(blocked.failures, u32::MAX);
    assert_eq!(
        blocked.blocked_reason.as_deref(),
        Some("uncertain mutation")
    );
    assert!(blocked.retry_at.is_none());
    let max = time::PrimitiveDateTime::MAX.assume_utc();
    let overflow = RenewalRetryState::after_failure(None, max, None, None);
    assert!(overflow.retry_at.is_none());
    assert!(overflow.blocked_reason.is_some());
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
    base.new_order_intent_saved = true;
    assert!(!base.failed_unresumable(now)); // lost newOrder response
    base.new_order_intent_saved = false;
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
    saved.renewal = Some(crate::renewal::RenewalPlan {
        certificate_id: None,
        not_before: now - time::Duration::days(1),
        not_after: now + time::Duration::days(30),
        renew_at: now + time::Duration::days(20),
        source: crate::renewal::RenewalSource::Fallback,
        suggested_window: None,
        explanation_url: None,
        last_checked_at: None,
        next_check_at: None,
        last_query_failed: false,
    });
    assert!(!saved.failed_unresumable(now)); // issued even if phase is damaged
    for status in ["invalid", "expired", "deactivated", "revoked"] {
        let mut saved = base.clone();
        saved.authorizations = serde_json::from_value(serde_json::json!([{"url":"https://ca.example/auth","resource":{"identifier":{"type":"dns","value":"example.com"},"status":status,"challenges":[]},"challenge_url":null,"validation_requirement":null,"cleanup_pending":false,"acknowledgement":"not_submitted"}])).unwrap();
        assert!(saved.failed_unresumable(now), "{status}");
    }
}
