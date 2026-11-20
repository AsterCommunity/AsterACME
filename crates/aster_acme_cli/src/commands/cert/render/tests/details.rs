//! Saved CA constraints and authorization instructions stay visible after module moves.
use crate::commands::cert::render::details::{authorization_lines, renewal_lines, request_lines};
use crate::commands::cert::render::tests::detailed_record;
use aster_acme::issuance::{RenewalRetryState, ValidationRequirement};
use time::Duration;

#[test]
fn renewal_details_show_saved_ari_and_effective_retry_without_rescheduling_history() {
    let mut record = detailed_record();
    let now = record.created_at;
    let plan = record.renewal.as_mut().unwrap();
    plan.source = aster_acme::renewal::RenewalSource::Ari;
    plan.suggested_window = Some(aster_acme_protocol::renewal::SuggestedWindow {
        start: now,
        end: now + Duration::days(1),
    });
    plan.next_check_at = Some(now + Duration::hours(1));
    plan.last_query_failed = true;
    plan.explanation_url = Some("https://ca.example/notice".into());
    record.renewal_retry = Some(RenewalRetryState {
        failures: 2,
        retry_at: Some(now + Duration::minutes(1)),
        ca_retry_at: Some(now + Duration::hours(2)),
        blocked_reason: None,
    });
    let text = renewal_lines(&record, now, false).join("\n");
    for field in [
        "ARI window:",
        "ARI next check:",
        "query incomplete or failed; saved renewal time retained",
        "Renewal failures:",
        "CA Retry-After:",
        "https://ca.example/notice",
    ] {
        assert!(text.contains(field), "missing {field}: {text}");
    }
    let effective = crate::common::time::timestamp(Some(now + Duration::hours(2)));
    assert_eq!(text.matches(&effective).count(), 2);
    record.renewal_retry.as_mut().unwrap().blocked_reason =
        Some("newOrder outcome unconfirmed".into());
    let blocked = renewal_lines(&record, now, false).join("\n");
    assert!(blocked.contains("blocked: newOrder outcome unconfirmed"));
    assert!(!blocked.contains("CA Retry-After:"));
    record.is_in_use = false;
    let history = renewal_lines(&record, now, false).join("\n");
    assert!(history.contains("not scheduled (historical version)"));
    assert!(!history.contains("Automatic retry:"));
}

#[test]
fn authorization_details_escape_materials_and_keep_wildcard_and_status_observations() {
    let mut record = detailed_record();
    for (status, requirement) in [
        (
            "pending",
            ValidationRequirement::Http01 {
                url: "http://example.com/path\n".into(),
                path: "/.well-known/acme-challenge/token".into(),
                content: "exact\nbytes".into(),
            },
        ),
        (
            "valid",
            ValidationRequirement::TlsAlpn01 {
                identifier: "example.com\n".into(),
                digest: [0; 32],
            },
        ),
        (
            "expired",
            ValidationRequirement::Dns01 {
                name: "_acme-challenge.example.com".into(),
                value: "value".into(),
            },
        ),
    ] {
        record.authorizations = vec![serde_json::from_value(serde_json::json!({
            "url":"https://ca.example/auth", "resource":{"identifier":{"type":"dns","value":"example.com"},"status":status,"wildcard":true,"challenges":[]},
            "challenge_url":null,"validation_requirement":requirement,"cleanup_pending":false,"acknowledgement":"not_submitted"
        })).unwrap()];
        let lines = authorization_lines(&record, false).join("\n");
        assert!(lines.contains(&format!("*.example.com | {status}")));
        assert!(lines.contains("Saved validation:"));
        assert!(!lines.contains("exact\nbytes"));
        if status == "pending" {
            assert!(lines.contains("File: .well-known/acme-challenge/token"));
            assert!(lines.contains("Content (exact, no newline required):"));
        }
    }
    record.solver_id = "webroot".into();
    record.challenge = aster_acme::challenge::ChallengeKind::Http01;
    record.solver_config = serde_json::json!({"root":"/srv/www"});
    assert!(
        request_lines(&record, record.created_at, false)
            .join("\n")
            .contains("Webroot:")
    );
    record.solver_id = "standalone".into();
    record.solver_config = serde_json::json!({"listen_address":"127.0.0.1:80"});
    assert!(
        request_lines(&record, record.created_at, false)
            .join("\n")
            .contains("127.0.0.1:80")
    );
}
