//! CLI renders reports; it does not perform CAA lookups or decide stage eligibility.
use crate::commands::cert::precheck::caa::*;
use aster_acme::precheck::{Observation as Entry, Report, order::Observer};
fn record() -> IssueRecord {
    serde_json::from_value(serde_json::json!({
        "operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name":"test", "created_at":"2026-11-12T00:00:00Z",
        "account_name":"default", "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "directory":"https://ca.example/directory",
        "account_url":"https://ca.example/account/1", "account_thumbprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "key_algorithm":"ecdsa-p256", "identifiers":["example.com", "*.example.com"], "solver_id":"manual_dns", "solver_config":{}, "challenge":"dns-01",
        "phase":"creating_order", "new_order_intent_saved":false, "authorizations":[], "finalize_submitted":"not_submitted"
    })).unwrap()
}

#[test]
fn every_observation_is_rendered_without_changing_issuance_state() {
    let saved = record();
    let before = serde_json::to_value(&saved).unwrap();
    let (output, _, diagnostics) = crate::common::session::tests::session(false);
    let progress = Progress::new(output);
    let observer = Display::new(&saved, &progress);
    observer.starting();
    for result in [
        Err(Failure::LookupFailed),
        Err(Failure::Unavailable),
        Err(Failure::TimedOut),
        Err(Failure::NotChecked),
        Err(Failure::UnsupportedInput),
        Ok(aster_acme_validation::caa::Report {
            identifier: "example.com".into(),
            source: Some("example.com".into()),
            properties: vec![],
            observation: Observation::NoMatch,
        }),
    ] {
        observer.observed(&Report {
            observations: vec![Entry { index: 0, result }],
        });
    }
    let text = diagnostics.text();
    assert!(text.contains("CAA example.com:"));
    assert!(text.contains("no caaIdentities") || text.contains("missing caaIdentities"));
    assert!(text.contains("CAA precheck timed out"));
    assert!(text.contains("no CAA record matches"));
    assert_eq!(serde_json::to_value(saved).unwrap(), before);
}

#[test]
fn only_matching_or_unrestricted_caa_results_use_info() {
    let saved = record();
    for (observation, level) in [
        (Observation::Unrestricted, "INFO"),
        (Observation::Matches, "INFO"),
        (Observation::NoMatch, "WARN"),
        (Observation::Unknown, "WARN"),
    ] {
        let (output, _, diagnostics) = crate::common::session::tests::session(false);
        let progress = Progress::new(output);
        Display::new(&saved, &progress).observed(&Report {
            observations: vec![Entry {
                index: 0,
                result: Ok(aster_acme_validation::caa::Report {
                    identifier: "example.com".into(),
                    source: None,
                    properties: vec![],
                    observation,
                }),
            }],
        });
        assert!(
            diagnostics.text().contains(&format!("[{level}]")),
            "{}",
            diagnostics.text()
        );
    }
    for failure in [
        Failure::Unavailable,
        Failure::LookupFailed,
        Failure::UnsupportedInput,
        Failure::TimedOut,
        Failure::NotChecked,
    ] {
        let (output, _, diagnostics) = crate::common::session::tests::session(false);
        let progress = Progress::new(output);
        Display::new(&saved, &progress).observed(&Report::<aster_acme_validation::caa::Report> {
            observations: vec![Entry {
                index: 0,
                result: Err(failure),
            }],
        });
        assert!(
            diagnostics.text().contains("[WARN]"),
            "{}",
            diagnostics.text()
        );
        assert!(!diagnostics.text().contains("[INFO]"));
    }
}
