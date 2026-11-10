//! Recovery ambiguity and primary-domain command contracts.
use crate::app::Args;
use clap::Parser;

#[test]
fn issue_arguments_keep_resume_and_new_requests_separate() {
    for arguments in [
        vec!["cert", "issue"],
        vec!["cert", "issue", "-d", "Example.com", "-d", "*.example.com"],
        vec!["cert", "issue", "--resume", "example.com"],
        vec![
            "cert",
            "issue",
            "-d",
            "example.com",
            "-f",
            "-a",
            "work",
            "-n",
            "example",
        ],
    ] {
        assert!(Args::try_parse_from(std::iter::once("aster-acme").chain(arguments)).is_ok());
    }
    for arguments in [
        vec![
            "cert",
            "issue",
            "--resume",
            "example.com",
            "-d",
            "other.com",
        ],
        vec!["cert", "issue", "-d", "example.com", "--operation", "id"],
        vec!["order", "create"],
        vec!["order", "show", "example.com", "--force"],
    ] {
        let parsed = Args::try_parse_from(std::iter::once("aster-acme").chain(arguments.clone()));
        assert!(parsed.is_err(), "unexpectedly accepted {arguments:?}");
    }
}

fn record(id: char, created: &str) -> aster_acme::issuance::IssueRecord {
    serde_json::from_value(serde_json::json!({
        "operation_id":id.to_string().repeat(43),"name":"example.com","created_at":created,
        "account_name":"default","account_id":"account","directory":"https://ca.example/directory",
        "account_url":"https://ca.example/account","account_thumbprint":"key","identifiers":["example.com"],
        "solver_id":"manual_dns","phase":"creating_order","creation_submitted":false,"order_url":null,"order":null,
        "authorizations":[],"finalize_submitted":"not_submitted","next_poll_at":null,"certificate_not_after":null
    })).unwrap()
}

#[test]
fn recovery_uses_exact_request_when_ambiguous_and_does_not_guess_newest() {
    let name = aster_acme::issuance::CertificateName::new("example.com").unwrap();
    let first = record('a', "2026-01-01T00:00:00Z");
    let mut second = record('b', "2026-02-01T00:00:00Z");
    assert!(super::choose(vec![first.clone(), second.clone()], &name, None, true, true).is_err());
    assert_eq!(
        super::choose(
            vec![first.clone(), second.clone()],
            &name,
            Some(&first.operation_id),
            true,
            true
        )
        .unwrap()
        .operation_id,
        first.operation_id
    );
    assert!(super::choose(vec![first.clone()], &name, Some("missing"), true, true).is_err());
    second.phase = aster_acme_core::workflow::IssuancePhase::Completed;
    assert_eq!(
        super::choose(vec![first.clone(), second], &name, None, true, true)
            .unwrap()
            .operation_id,
        first.operation_id
    );
    assert!(super::choose(vec![], &name, None, true, true).is_err());
    let text = super::super::render::show(std::slice::from_ref(&first), false, false).unwrap();
    assert!(
        text.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains("Requested: 2026-01-01")
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            &super::super::render::show(&[first], true, false).unwrap()
        )
        .unwrap()[0]["created_at"],
        "2026-01-01T00:00:00Z"
    );
}

#[test]
fn one_challenge_option_selects_publication_without_exposing_wire_method() {
    use clap::CommandFactory;
    for arguments in [
        vec!["cert", "issue", "-d", "example.com"],
        vec!["cert", "issue", "-d", "example.com", "-c", "manual_dns"],
    ] {
        let parsed = Args::try_parse_from(std::iter::once("aster-acme").chain(arguments)).unwrap();
        let crate::app::Command::Cert { command } = parsed.command else {
            panic!("expected certificate command");
        };
        let super::super::args::CertCommand::Issue(args) = *command else {
            panic!("expected issue");
        };
        assert!(matches!(
            args.challenge,
            super::super::args::Challenge::ManualDns
        ));
    }
    for flag in [
        vec!["-c", "dns-01"],
        vec!["--solver", "manual_dns"],
        vec!["-c", "standalone"],
    ] {
        assert!(
            Args::try_parse_from(
                ["aster-acme", "cert", "issue", "-d", "example.com"]
                    .into_iter()
                    .chain(flag)
            )
            .is_err()
        );
    }
    let mut root = Args::command();
    let cert = root.find_subcommand_mut("cert").unwrap();
    let issue = cert.find_subcommand_mut("issue").unwrap();
    let help = issue.render_long_help().to_string();
    assert!(help.contains("manual_dns"));
    assert!(!help.contains("--solver"));
    assert!(!help.contains("dns-01"));
}

#[test]
fn manual_action_is_a_warning_but_json_retains_a_typed_action_result() {
    let record = record('a', "2026-01-01T00:00:00Z");
    let outcome = aster_acme::issuance::IssueOutcome::ActionRequired {
        record: Box::new(record),
        records: vec![aster_acme::issuance::DnsRequirement {
            name: "_acme-challenge.example.com".into(),
            value: "opaque-TXT-value".into(),
        }],
    };
    let root = std::path::Path::new("/private/tmp/fixture");
    let text = super::super::render::outcome(&outcome, false, root).unwrap();
    assert!(text.starts_with("[WARN] Action required for example.com"));
    assert!(text.contains("opaque-TXT-value"));
    assert!(text.contains("--resume 'example.com'"));
    let json = super::super::render::outcome(&outcome, true, root).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["status"], "action_required");
    assert!(!json.contains("[WARN]"));
    assert!(!json.contains('\x1b'));
}

#[test]
fn issued_certificate_has_a_done_summary_and_independent_manual_cleanup() {
    let outcome = aster_acme::issuance::IssueOutcome::Completed {
        record: Box::new(record('a', "2026-01-01T00:00:00Z")),
        cleanup: vec![aster_acme::issuance::DnsRequirement {
            name: "_acme-challenge.example.com".into(),
            value: "manual-value".into(),
        }],
    };
    let text = super::super::render::outcome(
        &outcome,
        false,
        std::path::Path::new("/private/tmp/fixture"),
    )
    .unwrap();
    assert!(text.starts_with("[DONE] Issued certificate example.com"));
    assert!(text.contains("manual-value"));
    assert!(text.contains("fullchain.pem"));
    assert!(text.contains("private-key.pem"));
    let json =
        super::super::render::outcome(&outcome, true, std::path::Path::new("/private/tmp/fixture"))
            .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap()["status"],
        "completed"
    );
    assert!(!json.contains("[DONE]"));
}

#[test]
fn order_list_is_a_compact_aligned_table_and_show_keeps_full_details() {
    let mut first = record('a', "2026-01-01T00:00:00Z");
    let second = record('b', "2026-02-01T00:00:00Z");
    first.name = aster_acme::issuance::CertificateName::new("long.example.com").unwrap();
    let text = super::super::render::list(&[first.clone(), second.clone()], false).unwrap();
    let lines = text.lines().collect::<Vec<_>>();
    assert!(lines[1].contains("REQUESTED (UTC)"));
    assert_eq!(lines[2].find("2026-01-01"), lines[3].find("2026-02-01"));
    assert!(!text.contains("https://"));
    assert!(!text.contains(&first.operation_id));
    assert!(!text.contains("  Request:"));
    assert!(
        super::super::render::show(std::slice::from_ref(&first), false, false)
            .unwrap()
            .contains(&first.operation_id)
    );
    let json = super::super::render::list(&[first, second], true).unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(&json)
            .unwrap()
            .is_array()
    );
    assert_eq!(
        super::super::render::list(&[], false).unwrap(),
        "No saved certificate requests."
    );
}

#[test]
fn selection_labels_only_show_primary_domain_fixed_time_and_status() {
    let first = record('a', "2026-01-01T00:00:00.123456Z");
    let second = record('b', "2026-01-01T00:00:00.999999Z");
    let label = super::choice_label(&first);
    assert_eq!(
        label,
        "example.com | 2026-01-01 00:00:00 UTC | creating order"
    );
    assert_eq!(label, super::choice_label(&second));
    assert!(!label.contains("https://"));
    assert!(!label.contains(&first.operation_id));
}

#[test]
fn cert_show_without_name_defers_to_interaction_but_never_prompts_scripts() {
    assert!(Args::try_parse_from(["aster-acme", "cert", "show"]).is_ok());
    let first = record('a', "2026-01-01T00:00:00Z");
    assert!(super::certificate_name(std::slice::from_ref(&first), None, None, true).is_err());
    assert_eq!(
        super::certificate_name(
            std::slice::from_ref(&first),
            None,
            Some(&first.operation_id),
            true
        )
        .unwrap(),
        first.name
    );
    assert_eq!(
        super::certificate_name(&[], Some("example.com"), None, true)
            .unwrap()
            .as_str(),
        "example.com"
    );
    assert!(super::certificate_name(&[], None, Some("missing"), true).is_err());
    for arguments in [
        ["aster-acme", "order", "list"],
        ["aster-acme", "order", "show"],
    ] {
        assert!(Args::try_parse_from(arguments).is_err());
    }
}

#[test]
fn verification_source_is_explicit_in_text_and_json() {
    let record = record('a', "2026-01-01T00:00:00Z");
    for verified in [false, true] {
        let text =
            super::super::render::show(std::slice::from_ref(&record), false, verified).unwrap();
        assert!(
            text.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains(if verified {
                    "Remote status: verified with CA"
                } else {
                    "Remote status: not verified."
                })
        );
        assert!(!text.contains("unless --verify"));
        let json =
            super::super::render::show(std::slice::from_ref(&record), true, verified).unwrap();
        let json: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(json[0]["verified"], verified);
        assert_eq!(json[0]["source"], if verified { "remote" } else { "local" });
    }
}

#[test]
fn certificate_yes_has_short_and_long_forms_without_implying_force_or_other_permissions() {
    for flag in ["-y", "--yes"] {
        let parsed = Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "--resume",
            "example.com",
            flag,
        ])
        .unwrap();
        let crate::app::Command::Cert { command } = parsed.command else {
            panic!("expected cert");
        };
        let super::super::args::CertCommand::Issue(args) = *command else {
            panic!("expected issue");
        };
        assert!(args.yes);
        assert!(!args.force);
        assert!(!args.local.json);
    }
    for command in ["list", "show"] {
        assert!(Args::try_parse_from(["aster-acme", "cert", command, "--yes"]).is_err());
    }
}
