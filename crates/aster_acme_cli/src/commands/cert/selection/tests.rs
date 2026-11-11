//! Recovery ambiguity and primary-domain command contracts.
use crate::app::Args;
use clap::Parser;

#[test]
fn issue_arguments_keep_resume_and_new_requests_separate() {
    for arguments in [
        vec!["cert", "issue", "-c", "manual_dns"],
        vec![
            "cert",
            "issue",
            "-d",
            "Example.com",
            "-d",
            "*.example.com",
            "-c",
            "manual_dns",
        ],
        vec!["cert", "issue", "--resume", "example.com"],
        vec![
            "cert",
            "issue",
            "-d",
            "example.com",
            "-a",
            "work",
            "-n",
            "example",
            "-c",
            "manual_dns",
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
        vec![
            "cert",
            "issue",
            "-d",
            "example.com",
            "--operation",
            "id",
            "-c",
            "manual_dns",
        ],
        vec!["order", "create"],
        vec!["order", "show", "example.com", "--skip-dns-check"],
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
        "key_algorithm":"ecdsa-p256","challenge":"dns-01","solver_config":{},"solver_id":"manual_dns","phase":"creating_order","creation_submitted":false,"order_url":null,"order":null,
        "authorizations":[],"finalize_submitted":"not_submitted","next_poll_at":null,"certificate_not_after":null
    })).unwrap()
}

#[test]
fn recovery_uses_exact_request_when_ambiguous_and_does_not_guess_newest() {
    let name = aster_acme::issuance::CertificateName::new("example.com").unwrap();
    let first = record('a', "2026-01-01T00:00:00Z");
    let mut second = record('b', "2026-02-01T00:00:00Z");
    assert!(
        super::choose(
            vec![first.clone(), second.clone()],
            &name,
            None,
            super::RequestSelection::Unfinished,
            &crate::common::session::OutputSession::new(true)
        )
        .is_err()
    );
    assert_eq!(
        super::choose(
            vec![first.clone(), second.clone()],
            &name,
            Some(&first.operation_id),
            super::RequestSelection::Unfinished,
            &crate::common::session::OutputSession::new(true)
        )
        .unwrap()
        .operation_id,
        first.operation_id
    );
    assert!(
        super::choose(
            vec![first.clone()],
            &name,
            Some("missing"),
            super::RequestSelection::Unfinished,
            &crate::common::session::OutputSession::new(true)
        )
        .is_err()
    );
    second.phase = aster_acme_core::workflow::IssuancePhase::Completed;
    assert_eq!(
        super::choose(
            vec![first.clone(), second],
            &name,
            None,
            super::RequestSelection::Unfinished,
            &crate::common::session::OutputSession::new(true)
        )
        .unwrap()
        .operation_id,
        first.operation_id
    );
    assert!(
        super::choose(
            vec![],
            &name,
            None,
            super::RequestSelection::Unfinished,
            &crate::common::session::OutputSession::new(true)
        )
        .is_err()
    );
    let text = super::super::render::show(
        std::slice::from_ref(&first),
        crate::common::session::Format::plain(false),
        false,
        super::super::render::DetailView::InUse,
    )
    .unwrap();
    assert!(
        text.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains("Requested: 2026-01-01")
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            &super::super::render::show(
                &[first],
                crate::common::session::Format::plain(true),
                false,
                super::super::render::DetailView::InUse
            )
            .unwrap()
        )
        .unwrap()[0]["created_at"],
        "2026-01-01T00:00:00Z"
    );
}

#[test]
fn one_challenge_option_selects_publication_without_exposing_wire_method() {
    use clap::CommandFactory;
    for arguments in [
        vec!["cert", "issue", "-d", "example.com", "-c", "manual_dns"],
        vec!["cert", "issue", "-d", "example.com", "-c", "manual_dns"],
    ] {
        let parsed = Args::try_parse_from(std::iter::once("aster-acme").chain(arguments)).unwrap();
        let crate::app::Command::Cert { command } = parsed.command else {
            panic!("expected certificate command");
        };
        let super::super::args::CertCommand::Issue(args) = command else {
            panic!("expected issue");
        };
        assert!(matches!(
            args.challenge,
            Some(super::super::validation::ValidationMethod::ManualDns)
        ));
    }
    for flag in [
        vec!["-c", "dns-01"],
        vec!["--solver", "manual_dns"],
        vec!["-c", "standalone"],
    ] {
        assert!(
            Args::try_parse_from(
                [
                    "aster-acme",
                    "cert",
                    "issue",
                    "-d",
                    "example.com",
                    "-c",
                    "manual_dns"
                ]
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
        records: vec![aster_acme::issuance::ValidationRequirement::Dns01 {
            name: "_acme-challenge.example.com".into(),
            value: "opaque-TXT-value".into(),
        }],
    };
    let root = std::path::Path::new("/private/tmp/fixture");
    let text =
        super::super::render::outcome(&outcome, crate::common::session::Format::plain(false), root)
            .unwrap();
    assert!(text.starts_with("[WARN] Action required for example.com"));
    assert!(text.contains("opaque-TXT-value"));
    assert!(text.contains("--resume 'example.com'"));
    let json =
        super::super::render::outcome(&outcome, crate::common::session::Format::plain(true), root)
            .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["status"], "action_required");
    assert!(!json.contains("[WARN]"));
    assert!(!json.contains('\x1b'));
}

#[test]
fn issued_certificate_has_a_done_summary_and_independent_manual_cleanup() {
    let outcome = aster_acme::issuance::IssueOutcome::Completed {
        record: Box::new(record('a', "2026-01-01T00:00:00Z")),
        cleanup: vec![aster_acme::issuance::ValidationRequirement::Dns01 {
            name: "_acme-challenge.example.com".into(),
            value: "manual-value".into(),
        }],
    };
    let text = super::super::render::outcome(
        &outcome,
        crate::common::session::Format::plain(false),
        std::path::Path::new("/private/tmp/fixture"),
    )
    .unwrap();
    assert!(text.starts_with("[DONE] Issued certificate example.com"));
    assert!(text.contains("manual-value"));
    assert!(text.contains("fullchain.pem"));
    assert!(text.contains("private-key.pem"));
    let json = super::super::render::outcome(
        &outcome,
        crate::common::session::Format::plain(true),
        std::path::Path::new("/private/tmp/fixture"),
    )
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
    let text = super::super::render::list(
        &[first.clone(), second.clone()],
        crate::common::session::Format::plain(false),
    )
    .unwrap();
    let lines = text.lines().collect::<Vec<_>>();
    assert!(lines[1].contains("REQUESTED (UTC)"));
    assert_eq!(lines[2].find("2026-01-01"), lines[3].find("2026-02-01"));
    assert!(!text.contains("https://"));
    assert!(!text.contains(&first.operation_id));
    assert!(!text.contains("  Request:"));
    assert!(
        super::super::render::show(
            std::slice::from_ref(&first),
            crate::common::session::Format::plain(false),
            false,
            super::super::render::DetailView::InUse
        )
        .unwrap()
        .contains(&first.operation_id)
    );
    let json = super::super::render::list(
        &[first, second],
        crate::common::session::Format::plain(true),
    )
    .unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(&json)
            .unwrap()
            .is_array()
    );
    assert_eq!(
        super::super::render::list(&[], crate::common::session::Format::plain(false)).unwrap(),
        "No saved certificate requests."
    );
}

#[test]
fn selection_labels_only_show_primary_domain_fixed_time_and_status() {
    let first = record('a', "2026-01-01T00:00:00.123456Z");
    let second = record('b', "2026-01-01T00:00:00.999999Z");
    let name_label = super::certificate_label(&first);
    assert_eq!(
        name_label,
        "example.com | example.com | 2026-01-01 00:00:00 UTC | creating order"
    );
    let mut in_use = first.clone();
    in_use.is_in_use = true;
    assert!(!super::certificate_label(&in_use).ends_with(" | in use"));
    assert!(super::choice_label(&in_use).ends_with(" | in use"));
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
    assert!(
        super::certificate_name(
            std::slice::from_ref(&first),
            None,
            None,
            &crate::common::session::OutputSession::new(true)
        )
        .is_err()
    );
    assert_eq!(
        super::certificate_name(
            std::slice::from_ref(&first),
            None,
            Some(&first.operation_id),
            &crate::common::session::OutputSession::new(true)
        )
        .unwrap(),
        first.name
    );
    assert_eq!(
        super::certificate_name(
            &[],
            Some("example.com"),
            None,
            &crate::common::session::OutputSession::new(true)
        )
        .unwrap()
        .as_str(),
        "example.com"
    );
    assert!(
        super::certificate_name(
            &[],
            None,
            Some("missing"),
            &crate::common::session::OutputSession::new(true)
        )
        .is_err()
    );
    for arguments in [
        ["aster-acme", "order", "list"],
        ["aster-acme", "order", "show"],
    ] {
        assert!(Args::try_parse_from(arguments).is_err());
    }
}

#[test]
fn verification_source_is_explicit_in_text_and_json() {
    use aster_acme_core::revocation::RevocationState;
    let mut record = record('a', "2026-01-01T00:00:00Z");
    for state in [
        RevocationState::NotRequested,
        RevocationState::Pending,
        RevocationState::Confirmed,
    ] {
        record.revocation.state = state;
        for verified in [false, true] {
            let text = super::super::render::show(
                std::slice::from_ref(&record),
                crate::common::session::Format::plain(false),
                verified,
                super::super::render::DetailView::InUse,
            )
            .unwrap();
            let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(normalized.contains(if verified {
                "CA query: order and authorizations refreshed"
            } else {
                "CA query: not performed (local data only)"
            }));
            let (source, label) = match state {
                RevocationState::Confirmed => {
                    ("saved_ca_response", "Revocation source: saved CA response")
                }
                RevocationState::NotRequested | RevocationState::Pending => {
                    ("local_state", "Revocation source: local state")
                }
            };
            assert!(normalized.contains(label));
            assert!(!text.contains("verified with CA"));
            let json = super::super::render::show(
                std::slice::from_ref(&record),
                crate::common::session::Format::plain(true),
                verified,
                super::super::render::DetailView::InUse,
            )
            .unwrap();
            let json: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(json[0]["ca_query"]["order_refreshed"], verified);
            assert_eq!(json[0]["ca_query"]["authorizations_refreshed"], verified);
            assert_eq!(json[0]["revocation_source"], source);
            assert!(json[0].get("verified").is_none());
            assert!(json[0].get("source").is_none());
        }
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
        let super::super::args::CertCommand::Issue(args) = command else {
            panic!("expected issue");
        };
        assert!(args.run.yes);
        assert!(!args.run.local.json);
    }
    for command in ["list", "show"] {
        assert!(Args::try_parse_from(["aster-acme", "cert", command, "--yes"]).is_err());
    }
}

#[test]
fn selectors_distinguish_revoked_and_unconfirmed_certificate_generations() {
    let mut request = record('a', "2026-01-01T00:00:00Z");
    request.phase = aster_acme_core::workflow::IssuancePhase::Completed;
    request.revocation.state = aster_acme_core::revocation::RevocationState::Pending;
    assert!(super::choice_label(&request).contains("revocation pending"));
    request.revocation.state = aster_acme_core::revocation::RevocationState::Confirmed;
    assert!(super::choice_label(&request).contains("revoked"));
}

#[test]
fn selectors_and_table_share_san_summary_and_in_use_marker_with_full_details_retained() {
    let mut request = record('a', "2026-01-01T00:00:00Z");
    request.identifiers = [
        "example.com",
        "*.example.com",
        "api.example.com",
        "unrelated.example.net",
        "extra.example.org",
    ]
    .map(|name| aster_acme::identifier::DnsIdentifier::new(name).unwrap())
    .to_vec();
    request.is_in_use = true;
    let label = super::choice_label(&request);
    assert!(label.contains("example.com, *.example.com, api.example.com, +2"));
    assert!(label.ends_with(" | in use"));
    assert!(!label.contains("unrelated.example.net"));
    let table = super::super::render::list(
        std::slice::from_ref(&request),
        crate::common::session::Format::plain(false),
    )
    .unwrap();
    assert!(table.contains("DOMAINS"));
    assert!(!table.contains("IN_USE"));
    assert!(table.contains("example.com, *.example.com, api.example.com, +2"));
    let details = super::super::render::show(
        std::slice::from_ref(&request),
        crate::common::session::Format::plain(false),
        false,
        super::super::render::DetailView::InUse,
    )
    .unwrap();
    assert!(details.contains("unrelated.example.net"));
    assert!(details.contains("extra.example.org"));
    let machine: serde_json::Value = serde_json::from_str(
        &super::super::render::show(
            &[request],
            crate::common::session::Format::plain(true),
            false,
            super::super::render::DetailView::InUse,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(machine[0]["in_use"], true);
    assert_eq!(machine[0]["identifiers"].as_array().unwrap().len(), 5);
}

#[test]
fn managed_inventory_and_default_show_prefer_in_use_without_scheduling_history() {
    let mut old = record('a', "2026-01-01T00:00:00Z");
    old.phase = aster_acme_core::workflow::IssuancePhase::Completed;
    let mut in_use = old.clone();
    in_use.operation_id = "b".repeat(43);
    in_use.is_in_use = true;
    let pending = record('c', "2026-03-01T00:00:00Z");
    let records = vec![pending.clone(), old.clone(), in_use.clone()];
    let grouped = super::managed_records(records.clone()).unwrap();
    assert_eq!(grouped.len(), 1);
    assert_eq!(grouped[0].operation_id, in_use.operation_id);
    let name = in_use.name.clone();
    assert_eq!(
        super::choose(
            records.clone(),
            &name,
            None,
            super::RequestSelection::InUse,
            &crate::common::session::OutputSession::new(true)
        )
        .unwrap()
        .operation_id,
        in_use.operation_id
    );
    assert_eq!(
        super::choose(
            records,
            &name,
            None,
            super::RequestSelection::Unfinished,
            &crate::common::session::OutputSession::new(true)
        )
        .unwrap()
        .operation_id,
        pending.operation_id
    );
    assert!(
        super::choose(
            vec![old.clone()],
            &name,
            None,
            super::RequestSelection::InUse,
            &crate::common::session::OutputSession::new(true)
        )
        .is_err()
    );
    assert_eq!(
        super::choose(
            vec![old.clone()],
            &name,
            Some(&old.operation_id),
            super::RequestSelection::InUse,
            &crate::common::session::OutputSession::new(true)
        )
        .unwrap()
        .operation_id,
        old.operation_id
    );
    assert_eq!(
        super::choose(
            vec![old, pending.clone()],
            &name,
            None,
            super::RequestSelection::InUse,
            &crate::common::session::OutputSession::new(true)
        )
        .unwrap()
        .operation_id,
        pending.operation_id
    );
    let mut duplicate = in_use.clone();
    duplicate.operation_id = "d".repeat(43);
    assert!(super::managed_records(vec![in_use, duplicate]).is_err());
}

#[test]
fn historical_list_and_show_are_explicit_and_do_not_conflict_with_exact_operation() {
    assert!(Args::try_parse_from(["aster-acme", "cert", "list", "--history"]).is_ok());
    assert!(
        Args::try_parse_from(["aster-acme", "cert", "show", "example.com", "--history"]).is_ok()
    );
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "show",
            "--history",
            "--operation",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ])
        .is_err()
    );
}

#[test]
fn stored_csr_rejection_stays_visible_even_when_order_observation_later_becomes_valid() {
    use aster_acme_protocol::problem::{Problem, ProblemKind};
    let mut request = record('a', "2026-01-01T00:00:00Z");
    request.finalize_rejection = Some(Problem {
        kind: ProblemKind::BadCsr,
        detail: Some("ECDSA curve P-521 not allowed".into()),
        instance: None,
        subproblems: vec![],
        extensions: serde_json::Map::new(),
    });
    let text = super::super::render::show(
        std::slice::from_ref(&request),
        crate::common::session::Format::plain(false),
        true,
        super::super::render::DetailView::InUse,
    )
    .unwrap();
    assert!(text.contains("CSR rejected"));
    assert!(text.contains("ECDSA curve P-521 not allowed"));
    assert!(super::choice_label(&request).contains("CSR rejected"));
    let json: serde_json::Value = serde_json::from_str(
        &super::super::render::show(
            &[request],
            crate::common::session::Format::plain(true),
            true,
            super::super::render::DetailView::InUse,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        json[0]["finalize_rejection"]["type"],
        "urn:ietf:params:acme:error:badCSR"
    );
}

#[test]
fn selected_version_details_show_in_use_only_when_explicitly_requested() {
    let mut saved = record('a', "2026-01-01T00:00:00Z");
    for selected in [false, true] {
        saved.is_in_use = selected;
        let ordinary = super::super::render::show(
            std::slice::from_ref(&saved),
            crate::common::session::Format::plain(false),
            false,
            super::super::render::DetailView::InUse,
        )
        .unwrap();
        assert!(!ordinary.contains("In use:"));
        let history = super::super::render::show(
            std::slice::from_ref(&saved),
            crate::common::session::Format::plain(false),
            false,
            super::super::render::DetailView::Version,
        )
        .unwrap();
        let normalized = history.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalized.contains(if selected {
            "In use: yes"
        } else {
            "In use: no"
        }));
    }
}
