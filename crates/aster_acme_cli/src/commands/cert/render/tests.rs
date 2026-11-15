//! Render regression tests.

use crate::commands::cert::render::batch::batch;
use crate::commands::cert::render::deployment::{DeploymentStatusView, deployment_report};
use crate::commands::cert::render::inspection::{
    DetailView, list, local_status_style, order_status_style, show, show_text,
};
use crate::commands::cert::render::lifecycle::{removed, revoked};
use crate::commands::cert::render::outcome::{issued_result, not_due, outcome};
use crate::commands::cert::render::*;
use crate::commands::cert::report::{CertificateResult, RenewalBatch};
use crate::common::output;
use crate::common::output::Style;
use crate::common::session::Format;
use aster_acme::issuance::{IssueOutcome, IssueRecord, ValidationRequirement};
use aster_acme_core::revocation::RevocationState;

mod contract;

#[test]
fn deployment_list_empty_and_json_match_other_local_lists() {
    let report = crate::commands::cert::report::DeploymentReport {
        events: Vec::new(),
        name: "web".into(),
        entries: Vec::new(),
        attempted: false,
    };
    let text = deployment_report(&report, Format::plain(false)).unwrap();
    assert!(text.starts_with("No deployment targets configured for web."));
    assert!(!text.contains("GENERATION"));
    assert!(text.contains("Tips:"));
    assert!(!text.contains('\x1b'));
    let json: serde_json::Value =
        serde_json::from_str(&deployment_report(&report, Format::plain(true)).unwrap()).unwrap();
    assert_eq!(json["certificate"], "web");
    assert_eq!(json["deployments"], serde_json::json!([]));
}

#[test]
fn deployment_list_uses_shared_alignment_and_semantic_styles_for_every_phase() {
    use aster_acme::deployment::DeploymentPhase;
    use aster_acme_cli_storage::issuance::{DeploymentBinding, DeploymentTarget};
    let phases = [
        DeploymentPhase::Configured,
        DeploymentPhase::Publishing,
        DeploymentPhase::PublishFailed,
        DeploymentPhase::PublicationComplete,
        DeploymentPhase::Reloading,
        DeploymentPhase::ReloadFailed,
        DeploymentPhase::ReloadUncertain,
        DeploymentPhase::Deployed,
    ];
    let mut report = crate::commands::cert::report::DeploymentReport {
        events: Vec::new(),
        name: "web\n".into(),
        entries: phases
            .iter()
            .enumerate()
            .map(|(index, phase)| DeploymentBinding {
                permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
                id: format!("target-{index}"),
                target: DeploymentTarget::Directory {
                    path: "/tmp".into(),
                },
                reload_command: vec!["secret-command".into()],
                timeout_seconds: 30,
                max_retries: 0,
                generation: None,
                pending_generation: None,
                phase: *phase,
                attempts: 0,
                retry_failures: 0,
                retry_at: None,
                last_error: Some("error\nvalue".into()),
            })
            .collect(),
        attempted: false,
    };
    report.entries[0].phase = DeploymentPhase::Deployed;
    report.entries[0].generation = Some("generation-old".into());
    report.entries[0].pending_generation = Some("generation-next".into());
    let plain = deployment_report(&report, Format::plain(false)).unwrap();
    let colored = deployment_report(
        &report,
        Format {
            json: false,
            color: true,
        },
    )
    .unwrap();
    assert!(plain.starts_with("Local deployments for web\\n (saved execution status):"));
    assert!(plain.contains("reload unconfirmed"));
    assert!(plain.contains("pending deployment"));
    assert!(plain.contains("error\\nvalue"));
    assert!(!plain.contains("secret-command"));
    assert!(colored.contains("\x1b[1;36mDEPLOYMENT"));
    assert!(colored.contains("\x1b[31mreload failed"));
    assert!(colored.contains("\x1b[32mdeployed"));
    assert!(colored.contains("\x1b[33mpending deployment"));
    let header = plain.lines().nth(1).unwrap();
    for line in plain
        .lines()
        .skip(2)
        .filter(|line| !line.starts_with("Tips:"))
    {
        use unicode_width::UnicodeWidthStr as _;
        assert_eq!(
            line[..line.find("error\\nvalue").unwrap()].width(),
            header[..header.find("ERROR").unwrap()].width()
        );
    }
}

fn detailed_record() -> IssueRecord {
    let record:IssueRecord=serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p256","challenge":"dns-01","solver_config":{},"solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"example.com",
            "created_at":"2026-01-01T00:00:00.123456Z","account_name":"default","account_id":"id","account_thumbprint":"key",
            "directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],
            "phase":"completed","new_order_intent_saved":true,"order_url":"https://ca.example/order","finalize_submitted":"submitted",
            "order":{"status":"valid","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[],"finalize":"https://ca.example/finalize"},
            "authorizations":[]
        })).unwrap();
    let mut record = record;
    record.is_in_use = true;
    record.renewal = Some(serde_json::from_value(serde_json::json!({
            "certificate_id":"a.b","not_before":"2026-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z",
            "renew_at":"2026-02-01T00:00:00Z","source":"fallback","suggested_window":null,"explanation_url":null,
            "last_checked_at":null,"next_check_at":null,"last_query_failed":false
        })).unwrap());
    record
}

#[test]
fn details_style_statuses_and_keep_human_times_fixed_without_altering_json() {
    let record = detailed_record();
    let colored = show_text(&record, time::OffsetDateTime::now_utc(), true, false);
    assert!(colored.contains("\x1b[32mcompleted\x1b[0m"));
    assert!(colored.contains("\x1b[32mvalid\x1b[0m"));
    assert!(colored.contains("2026-01-01 00:00:00 UTC"));
    assert!(!colored.contains(".123456"));
    let plain = show_text(&record, time::OffsetDateTime::now_utc(), false, false);
    assert!(plain.contains("Key type:"));
    assert!(plain.contains("ecdsa-p256"));
    assert!(
        list(
            std::slice::from_ref(&record),
            crate::common::session::Format::plain(false)
        )
        .unwrap()
        .contains("KEY TYPE")
    );
    assert!(!plain.contains('\x1b'));
    assert!(plain.contains("Next renewal:"));
    assert!(plain.contains("2026-02-01 00:00:00 UTC"));
    assert!(plain.contains("fallback (randomized before validity threshold)"));
    assert!(
        list(
            std::slice::from_ref(&record),
            crate::common::session::Format::plain(false)
        )
        .unwrap()
        .contains("NEXT RENEWAL (UTC)")
    );
    let machine = show(
        std::slice::from_ref(&record),
        crate::common::session::Format::plain(true),
        false,
        DetailView::InUse,
    )
    .unwrap();
    assert!(machine.contains("2026-01-01T00:00:00.123456Z"));
    assert!(!machine.contains('\x1b'));
    let result = IssueOutcome::Completed {
        record: Box::new(record),
        cleanup: vec![],
    };
    let human = outcome(
        &result,
        crate::common::session::Format::plain(false),
        std::path::Path::new("/data"),
    )
    .unwrap();
    assert!(human.contains("Next renewal:"));
    assert!(human.contains("2026-02-01 00:00:00 UTC"));
    assert!(human.find("Private key:").unwrap() < human.find("Next renewal:").unwrap());
    let output = outcome(
        &result,
        crate::common::session::Format::plain(true),
        std::path::Path::new("/data"),
    )
    .unwrap();
    let fields: serde_json::Value = serde_json::from_str(&output).unwrap();
    for (key, file) in [
        ("fullchain", "fullchain.pem"),
        ("certificate", "cert.pem"),
        ("ca_chain", "ca.pem"),
        ("private_key", "private-key.pem"),
    ] {
        assert_eq!(
            fields["artifacts"][key],
            std::path::Path::new("/data")
                .join("certs")
                .join("example.com")
                .join("in_use")
                .join(file)
                .to_string_lossy()
                .as_ref()
        );
    }
}

#[test]
fn revoked_and_pending_records_suspend_scheduling_without_claiming_fresh_verification() {
    let record = Box::new(detailed_record());
    for state in [RevocationState::Pending, RevocationState::Confirmed] {
        let mut record = record.as_ref().clone();
        record.revocation.state = state;
        let human = show_text(&record, time::OffsetDateTime::now_utc(), false, false);
        assert!(human.contains(match state {
            RevocationState::Pending => "suspended (revocation unconfirmed)",
            RevocationState::Confirmed => "disabled (revoked)",
            RevocationState::NotRequested => unreachable!(),
        }));
        assert!(!human.contains("2026-02-01 00:00:00 UTC"));
        let json: serde_json::Value = serde_json::from_str(
            &show(
                std::slice::from_ref(&record),
                crate::common::session::Format::plain(true),
                false,
                DetailView::InUse,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json[0]["renewal_due"], false);
        if matches!(state, RevocationState::Confirmed) {
            assert!(
                revoked(&record, crate::common::session::Format::plain(false))
                    .unwrap()
                    .contains("Next renewal:")
            );
            assert!(
                revoked(&record, crate::common::session::Format::plain(false))
                    .unwrap()
                    .contains("disabled (revoked)")
            );
        }
    }
}

#[test]
fn local_deletion_output_does_not_assert_a_remote_certificate_status() {
    let machine: serde_json::Value = serde_json::from_str(
        &removed(
            "example.com",
            &aster_acme_cli_storage::issuance::removal::RemovalScope::All,
            &["a".into(), "b".into(), "c".into()],
            true,
            crate::common::session::Format::plain(true),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(machine["removed_locally"], true);
    assert_eq!(machine["generations"], 3);
    assert_eq!(machine["ca_request_performed"], false);
    assert!(machine.get("ca_revoked").is_none());
    let human = removed(
        "example.com",
        &aster_acme_cli_storage::issuance::removal::RemovalScope::All,
        &["a".into(), "b".into(), "c".into()],
        true,
        crate::common::session::Format::plain(false),
    )
    .unwrap();
    assert!(human.contains("Removed all local certificate requests for example.com."));
    assert!(!human.contains("Revoked"));
}
#[test]
fn rejected_csr_local_failure_keeps_ready_order_status_and_distinct_colors() {
    use aster_acme_protocol::problem::{Problem, ProblemKind};
    let mut record:IssueRecord=serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p521","challenge":"dns-01","solver_config":{},"solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"example.com",
            "created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"id","account_thumbprint":"key",
            "directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],
            "phase":"finalizing","new_order_intent_saved":true,"order_url":"https://ca.example/order","finalize_submitted":"submitted",
            "order":{"status":"ready","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[],"finalize":"https://ca.example/finalize"},"authorizations":[]
        })).unwrap();
    record.finalize_rejection = Some(aster_acme::issuance::RequestFailure {
        status: 400,
        retry_at: None,
        problem: Some(Problem {
            kind: ProblemKind::BadCsr,
            detail: Some("P-521 not allowed".into()),
            instance: None,
            subproblems: vec![],
            extensions: serde_json::Map::new(),
        }),
    });
    let now = time::OffsetDateTime::now_utc();
    assert_eq!(request_status(&record, now), "failed (CSR rejected)");
    assert_eq!(local_status_style(&record, now), Style::Red);
    assert_eq!(
        order_status_style(record.order.as_ref().map(|order| &order.status)),
        Style::Blue
    );
    let table = list(
        std::slice::from_ref(&record),
        crate::common::session::Format::plain(false),
    )
    .unwrap();
    assert!(table.contains("STATUS"));
    assert!(!table.contains("PHASE"));
    assert!(table.contains("failed (CSR rejected)"));
    assert!(table.contains("ready"));
    let details = show_text(&record, now, true, false);
    assert!(details.contains("\x1b[31mfailed (CSR rejected)\x1b[0m"));
    assert!(details.contains("\x1b[34mready\x1b[0m"));
    let json: serde_json::Value = serde_json::from_str(
        &show(
            &[record],
            crate::common::session::Format::plain(true),
            false,
            DetailView::InUse,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(json[0]["order"]["status"], "ready");
}
#[test]
fn final_output_variants_cannot_mix_manual_actions_artifacts_or_not_due_results() {
    let record:IssueRecord=serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p256","challenge":"dns-01","solver_config":{},"solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"web","created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"id","account_thumbprint":"key","directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],"phase":"authorizing","new_order_intent_saved":true,"authorizations":[],"finalize_submitted":"not_submitted"
        })).unwrap();
    let pending = IssueOutcome::ActionRequired {
        record: Box::new(record.clone()),
        records: vec![ValidationRequirement::Dns01 {
            name: "_acme-challenge.example.com".into(),
            value: "txt-value".into(),
        }],
    };
    let root = std::path::Path::new("/data");
    let json: serde_json::Value = serde_json::from_str(
        &outcome(&pending, crate::common::session::Format::plain(true), root).unwrap(),
    )
    .unwrap();
    assert_eq!(json["status"], "action_required");
    assert!(json.get("artifacts").is_none());
    assert!(
        outcome(&pending, crate::common::session::Format::plain(false), root)
            .unwrap()
            .contains("[WARN]")
    );
    assert!(
        !outcome(&pending, crate::common::session::Format::plain(false), root)
            .unwrap()
            .contains("[DONE]")
    );
    for renewal in [false, true] {
        let mut complete = record.clone();
        complete.phase = aster_acme_core::workflow::IssuancePhase::Completed;
        if renewal {
            complete.renewal_of = Some(aster_acme::issuance::RenewalPredecessor {
                retained_validation: Vec::new(),
                operation_id: "old".into(),
                certificate_id: None,
            });
        }
        let completed = IssueOutcome::Completed {
            record: Box::new(complete),
            cleanup: vec![],
        };
        let human = outcome(
            &completed,
            crate::common::session::Format::plain(false),
            root,
        )
        .unwrap();
        assert!(human.contains(if renewal {
            "Renewed certificate"
        } else {
            "Issued certificate"
        }));
        let json: serde_json::Value = serde_json::from_str(
            &outcome(
                &completed,
                crate::common::session::Format::plain(true),
                root,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["status"], "completed");
        assert!(json.get("resume").is_none());
        assert!(json.get("artifacts").is_some());
    }
    let json: serde_json::Value = serde_json::from_str(
        &not_due(&record, crate::common::session::Format::plain(true)).unwrap(),
    )
    .unwrap();
    assert_eq!(json["status"], "not_due");
    assert!(json.get("resume").is_none());
    assert!(json.get("artifacts").is_none());
    for state in [RevocationState::NotRequested, RevocationState::Pending] {
        let mut record = record.clone();
        record.revocation.state = state;
        assert!(revoked(&record, crate::common::session::Format::plain(true)).is_err());
    }
}

#[test]
fn authorizing_status_and_order_status_keep_their_own_aligned_columns_with_or_without_color() {
    let mut record = detailed_record();
    record.phase = aster_acme_core::workflow::IssuancePhase::Authorizing;
    record.order.as_mut().unwrap().status = aster_acme_core::protocol::OrderStatus::Pending;
    for color in [false, true] {
        let rendered = list(std::slice::from_ref(&record), Format { json: false, color }).unwrap();
        let plain = rendered
            .replace("\x1b[1;36m", "")
            .replace("\x1b[33m", "")
            .replace("\x1b[0m", "");
        let header = plain
            .lines()
            .find(|line| line.contains("ORDER STATUS"))
            .unwrap();
        let row = plain
            .lines()
            .find(|line| line.contains("authorizing domains"))
            .unwrap();
        assert!(row.contains("authorizing domains  "));
        assert_eq!(row.find("pending"), header.find("ORDER STATUS"));
    }
}
#[test]
fn new_order_errors_have_local_status_without_inventing_a_ca_order() {
    for (status, label) in [
        (400, "creation rejected"),
        (403, "creation rejected"),
        (409, "creation rejected"),
        (408, "creation deferred"),
        (429, "creation deferred"),
        (503, "creation unconfirmed"),
    ] {
        let mut record = detailed_record();
        record.phase = aster_acme_core::workflow::IssuancePhase::CreatingOrder;
        record.order = None;
        record.order_url = None;
        record.authorizations.clear();
        record.creation_failure = Some(aster_acme::issuance::RequestFailure {
                status, retry_at: None, problem: Some(serde_json::from_value(serde_json::json!({"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"forbidden by policy"})).unwrap()),
            });
        assert_eq!(
            request_status(&record, time::OffsetDateTime::now_utc()),
            label
        );
        for (kind, expected) in [
            (
                aster_acme_protocol::problem::ProblemKind::RateLimited,
                "creation deferred",
            ),
            (
                aster_acme_protocol::problem::ProblemKind::ServerInternal,
                "creation unconfirmed",
            ),
        ] {
            let mut atypical = record.clone();
            let failure = atypical.creation_failure.as_mut().unwrap();
            failure.status = 400;
            failure.problem.as_mut().unwrap().kind = kind;
            assert_eq!(
                request_status(&atypical, time::OffsetDateTime::now_utc()),
                expected
            );
        }
        let human = show(
            std::slice::from_ref(&record),
            crate::common::session::Format::plain(false),
            false,
            DetailView::InUse,
        )
        .unwrap();
        assert!(human.contains(label));
        assert!(human.contains("not observed"));
        assert!(human.contains("forbidden by policy"));
        assert!(human.contains("newOrder HTTP:"));
        let json: serde_json::Value = serde_json::from_str(
            &show(
                &[record],
                crate::common::session::Format::plain(true),
                false,
                DetailView::InUse,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(json[0]["order"].is_null());
        assert_eq!(json[0]["creation_failure"]["status"], status);
        assert_eq!(
            json[0]["creation_failure"]["problem"]["detail"],
            "forbidden by policy"
        );
    }
}

#[test]
fn deployment_json_status_never_serializes_reload_command_arguments() {
    let entry = aster_acme_cli_storage::issuance::DeploymentBinding {
        permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
        id: "nginx".into(),
        target: aster_acme_cli_storage::issuance::DeploymentTarget::Directory {
            path: std::path::PathBuf::from("/etc/nginx/certs"),
        },
        reload_command: vec!["systemctl".into(), "--password=secret".into()],
        timeout_seconds: 30,
        max_retries: 3,
        generation: Some("generation-1".into()),
        pending_generation: None,
        phase: aster_acme::deployment::DeploymentPhase::Deployed,
        attempts: 1,
        retry_failures: 0,
        retry_at: None,
        last_error: None,
    };
    let serialized = serde_json::to_string(&DeploymentStatusView::from(&entry)).unwrap();
    assert!(serialized.contains("generation-1"));
    assert!(!serialized.contains("systemctl"));
    assert!(!serialized.contains("secret"));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep single and batch deployment status parity in one outcome matrix"
)]
fn issued_deployment_failure_is_visible_in_single_and_batch_json_and_exit_status() {
    use crate::commands::cert::report::{CertificateReport, RenewalEntry, RenewalResult};
    use aster_acme::deployment::DeploymentPhase;
    use aster_acme_cli_storage::issuance::{DeploymentBinding, DeploymentTarget};
    for (phase, pending_generation) in [
        (DeploymentPhase::Deployed, None),
        (DeploymentPhase::ReloadFailed, None),
        (DeploymentPhase::ReloadUncertain, None),
        (DeploymentPhase::Deployed, Some("generation-next")),
    ] {
        let result_value = CertificateResult::Issued {
            deployment_events: Vec::new(),
            outcome: IssueOutcome::Completed {
                record: Box::new(detailed_record()),
                cleanup: Vec::new(),
            },
            deployments: vec![DeploymentBinding {
                permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
                id: "nginx".into(),
                target: DeploymentTarget::Directory {
                    path: "/tmp".into(),
                },
                reload_command: vec!["secret-command".into()],
                timeout_seconds: 30,
                max_retries: 0,
                generation: Some("generation".into()),
                pending_generation: pending_generation.map(str::to_owned),
                phase,
                attempts: 1,
                retry_failures: 0,
                retry_at: None,
                last_error: None,
            }],
        };
        let failed = phase != DeploymentPhase::Deployed || pending_generation.is_some();
        let report = CertificateReport::Result {
            result: result_value,
            data_dir: "/tmp".into(),
        };
        assert!(matches!(
            (report.exit_status(), failed),
            (crate::common::session::ExitStatus::Failed, true)
                | (crate::common::session::ExitStatus::Success, false)
        ));
        let text = render(&report, Format::plain(true)).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["deployments"][0]["id"], "nginx");
        assert!(!text.contains("secret-command"));
        let CertificateReport::Result { result, .. } = report else {
            panic!("expected result");
        };
        let batch_report = RenewalBatch {
            entries: vec![RenewalEntry {
                name: "web".into(),
                result: RenewalResult::Outcome(result),
            }],
            cancelled: false,
        };
        assert_eq!(batch_report.summary().failed, usize::from(failed));
        assert_eq!(batch_report.summary().completed, usize::from(!failed));
        assert_eq!(
            batch_report.disposition(),
            if failed {
                crate::commands::cert::report::BatchDisposition::PartialFailure
            } else {
                crate::commands::cert::report::BatchDisposition::Completed
            }
        );
        let json: serde_json::Value = serde_json::from_str(
            &batch(
                &batch_report,
                Format::plain(true),
                std::path::Path::new("/tmp"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            json["status"],
            if failed {
                "partial_failure"
            } else {
                "completed"
            }
        );
        assert_eq!(
            json["results"][0]["result"]["deployments"][0]["id"],
            "nginx"
        );
        let text = batch(
            &batch_report,
            Format::plain(false),
            std::path::Path::new("/tmp"),
        )
        .unwrap();
        assert!(text.contains(if failed {
            "deployment failed"
        } else {
            "completed"
        }));
        assert_eq!(
            CertificateReport::Batch {
                report: batch_report,
                data_dir: "/tmp".into(),
            }
            .exit_status(),
            if failed {
                crate::common::session::ExitStatus::Failed
            } else {
                crate::common::session::ExitStatus::Success
            }
        );
    }
}
#[test]
fn automatic_deployment_uses_same_table_and_orders_events_after_certificate_summary() {
    use crate::commands::cert::report::{DeploymentEvent, DeploymentReport};
    use aster_acme::deployment::DeploymentPhase;
    use aster_acme_cli_storage::issuance::{DeploymentBinding, DeploymentTarget};
    let record = detailed_record();
    let entry = DeploymentBinding {
        permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
        id: "nginx".into(),
        target: DeploymentTarget::Directory {
            path: "/tmp".into(),
        },
        reload_command: vec!["private-command".into()],
        timeout_seconds: 30,
        max_retries: 0,
        generation: Some("generation".into()),
        pending_generation: None,
        phase: DeploymentPhase::Deployed,
        attempts: 1,
        retry_failures: 0,
        retry_at: None,
        last_error: None,
    };
    let events = vec![DeploymentEvent {
        deployment: Some("nginx".into()),
        kind: output::MessageKind::Info,
        message: "Started deployment 'nginx'".into(),
        at: record.created_at,
    }];
    let manual = deployment_report(
        &DeploymentReport {
            events: Vec::new(),
            name: record.name.as_str().into(),
            entries: vec![entry.clone()],
            attempted: true,
        },
        Format::plain(false),
    )
    .unwrap();
    let outcome = IssueOutcome::Completed {
        record: Box::new(record),
        cleanup: Vec::new(),
    };
    let automatic = issued_result(
        &outcome,
        &[entry],
        &events,
        Format::plain(false),
        std::path::Path::new("/tmp"),
    )
    .unwrap();
    assert!(automatic.ends_with(&manual));
    assert!(automatic.contains("\n\n[2026-01-01 00:00:00 UTC] [INFO]"));
    assert!(automatic.find("[DONE]").unwrap() < automatic.find("Started deployment").unwrap());
    assert!(!automatic.contains("Deployment targets:"));
    assert!(!automatic.contains("private-command"));
}
