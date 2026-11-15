//! Byte-for-byte report and exit-status fixtures captured from revision 26ef130.

use crate::commands::cert::render::tests::detailed_record;
use crate::commands::cert::render::{self, inspection::DetailView};
use crate::commands::cert::report::{
    CertificateReport, CertificateResult, DeploymentEvent, DeploymentReport, RenewalBatch,
    RenewalEntry, RenewalResult, SkipReason,
};
use crate::common::{output::MessageKind, session::Format};
use aster_acme::issuance::IssueOutcome;
use aster_acme_cli_storage::issuance::{
    DeploymentBinding, DeploymentPermissions, DeploymentTarget, removal::RemovalScope,
};
use aster_acme_core::revocation::RevocationState;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "One baseline matrix covers every certificate report in text, color and JSON"
)]
fn certificate_reports_match_pre_split_bytes_and_exit_statuses() {
    let record = detailed_record();
    let binding = DeploymentBinding {
        permissions: DeploymentPermissions::default(),
        id: "nginx".into(),
        target: DeploymentTarget::Directory {
            path: "/certificates".into(),
        },
        reload_command: vec!["reload-service".into()],
        timeout_seconds: 30,
        max_retries: 3,
        generation: Some(record.generation_name()),
        pending_generation: None,
        phase: aster_acme::deployment::DeploymentPhase::Deployed,
        attempts: 1,
        retry_failures: 0,
        retry_at: None,
        last_error: None,
    };
    let event = DeploymentEvent {
        deployment: Some("nginx".into()),
        kind: MessageKind::Success,
        message: "Reload succeeded\nservice is ready".into(),
        at: record.created_at,
    };
    let completed = || IssueOutcome::Completed {
        record: Box::new(record.clone()),
        cleanup: vec![],
    };
    let mut revoked = record.clone();
    revoked.revocation.state = RevocationState::Confirmed;
    let mut reports = vec![
        ("list", CertificateReport::List(vec![record.clone()])),
        ("empty-list", CertificateReport::List(vec![])),
        (
            "show",
            CertificateReport::Show {
                record: Box::new(record.clone()),
                verified: false,
                view: DetailView::InUse,
            },
        ),
        (
            "verified-version",
            CertificateReport::Show {
                record: Box::new(record.clone()),
                verified: true,
                view: DetailView::Version,
            },
        ),
        (
            "completed",
            CertificateReport::Result {
                result: CertificateResult::Issuance(completed()),
                data_dir: "/data".into(),
            },
        ),
        (
            "not-due",
            CertificateReport::Result {
                result: CertificateResult::NotDue(Box::new(record.clone())),
                data_dir: "/data".into(),
            },
        ),
        (
            "action-required",
            CertificateReport::Result {
                result: CertificateResult::Issuance(IssueOutcome::ActionRequired {
                    record: Box::new(record.clone()),
                    records: vec![aster_acme::issuance::ValidationRequirement::Dns01 {
                        name: "_acme-challenge.example.com".into(),
                        value: "txt-value".into(),
                    }],
                }),
                data_dir: "/data".into(),
            },
        ),
        (
            "issued-deployed",
            CertificateReport::Result {
                result: CertificateResult::Issued {
                    outcome: completed(),
                    deployments: vec![binding.clone()],
                    deployment_events: vec![event.clone()],
                },
                data_dir: "/data".into(),
            },
        ),
        (
            "deployment",
            CertificateReport::Deployment(DeploymentReport {
                name: "example.com".into(),
                entries: vec![binding.clone()],
                events: vec![event.clone()],
                attempted: true,
            }),
        ),
        (
            "deployment-details",
            CertificateReport::DeploymentDetails {
                name: "example.com".into(),
                binding: Box::new(binding.clone()),
            },
        ),
        (
            "deployment-updated",
            CertificateReport::DeploymentUpdated {
                name: "example.com".into(),
                binding: Box::new(binding.clone()),
            },
        ),
        (
            "deployment-removed",
            CertificateReport::DeploymentRemoved {
                name: "example.com".into(),
                id: "nginx".into(),
            },
        ),
        ("revoked", CertificateReport::Revoked(Box::new(revoked))),
    ];
    for (label, scope) in [
        (
            "removed-request",
            RemovalScope::Operation("operation".into()),
        ),
        ("removed-history", RemovalScope::History),
        ("removed-all", RemovalScope::All),
        ("removed-revoked", RemovalScope::Revoked),
        ("removed-failed", RemovalScope::Failed),
    ] {
        reports.push((
            label,
            CertificateReport::Removed {
                name: "example.com".into(),
                scope,
                ids: vec!["operation".into()],
                in_use_removed: true,
            },
        ));
    }
    let batch = RenewalBatch {
        entries: vec![
            RenewalEntry {
                name: "completed".into(),
                result: RenewalResult::Outcome(CertificateResult::Issuance(completed())),
            },
            RenewalEntry {
                name: "skipped".into(),
                result: RenewalResult::Skipped(SkipReason::ManualValidation),
            },
            RenewalEntry {
                name: "failed".into(),
                result: RenewalResult::Failed {
                    message: "request failed\ninspect state".into(),
                    hint: Some("retry explicitly".into()),
                },
            },
            RenewalEntry {
                name: "cancelled".into(),
                result: RenewalResult::Cancelled,
            },
        ],
        ..RenewalBatch::empty()
    };
    reports.push((
        "batch",
        CertificateReport::Batch {
            report: batch,
            data_dir: "/data".into(),
        },
    ));
    let mut captured = std::collections::BTreeMap::new();
    for (label, report) in reports {
        for (mode, format) in [
            ("text", Format::plain(false)),
            ("json", Format::plain(true)),
            (
                "color",
                Format {
                    json: false,
                    color: true,
                },
            ),
        ] {
            let text = render::render(&report, format).unwrap();
            captured.insert(format!("{label}/{mode}"), serde_json::json!({ "output": text, "exit_status": format!("{:?}", report.exit_status()) }));
        }
    }
    let actual = serde_json::to_string_pretty(&captured).unwrap();
    assert_eq!(actual, platform_snapshot());
}

fn platform_snapshot() -> String {
    let snapshot = include_str!("snapshots/cert-reports.json");
    if cfg!(not(windows)) {
        return snapshot.into();
    }
    // Only platform path separators differ in the pre-split Windows output.
    // Adapt expected paths, keeping the actual rendered bytes untouched.
    let mut expected: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(snapshot).unwrap();
    for (label, entry) in &mut expected {
        let output = entry["output"].as_str().unwrap();
        let mut output = output.to_owned();
        for file in ["fullchain.pem", "cert.pem", "ca.pem", "private-key.pem"] {
            let original = format!("/data/certs/example.com/in_use/{file}");
            let native = std::path::Path::new("/data")
                .join("certs")
                .join("example.com")
                .join("in_use")
                .join(file);
            if label.ends_with("/json") {
                output = output.replace(
                    &serde_json::to_string(&original).unwrap(),
                    &serde_json::to_string(&native).unwrap(),
                );
            } else {
                output = output.replace(&original, &native.display().to_string());
            }
        }
        for file in ["cert.pem", "private-key.pem", "ca.pem", "fullchain.pem"] {
            let original = format!("/certificates/{file}");
            let native = std::path::Path::new("/certificates").join(file);
            output = output.replace(&original, &native.display().to_string());
        }
        if !label.ends_with("/json") {
            output = output
                .replace("0600 (default)", "platform inherited permissions")
                .replace("0644", "platform inherited permissions");
        }
        entry["output"] = output.into();
    }
    serde_json::to_string_pretty(&expected).unwrap()
}
