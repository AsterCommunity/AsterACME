//! Maintenance events retain every outcome, including deployment diagnostics.
use crate::commands::cert::render::maintenance::maintenance_log_events;
use crate::commands::cert::render::tests::detailed_record;
use crate::commands::cert::report::{
    CertificateResult, DeploymentEvent, DeploymentReport, RenewalBatch, RenewalEntry,
    RenewalResult, SkipReason,
};
use crate::common::output::MessageKind;
use aster_acme::issuance::{IssueError, IssueOutcome};
use aster_acme::maintenance::{Entry, Outcome, Report};

#[test]
fn maintenance_events_preserve_stage_order_severity_and_saved_deployment_times() {
    let record = detailed_record();
    let ari = Report {
        entries: [
            Outcome::Refreshed,
            Outcome::RetryScheduled,
            Outcome::Unavailable,
            Outcome::Skipped,
            Outcome::Failed(IssueError::InvalidInput("ARI failed")),
            Outcome::Cancelled,
            Outcome::NotStarted,
        ]
        .into_iter()
        .map(|outcome| Entry {
            name: record.name.clone(),
            operation_id: record.operation_id.clone(),
            outcome,
            renew_at: None,
            next_check_at: None,
        })
        .collect(),
        cancelled: true,
    };
    let deployment = DeploymentEvent {
        deployment: Some("service".into()),
        kind: MessageKind::Error,
        message: "reload failed; result retained".into(),
        at: record.created_at,
    };
    let completed = || IssueOutcome::Completed {
        record: Box::new(record.clone()),
        cleanup: vec![],
    };
    let outcomes = vec![
        RenewalResult::Outcome(CertificateResult::Issuance(completed())),
        RenewalResult::Outcome(CertificateResult::Issued {
            outcome: completed(),
            deployments: vec![],
            deployment_events: vec![deployment.clone()],
        }),
        RenewalResult::Outcome(CertificateResult::Issuance(IssueOutcome::ActionRequired {
            record: Box::new(record.clone()),
            records: vec![],
        })),
        RenewalResult::Outcome(CertificateResult::NotDue(Box::new(record.clone()))),
        RenewalResult::Skipped(SkipReason::ManualValidation),
        RenewalResult::Failed {
            message: "CA error".into(),
            hint: None,
        },
        RenewalResult::Cancelled,
    ];
    let renewals = RenewalBatch {
        entries: outcomes
            .into_iter()
            .map(|result| RenewalEntry {
                name: "example.com".into(),
                result,
            })
            .collect(),
        cancelled: true,
    };
    let deployments = [DeploymentReport {
        name: "example.com".into(),
        entries: vec![],
        events: vec![deployment],
        attempted: true,
    }];
    let events = maintenance_log_events(&ari, &renewals, &deployments);

    assert_eq!(events.len(), EXPECTED_EVENTS.len());
    for (event, (kind, message)) in events.iter().zip(EXPECTED_EVENTS) {
        assert_eq!(event.kind, kind);
        assert_eq!(event.message, message);
    }
    assert_eq!(events[9].at, record.created_at);
    assert_eq!(events[15].at, record.created_at);
}

const EXPECTED_EVENTS: [(MessageKind, &str); 16] = [
    (MessageKind::Success, "example.com: ARI refreshed"),
    (MessageKind::Warning, "example.com: ARI retry scheduled"),
    (MessageKind::Warning, "example.com: ARI unavailable"),
    (MessageKind::Info, "example.com: ARI refresh no longer due"),
    (MessageKind::Error, "example.com: ARI failed"),
    (MessageKind::Warning, "example.com: ARI refresh cancelled"),
    (MessageKind::Warning, "example.com: ARI refresh not started"),
    (MessageKind::Done, "Renewed certificate example.com"),
    (MessageKind::Done, "Renewed certificate example.com"),
    (
        MessageKind::Error,
        "example.com: reload failed; result retained",
    ),
    (
        MessageKind::Warning,
        "Renewal action required for example.com",
    ),
    (MessageKind::Info, "example.com: renewal is not due"),
    (
        MessageKind::Warning,
        "example.com: saved validation method requires user action; automatic renewal skipped",
    ),
    (MessageKind::Error, "example.com: CA error"),
    (MessageKind::Warning, "example.com: renewal cancelled"),
    (
        MessageKind::Error,
        "example.com: reload failed; result retained",
    ),
];
