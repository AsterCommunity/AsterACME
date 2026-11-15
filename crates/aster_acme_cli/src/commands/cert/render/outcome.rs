//! Outcome report presentation; no side effects.

use crate::commands::cert::render::deployment;
use crate::commands::cert::render::deployment::{
    DeploymentStatusView, current_error, deployment_table,
};
use crate::commands::cert::render::details::renewal_lines;
use crate::commands::cert::render::materials::requirement_lines;
use crate::commands::cert::report::CertificateResult;
use crate::common::error::CliResult;
use crate::common::output;
use crate::common::session::Format;
use aster_acme::issuance::{IssueOutcome, IssueRecord, ValidationRequirement};
use serde::Serialize;

/// A result cannot simultaneously expose pending instructions and completed artifacts.
#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(in crate::commands::cert::render) enum ResultOutput<'a> {
    ActionRequired {
        operation: &'a IssueRecord,
        records: &'a [ValidationRequirement],
        resume: String,
    },
    Completed {
        operation: &'a IssueRecord,
        records: &'a [ValidationRequirement],
        artifacts: ArtifactPaths,
        deployments: Vec<DeploymentStatusView<'a>>,
        deployment_events: &'a [crate::commands::cert::report::DeploymentEvent],
    },
    NotDue {
        operation: &'a IssueRecord,
    },
}

#[derive(Serialize)]
pub(in crate::commands::cert::render) struct ArtifactPaths {
    fullchain: std::path::PathBuf,
    certificate: std::path::PathBuf,
    ca_chain: std::path::PathBuf,
    private_key: std::path::PathBuf,
}

pub(in crate::commands::cert::render) fn artifact_lines(paths: &ArtifactPaths) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "  Full chain: {}",
        output::safe(&paths.fullchain.display().to_string())
    ));
    lines.push(format!(
        "  Certificate: {}",
        output::safe(&paths.certificate.display().to_string())
    ));
    lines.push(format!(
        "  CA chain: {}",
        output::safe(&paths.ca_chain.display().to_string())
    ));
    lines.push(format!(
        "  Private key: {}",
        output::safe(&paths.private_key.display().to_string())
    ));
    lines
}

pub(in crate::commands::cert) fn result(
    result: &CertificateResult,
    format: Format,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    match result {
        CertificateResult::Issuance(issued) => outcome(issued, format, data_dir),
        CertificateResult::Issued {
            outcome: issued,
            deployments,
            deployment_events,
        } => issued_result(issued, deployments, deployment_events, format, data_dir),
        CertificateResult::NotDue(record) => not_due(record, format),
    }
}

pub(in crate::commands::cert::render) fn issued_result(
    issued: &IssueOutcome,
    deployments: &[aster_acme_cli_storage::issuance::DeploymentBinding],
    deployment_events: &[crate::commands::cert::report::DeploymentEvent],
    format: Format,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    if format.json {
        return Ok(serde_json::to_string_pretty(
            &ResultOutput::from_outcome(issued, data_dir, deployments)
                .with_events(deployment_events),
        )?);
    }
    let text = outcome(issued, format, data_dir)?;
    if deployments.is_empty() && deployment_events.is_empty() {
        return Ok(text);
    }
    let mut lines = vec![text, String::new()];
    lines.extend(
        deployment_events
            .iter()
            .map(|event| deployment::event(event, format.color)),
    );
    if !deployments.is_empty() {
        lines.push(String::new());
        let name = match issued {
            IssueOutcome::Completed { record, .. }
            | IssueOutcome::ActionRequired { record, .. } => record.name.as_str(),
        };
        lines.push(deployment_table(
            name,
            deployments,
            true,
            deployment_events,
            format,
        ));
    }
    Ok(lines.join("\n"))
}

// One typed conversion shared by single results and batch JSON; no parsing rendered JSON.
pub(in crate::commands::cert::render) fn result_output<'a>(
    result: &'a CertificateResult,
    data_dir: &std::path::Path,
) -> ResultOutput<'a> {
    match result {
        CertificateResult::NotDue(record) => ResultOutput::NotDue { operation: record },
        CertificateResult::Issuance(outcome) => ResultOutput::from_outcome(outcome, data_dir, &[]),
        CertificateResult::Issued {
            outcome,
            deployments,
            deployment_events,
        } => ResultOutput::from_outcome(outcome, data_dir, deployments)
            .with_events(deployment_events),
    }
}

impl<'a> ResultOutput<'a> {
    fn with_events(mut self, events: &'a [crate::commands::cert::report::DeploymentEvent]) -> Self {
        if let Self::Completed {
            deployment_events,
            deployments,
            ..
        } = &mut self
        {
            *deployment_events = events;
            for binding in deployments {
                binding.execution_error = current_error(events, binding.id);
            }
        }
        self
    }

    fn from_outcome(
        outcome: &'a IssueOutcome,
        data_dir: &std::path::Path,
        deployments: &'a [aster_acme_cli_storage::issuance::DeploymentBinding],
    ) -> Self {
        match outcome {
            IssueOutcome::ActionRequired { record, records } => Self::ActionRequired {
                operation: record,
                records,
                resume: format!(
                    "aster-acme cert issue --resume '{}' --operation {}",
                    record.name.as_str(),
                    record.operation_id
                ),
            },
            IssueOutcome::Completed { record, cleanup } => {
                let generation = data_dir
                    .join("certs")
                    .join(record.name.as_str())
                    .join("in_use");
                Self::Completed {
                    operation: record,
                    records: cleanup,
                    deployments: deployments.iter().map(DeploymentStatusView::from).collect(),
                    deployment_events: &[],
                    artifacts: ArtifactPaths {
                        fullchain: generation.join("fullchain.pem"),
                        certificate: generation.join("cert.pem"),
                        ca_chain: generation.join("ca.pem"),
                        private_key: generation.join("private-key.pem"),
                    },
                }
            }
        }
    }
}
pub(in crate::commands::cert) fn outcome(
    outcome: &IssueOutcome,
    format: Format,
    data_dir: &std::path::Path,
) -> CliResult<String> {
    let (record, records) = match outcome {
        IssueOutcome::ActionRequired { record, records } => (record.as_ref(), records.as_slice()),
        IssueOutcome::Completed { record, cleanup } => (record.as_ref(), cleanup.as_slice()),
    };
    let result = ResultOutput::from_outcome(outcome, data_dir, &[]);
    if format.json {
        return Ok(serde_json::to_string_pretty(&result)?);
    }
    let color = format.color;
    let (kind, message) = match outcome {
        IssueOutcome::ActionRequired { .. } => {
            (output::MessageKind::Warning, "Action required for")
        }
        IssueOutcome::Completed { record, .. } => match &record.renewal_of {
            Some(_) => (output::MessageKind::Done, "Renewed certificate"),
            None => (output::MessageKind::Done, "Issued certificate"),
        },
    };
    let mut lines = vec![format!(
        "{} {message} {}",
        kind.badge(color),
        output::safe(record.name.as_str())
    )];
    lines.push(format!("  Request: {}", record.operation_id));
    if let ResultOutput::Completed { artifacts, .. } = &result {
        lines.extend(artifact_lines(artifacts));
    }
    if let IssueOutcome::Completed { .. } = outcome {
        lines.extend(renewal_lines(
            record,
            time::OffsetDateTime::now_utc(),
            color,
        ));
        let retained = record.retained_validation_requirements();
        if !retained.is_empty() {
            lines.push("Retain these persistent validation requirements for renewal; remove publication only to revoke future validation:".into());
            lines.extend(requirement_lines(&retained));
        }
    }
    if !records.is_empty() {
        lines.push(
            match outcome {
                IssueOutcome::ActionRequired { .. } => {
                    "Publish every validation requirement below; retain unrelated files and records:"
                }
                IssueOutcome::Completed { .. } => {
                    "Validation finished. You may remove these specific saved manual validation values/files:"
                }
            }
            .into(),
        );
        lines.extend(
            requirement_lines(records)
                .into_iter()
                .map(|line| format!("  {line}")),
        );
    }
    if let IssueOutcome::ActionRequired { .. } = outcome {
        lines.push(format!(
            "To resume, run:\n  aster-acme cert issue --resume '{}'",
            record.name.as_str()
        ));
    }
    Ok(lines.join("\n"))
}

pub(in crate::commands::cert) fn not_due(
    record: &IssueRecord,
    format: Format,
) -> CliResult<String> {
    if format.json {
        return Ok(serde_json::to_string_pretty(&ResultOutput::NotDue {
            operation: record,
        })?);
    }
    let color = format.color;
    let mut lines = vec![format!(
        "{} Certificate {} is not due for renewal.",
        crate::common::output::MessageKind::Info.badge(color),
        output::safe(record.name.as_str())
    )];
    lines.extend(renewal_lines(
        record,
        time::OffsetDateTime::now_utc(),
        color,
    ));
    lines.push(output::tips(
        "Use cert renew <NAME> --now to renew early.",
        color,
    ));
    Ok(lines.join("\n"))
}
