//! Deployment automatic stage.

use crate::commands::cert::deployment::event;
use crate::commands::cert::deployment::execution::Execution;
use crate::commands::cert::deployment::publication::run_target;
use crate::commands::cert::{
    progress::Progress,
    report::{DeploymentEvent, DeploymentReport},
};
use crate::common::output::MessageKind;
use aster_acme::{
    deployment::{DeploymentIntent, DeploymentPhase},
    issuance::CertificateName,
};
use aster_acme_cli_storage::issuance::{CliIssueStore, DeploymentBinding};
use std::time::Duration;

pub(crate) async fn retry_due(
    store: &CliIssueStore,
    timeout: Duration,
    cancellation: &tokio_util::sync::CancellationToken,
    cli: &crate::common::context::CommandContext,
    records: Vec<aster_acme::issuance::IssueRecord>,
) -> Vec<DeploymentReport> {
    let now = time::OffsetDateTime::now_utc();
    let progress = Progress::new(cli.output.clone());
    let mut reports = Vec::new();
    for record in records {
        if cancellation.is_cancelled() {
            break;
        }
        let definitions = match store.deployments(&record.name).await {
            Ok(definitions) => definitions,
            Err(error) => {
                reports.push(DeploymentReport {
                    name: record.name.as_str().to_owned(),
                    entries: Vec::new(),
                    events: vec![event(
                        MessageKind::Error,
                        format!("Deployment retry state could not be read: {error}"),
                    )],
                    attempted: true,
                });
                continue;
            }
        };
        let generation = record.generation_name();
        let selected = definitions
            .into_iter()
            .filter(|binding| binding.checkpoint().due(&generation, now))
            .collect::<Vec<_>>();
        if selected.is_empty() {
            continue;
        }
        let execution = Execution {
            cancellation: cancellation.clone(),
            deadline: std::time::Instant::now().checked_add(timeout),
        };
        let mut events = Vec::new();
        let entries = run_selected(
            store,
            &record.name,
            selected,
            &progress,
            &execution,
            &mut events,
            Some(&generation),
        )
        .await;
        if entries.is_empty() && events.is_empty() {
            continue;
        }
        reports.push(DeploymentReport {
            name: record.name.as_str().to_owned(),
            entries,
            events,
            attempted: true,
        });
    }
    reports
}

pub(super) async fn run_selected(
    store: &CliIssueStore,
    name: &CertificateName,
    selected: Vec<DeploymentBinding>,
    progress: &Progress,
    execution: &Execution,
    execution_events: &mut Vec<DeploymentEvent>,
    retry_generation: Option<&str>,
) -> Vec<DeploymentBinding> {
    let mut entries = Vec::with_capacity(selected.len());
    let mut selected = selected.into_iter();
    while let Some(definition) = selected.next() {
        if execution.check().is_err() {
            execution_events.push(event(
                MessageKind::Error,
                "Deployment cancelled before next target; completed results retained.",
            ));
            entries.push(definition);
            entries.extend(selected);
            break;
        }
        let intent = match retry_generation {
            Some(generation) => DeploymentIntent::Retry {
                generation,
                snapshot: &definition,
            },
            None => DeploymentIntent::Explicit,
        };
        let execution = run_target(
            store,
            name,
            &definition,
            intent,
            Some(progress),
            Some(execution),
        )
        .await;
        if execution.attempted {
            entries.push(execution.binding);
        }
        execution_events.extend(execution.events);
    }

    entries
}

pub(in crate::commands::cert) async fn after_issuance(
    store: &CliIssueStore,
    name: &CertificateName,
    generation: &str,
    execution: &aster_acme::solver::ExecutionContext,
) -> (Vec<DeploymentBinding>, Vec<DeploymentEvent>) {
    // Do not drop automatic_inner at the operation deadline: a started blocking
    // publication continues under its lease. The worker records the final publish
    // state, then checks the deadline before starting reload or another target.
    Box::pin(automatic_inner(store, name, generation, execution)).await
}

pub(super) async fn automatic_inner(
    store: &CliIssueStore,
    name: &CertificateName,
    generation: &str,
    execution: &aster_acme::solver::ExecutionContext,
) -> (Vec<DeploymentBinding>, Vec<DeploymentEvent>) {
    let execution = Execution::from(execution);
    let definitions = match store.deployments(name).await {
        Ok(definitions) => definitions,
        Err(error) => {
            return (
                Vec::new(),
                vec![event(
                    MessageKind::Error,
                    format!("Certificate issued; deployment inventory could not be read: {error}"),
                )],
            );
        }
    };
    let mut result = Vec::with_capacity(definitions.len());
    let mut events = Vec::new();
    let mut definitions = definitions;
    for definition in &mut definitions {
        if definition.generation.as_deref() == Some(generation)
            || definition.pending_generation.as_deref() == Some(generation)
            || definition.phase.reload_uncertain()
        {
            continue;
        }
        match store.open_deployment(name, &definition.id).await {
            Ok(mut session) => match session.save_pending_generation(generation).await {
                Ok(()) => *definition = session.definition().clone(),
                Err(error) => events.push(event(
                    MessageKind::Error,
                    format!(
                        "Deployment '{}' intent could not be saved: {error}",
                        definition.id
                    ),
                )),
            },
            Err(error) => events.push(event(
                MessageKind::Error,
                format!(
                    "Deployment '{}' intent could not be saved: {error}",
                    definition.id
                ),
            )),
        }
    }
    let mut definitions = definitions.into_iter();
    while let Some(definition) = definitions.next() {
        if execution.check().is_err() {
            events.push(event(MessageKind::Error, "Automatic deployment stopped before the next target because issuance was cancelled or its deadline expired; committed certificate and deployment checkpoints are retained."));
            result.push(definition);
            result.extend(definitions);
            break;
        }
        let same_generation = definition.generation.as_deref() == Some(generation);
        if same_generation && definition.phase == DeploymentPhase::Deployed {
            result.push(definition);
            continue;
        }
        let target = Box::pin(run_target(
            store,
            name,
            &definition,
            DeploymentIntent::AfterIssuance { generation },
            None,
            Some(&execution),
        ))
        .await;
        events.extend(target.events);
        result.push(target.binding);
    }
    (result, events)
}
