//! Deployment command stage.

use crate::commands::account::args::AccountArgs;
use crate::commands::cert::deployment::automatic::run_selected;
use crate::commands::cert::deployment::configuration::{
    binding_id, complete_add, definition, remove_id, select_certificate, select_targets, update,
};
use crate::commands::cert::deployment::execution::Execution;
use crate::commands::cert::deployment::publication::run_target;
use crate::commands::cert::{
    args::deployment::{DeployArgs, DeployCommand},
    progress::Progress,
    report::DeploymentReport,
};
use crate::common::{context::CliSettings, error::CliResult};
use aster_acme::deployment::DeploymentIntent;
use aster_acme_cli_storage::issuance::CliIssueStore;
use std::time::Duration;

pub(in crate::commands::cert) async fn execute(
    args: DeployArgs,
    cli: &crate::common::context::CommandContext,
    cancellation: tokio_util::sync::CancellationToken,
) -> CliResult<crate::commands::cert::report::CertificateReport> {
    let _signal = crate::common::signal::InterruptGuard::new(cancellation.clone());
    // Never drop the command future while publication owns a blocking task.
    // Cancellation is propagated to the shared execution boundaries instead.
    let execution = Execution {
        cancellation,
        deadline: None,
    };
    execute_inner(args, cli, &execution).await
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep deployment subcommand dispatch together"
)]
pub(super) async fn execute_inner(
    args: DeployArgs,
    cli: &crate::common::context::CommandContext,
    execution: &Execution,
) -> CliResult<crate::commands::cert::report::CertificateReport> {
    let options: AccountArgs = args.local().clone().into();
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir, Duration::from_secs(5));
    let managing = matches!(
        args.command,
        DeployCommand::List(_)
            | DeployCommand::Show(_)
            | DeployCommand::Remove(_)
            | DeployCommand::Update(_)
    );
    let name = select_certificate(&store, args.name(), managing, &cli.output).await?;
    execution.check()?;
    let progress = Progress::new(cli.output.clone());
    let mut execution_events = Vec::new();
    let (entries, attempted) = match args.command {
        DeployCommand::List(_) => (store.deployments(&name).await?, false),
        DeployCommand::Show(args) => {
            let id = if let Some(id) = args.deployment {
                id
            } else {
                let bindings = store.deployments(&name).await?;
                binding_id(&bindings, "inspect", &cli.output)?
            };
            let binding = store.deployment(&name, &id).await?;
            return Ok(
                crate::commands::cert::report::CertificateReport::DeploymentDetails {
                    name: name.as_str().into(),
                    binding: Box::new(binding),
                },
            );
        }
        DeployCommand::Remove(args) => {
            let definitions = store.deployments(&name).await?;
            let id = remove_id(args.id, &definitions, &cli.output)?;
            store.remove_deployment(&name, &id).await?;
            return Ok(
                crate::commands::cert::report::CertificateReport::DeploymentRemoved {
                    name: name.as_str().into(),
                    id,
                },
            );
        }
        DeployCommand::Update(args) => {
            let binding = update(&store, &name, args, &cli.output).await?;
            return Ok(
                crate::commands::cert::report::CertificateReport::DeploymentUpdated {
                    name: name.as_str().into(),
                    binding: Box::new(binding),
                },
            );
        }
        DeployCommand::Add(mut args) => {
            complete_add(&store, &name, &mut args, &cli.output).await?;
            let definition = definition(args)?;
            execution.check()?;
            let configured = store.add_deployment(&name, definition).await?;
            let execution = run_target(
                &store,
                &name,
                &configured,
                DeploymentIntent::Explicit,
                Some(&progress),
                Some(execution),
                None,
            )
            .await;
            execution_events.extend(execution.events);
            (vec![execution.binding], true)
        }
        DeployCommand::Run(args) => {
            let definitions = store.deployments(&name).await?;
            let selected = select_targets(definitions, args.id.as_deref())?;
            if selected.is_empty() {
                return Err(
                    "No deployment targets are configured. Use cert deploy add to configure one."
                        .into(),
                );
            }
            let entries = run_selected(
                &store,
                &name,
                selected,
                &progress,
                execution,
                &mut execution_events,
                None,
            )
            .await;
            (entries, true)
        }
    };
    Ok(
        crate::commands::cert::report::CertificateReport::Deployment(DeploymentReport {
            name: name.as_str().into(),
            entries,
            events: execution_events,
            attempted,
        }),
    )
}
