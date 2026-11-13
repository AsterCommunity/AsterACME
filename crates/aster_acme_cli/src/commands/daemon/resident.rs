//! Foreground, serial maintenance loop. No scheduler state is duplicated in memory.
use crate::{
    commands::{
        account::args::AccountArgs,
        daemon::{DaemonReport, DaemonStopped, RunOnceArgs, execute_cycle, render},
    },
    common::{
        context::{CliSettings, CommandContext},
        error::CliResult,
        output::MessageKind,
        signal::InterruptGuard,
    },
};
use aster_acme_cli_storage::{daemon::DaemonLease, issuance::CliIssueStore};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const DEFAULT_INTERVAL: u64 = 60;

pub(super) fn interval(args: Option<u64>, config: Option<u64>) -> CliResult<Duration> {
    let seconds = args.or(config).unwrap_or(DEFAULT_INTERVAL);
    if !(1..=86400).contains(&seconds) {
        return Err("Daemon interval must be between 1 and 86400 seconds.".into());
    }
    Ok(Duration::from_secs(seconds))
}

pub(super) async fn run(
    args: RunOnceArgs,
    interval_override: Option<u64>,
    cli: &CommandContext,
) -> CliResult<DaemonStopped> {
    let settings = CliSettings::load(&AccountArgs {
        data_dir: args.local.data_dir.clone(),
        json: args.local.json,
        ..AccountArgs::default()
    })
    .await?;
    let interval = interval(interval_override, settings.config.daemon_interval)?;
    let cancellation = CancellationToken::new();
    // Register shutdown before waiting for the process lease. Acquiring a blocking
    // file lock is bounded and awaited even if shutdown arrives during that wait.
    let _signal = InterruptGuard::daemon(cancellation.clone());
    let _lease = DaemonLease::acquire(settings.data_dir.clone(), Duration::from_secs(5)).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    if !cancellation.is_cancelled() {
        render::started(&cli.output, interval, &settings.data_dir)?;
    }
    let task = MaintenanceCycle {
        args: &args,
        settings: &settings,
        store: &store,
        cli,
    };
    let statistics = run_loop(&task, interval, cli, &cancellation).await?;
    let stopped = DaemonStopped {
        cycles: statistics.cycles,
        failed_cycles: statistics.failed_cycles,
        data_dir: settings.data_dir,
    };
    render::stopped(&cli.output, &stopped)?;
    Ok(stopped)
}

#[async_trait::async_trait(?Send)]
trait Cycle {
    async fn execute(&self, cancellation: &CancellationToken) -> CliResult<DaemonReport>;
}

struct MaintenanceCycle<'a> {
    args: &'a RunOnceArgs,
    settings: &'a CliSettings,
    store: &'a CliIssueStore,
    cli: &'a CommandContext,
}

#[async_trait::async_trait(?Send)]
impl Cycle for MaintenanceCycle<'_> {
    async fn execute(&self, cancellation: &CancellationToken) -> CliResult<DaemonReport> {
        execute_cycle(self.args, self.settings, self.store, self.cli, cancellation).await
    }
}

#[derive(Default)]
struct Statistics {
    cycles: u64,
    failed_cycles: u64,
}

async fn run_loop(
    task: &dyn Cycle,
    interval: Duration,
    cli: &CommandContext,
    cancellation: &CancellationToken,
) -> CliResult<Statistics> {
    let mut statistics = Statistics::default();
    while !cancellation.is_cancelled() {
        cli.output.check_health()?;
        statistics.cycles = statistics.cycles.saturating_add(1);
        // Await the whole transaction. Selecting cancellation around this future
        // would drop started issuance/publication and lose committed reports.
        let result = task.execute(cancellation).await;
        let failed = render::cycle(&cli.output, statistics.cycles, &result)?;
        if failed {
            statistics.failed_cycles = statistics.failed_cycles.saturating_add(1);
        }
        cli.output.check_health()?;
        if cancellation.is_cancelled() {
            break;
        }
        cli.output.progress(
            MessageKind::Wait,
            &format!(
                "Waiting {}s before the next daemon maintenance cycle",
                interval.as_secs()
            ),
        );
        cli.output.check_health()?;
        // A fresh delay after completion prevents overlap and missed-tick bursts
        // after suspend, long CA validation, or a failed cycle.
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            () = tokio::time::sleep(interval) => {},
        }
    }
    Ok(statistics)
}

#[cfg(test)]
mod tests;
