//! Host adapter for a finite, noninteractive maintenance cycle.
pub(crate) mod render;
use crate::{
    commands::account::args::AccountArgs,
    commands::cert::args::RunArgs,
    common::{
        args::{HttpArgs, LocalArgs},
        context::{CliSettings, CommandContext},
        error::CliResult,
        output::MessageKind,
        session::{ExitStatus, OutputSession},
        signal::InterruptGuard,
    },
};
use aster_acme::{
    maintenance::{self, Observer, Options, Outcome, Report},
    transport::TransportOptions,
};
use aster_acme_cli_storage::issuance::CliIssueStore;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const SCHEDULING_HELP: &str = "Scheduling (cron example, every 15 minutes):
  Run crontab -e and add:
  */15 * * * * /absolute/path/to/aster-acme daemon run-once --data-dir /absolute/path/to/state

Use absolute paths and the same --data-dir as issue/renew. Quote paths containing spaces.
Refreshes ARI advice, renews due webroot/standalone/tls_alpn certificates, retries due known deployment failures, and runs configured deployments. Manual validation is skipped. Uncertain ACME submissions and reloads are never replayed automatically. The command does not install a cron job.";

#[derive(clap::Subcommand)]
#[command(after_help = SCHEDULING_HELP)]
pub(crate) enum DaemonCommand {
    /// Refresh ARI, renew eligible certificates, and retry due known deployment failures once.
    #[command(after_help = SCHEDULING_HELP)]
    RunOnce(RunOnceArgs),
}

#[derive(clap::Args)]
pub(crate) struct RunOnceArgs {
    #[command(flatten)]
    pub(crate) local: LocalArgs,
    #[command(flatten)]
    pub(crate) http: HttpArgs,
    /// Budget per certificate for each ARI or renewal step in seconds (1–86400); config `operation_timeout`, default 600.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86400))]
    pub(crate) operation_timeout: Option<u64>,
    /// Local CA order polling interval in seconds (1–300); config `poll_interval`, default 5. Retry-After takes precedence.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub(crate) poll_interval: Option<u64>,
    /// Maximum CA order polls per certificate (1–1000); config `max_polls`, default 30.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub(crate) max_polls: Option<u32>,
}
impl RunOnceArgs {
    fn options(&self, settings: &CliSettings) -> Options {
        Options {
            transport: TransportOptions {
                request_timeout: Duration::from_secs(
                    self.http
                        .request_timeout
                        .or(settings.config.request_timeout)
                        .unwrap_or(30),
                ),
                user_agent: self.http.user_agent.clone(),
                ..TransportOptions::default()
            },
            certificate_timeout: Duration::from_secs(
                self.operation_timeout
                    .or(settings.config.operation_timeout)
                    .unwrap_or(600),
            ),
        }
    }
}

pub(crate) struct DaemonReport {
    pub(crate) ari: Report,
    pub(crate) renewals: crate::commands::cert::report::RenewalBatch,
    pub(crate) deployment_retries: Vec<crate::commands::cert::report::DeploymentReport>,
    pub(crate) deployment_cancelled: bool,
    pub(crate) data_dir: std::path::PathBuf,
}

pub(crate) async fn execute(
    command: DaemonCommand,
    cli: &CommandContext,
) -> CliResult<DaemonReport> {
    let DaemonCommand::RunOnce(args) = command;
    let settings = CliSettings::load(&AccountArgs {
        data_dir: args.local.data_dir.clone(),
        json: args.local.json,
        ..AccountArgs::default()
    })
    .await?;
    let options = args.options(&settings);
    let renewal_run = RunArgs {
        poll_interval: args.poll_interval,
        max_polls: args.max_polls,
        yes: true,
        operation_timeout: args.operation_timeout,
        http: args.http.clone(),
        local: args.local.clone(),
    };
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    let cancellation = CancellationToken::new();
    let _signal = InterruptGuard::new(cancellation.clone());
    let tasks = CliAutomaticTasks {
        settings: settings.clone(),
        store: &store,
        run: &renewal_run,
        timeout: options.certificate_timeout,
        cli,
    };
    let cycle = maintenance::run_cycle(
        &store,
        &cli.http,
        &options,
        &cancellation,
        Some(&AriProgress(cli.output.clone())),
        &tasks,
    )
    .await?;
    Ok(DaemonReport {
        ari: cycle.ari,
        renewals: match cycle.renewals {
            maintenance::Stage::Completed(report) => report,
            maintenance::Stage::NotRun => crate::commands::cert::report::RenewalBatch::cancelled(),
        },
        deployment_retries: match cycle.deployments {
            maintenance::Stage::Completed(reports) => reports,
            maintenance::Stage::NotRun => Vec::new(),
        },
        deployment_cancelled: cancellation.is_cancelled(),
        data_dir: settings.data_dir,
    })
}

struct CliAutomaticTasks<'a> {
    settings: CliSettings,
    store: &'a CliIssueStore,
    run: &'a RunArgs,
    timeout: Duration,
    cli: &'a CommandContext,
}

#[async_trait::async_trait(?Send)]
impl maintenance::AutomaticTasks for CliAutomaticTasks<'_> {
    type Renewals = crate::commands::cert::report::RenewalBatch;
    type Deployments = Vec<crate::commands::cert::report::DeploymentReport>;

    async fn renew(
        &self,
        candidates: Vec<aster_acme::issuance::IssueRecord>,
        cancellation: &CancellationToken,
    ) -> Self::Renewals {
        crate::commands::cert::renewal::execute_automatic(
            self.settings.clone(),
            self.store,
            self.run,
            self.cli,
            cancellation,
            candidates,
        )
        .await
    }

    async fn deploy(
        &self,
        candidates: Vec<aster_acme::issuance::IssueRecord>,
        cancellation: &CancellationToken,
    ) -> Self::Deployments {
        crate::commands::cert::deployment::retry_due(
            self.store,
            self.timeout,
            cancellation,
            self.cli,
            candidates,
        )
        .await
    }
}

pub(crate) fn exit_status(report: &DaemonReport) -> ExitStatus {
    if report.ari.cancelled || report.renewals.was_cancelled() || report.deployment_cancelled {
        ExitStatus::Cancelled
    } else if report
        .ari
        .entries
        .iter()
        .any(|entry| matches!(entry.outcome, Outcome::Failed(_) | Outcome::RetryScheduled))
        || report.renewals.has_failures()
        || report
            .deployment_retries
            .iter()
            .any(crate::commands::cert::report::DeploymentReport::has_failures)
    {
        ExitStatus::Failed
    } else {
        ExitStatus::Success
    }
}

struct AriProgress(OutputSession);
impl Observer for AriProgress {
    fn started(&self, items: usize) {
        self.0.progress(
            MessageKind::Info,
            &format!("Refreshing ARI suggestions for {items} certificates"),
        );
    }

    fn observed(&self, _: &aster_acme::maintenance::Entry) {}
}

#[cfg(test)]
mod tests;
