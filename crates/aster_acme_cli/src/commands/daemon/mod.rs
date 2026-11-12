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
    maintenance::{self, Entry, Observer, Options, Outcome, Report},
    transport::TransportOptions,
};
use aster_acme_cli_storage::issuance::CliIssueStore;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const SCHEDULING_HELP: &str = "Scheduling (cron example, every 15 minutes):
  Run crontab -e and add:
  */15 * * * * /absolute/path/to/aster-acme daemon run-once --data-dir /absolute/path/to/state

Use absolute paths and the same --data-dir as issue/renew. Quote paths containing spaces.
Refreshes ARI advice, renews due webroot/standalone/tls_alpn certificates, and runs configured deployments. Manual validation is skipped. The command does not install a cron job.";

#[derive(clap::Subcommand)]
#[command(after_help = SCHEDULING_HELP)]
pub(crate) enum DaemonCommand {
    /// Refresh ARI suggestions and automatically renew eligible due certificates once.
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
    cli.output.progress(
        MessageKind::Info,
        "Starting maintenance: refresh due ARI suggestions",
    );
    let ari = maintenance::run_once(
        &store,
        &cli.http,
        &options,
        &cancellation,
        Some(&Progress(&cli.output)),
    )
    .await?;
    if cancellation.is_cancelled() {
        return Ok(DaemonReport {
            ari,
            renewals: crate::commands::cert::report::RenewalBatch::cancelled(),
            data_dir: settings.data_dir,
        });
    }
    cli.output
        .progress(MessageKind::Info, "Checking automatic renewal eligibility");
    let renewals = crate::commands::cert::renewal::execute_automatic(
        settings.clone(),
        &store,
        &renewal_run,
        cli,
        &cancellation,
    )
    .await?;
    Ok(DaemonReport {
        ari,
        renewals,
        data_dir: settings.data_dir,
    })
}

pub(crate) fn exit_status(report: &DaemonReport) -> ExitStatus {
    if report.ari.cancelled || report.renewals.was_cancelled() {
        ExitStatus::Cancelled
    } else if report
        .ari
        .entries
        .iter()
        .any(|entry| matches!(entry.outcome, Outcome::Failed(_) | Outcome::RetryScheduled))
        || report.renewals.has_failures()
    {
        ExitStatus::Failed
    } else {
        ExitStatus::Success
    }
}

struct Progress<'a>(&'a OutputSession);
impl Observer for Progress<'_> {
    fn observed(&self, entry: &Entry) {
        let kind = match entry.outcome {
            Outcome::Refreshed => MessageKind::Success,
            Outcome::RetryScheduled | Outcome::Failed(_) | Outcome::Unavailable => {
                MessageKind::Warning
            }
            Outcome::Skipped | Outcome::Cancelled | Outcome::NotStarted => MessageKind::Info,
        };
        self.0.progress(
            kind,
            &format!(
                "ARI {}: {}",
                entry.name.as_str(),
                render::status(&entry.outcome)
            ),
        );
    }
}

#[cfg(test)]
mod tests;
