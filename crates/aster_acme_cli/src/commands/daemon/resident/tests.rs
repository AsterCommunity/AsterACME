use crate::{
    commands::{
        cert::report::RenewalBatch,
        daemon::{
            DaemonReport,
            resident::{Cycle, interval, run_loop},
        },
    },
    common::{context::CommandContext, error::CliResult, output::MessageKind, session::ExitStatus},
};
use aster_acme::maintenance::Report;
use std::{cell::Cell, time::Duration};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn interval_uses_cli_then_config_then_sixty_second_default_and_checks_limits() {
    assert_eq!(interval(None, None).unwrap(), Duration::from_secs(60));
    assert_eq!(interval(None, Some(5)).unwrap(), Duration::from_secs(5));
    assert_eq!(interval(Some(1), Some(5)).unwrap(), Duration::from_secs(1));
    assert_eq!(
        interval(Some(86400), None).unwrap(),
        Duration::from_hours(24)
    );
    for invalid in [0, 86401] {
        assert!(interval(Some(invalid), None).is_err());
        assert!(interval(None, Some(invalid)).is_err());
    }
}

struct CancellingCycle {
    calls: Cell<u64>,
    cancellation: CancellationToken,
    fail_first: bool,
}

#[async_trait::async_trait(?Send)]
impl Cycle for CancellingCycle {
    async fn execute(&self, _: &CancellationToken) -> CliResult<DaemonReport> {
        let calls = self.calls.get() + 1;
        self.calls.set(calls);
        if calls == 2 {
            self.cancellation.cancel();
        }
        if self.fail_first && calls == 1 {
            return Err("injected maintenance cycle failure".into());
        }
        Ok(DaemonReport {
            ari: Report::default(),
            renewals: RenewalBatch::empty(),
            deployment_retries: Vec::new(),
            deployment_cancelled: false,
            data_dir: ".".into(),
        })
    }
}

#[tokio::test]
async fn resident_loop_runs_serially_recovers_after_a_failed_cycle_and_stops_after_cancellation() {
    let cancellation = CancellationToken::new();
    let task = CancellingCycle {
        calls: Cell::new(0),
        cancellation: cancellation.clone(),
        fail_first: true,
    };
    let cli = CommandContext::new(false);
    cli.output.progress(MessageKind::Info, "test start");
    let statistics = run_loop(&task, Duration::from_millis(1), &cli, &cancellation)
        .await
        .unwrap();
    assert_eq!(statistics.cycles, 2);
    assert_eq!(statistics.failed_cycles, 1);
    assert_eq!(task.calls.get(), 2);
    cli.output.check_health().unwrap();
}

#[test]
fn stopped_resident_process_is_a_successful_command_disposition() {
    use crate::dispatch::CommandReport;
    let report = CommandReport::DaemonStopped(crate::commands::daemon::DaemonStopped {
        cycles: 3,
        failed_cycles: 1,
        data_dir: ".".into(),
    });
    assert_eq!(report.exit_status(), ExitStatus::Success);
}
