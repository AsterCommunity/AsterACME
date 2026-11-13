use crate::{
    app::{Args, Command},
    commands::daemon::{self, DaemonReport, render},
    common::{
        context::{CliSettings, CommandContext},
        session::{ExitStatus, Format},
    },
    config::Config,
};
use aster_acme::{
    issuance::{CertificateName, IssueError},
    maintenance::{Entry, Outcome, Report},
};
use clap::Parser;

fn parse(extra: &[&str]) -> daemon::RunOnceArgs {
    let args = Args::try_parse_from(
        ["aster-acme", "daemon", "run-once"]
            .into_iter()
            .chain(extra.iter().copied()),
    )
    .unwrap();
    assert_eq!(args.json(), extra.contains(&"--json"));
    let Command::Daemon {
        command: daemon::DaemonCommand::RunOnce(args),
    } = args.command
    else {
        panic!("expected daemon")
    };
    args
}

#[test]
fn daemon_commands_and_bounded_limits_are_accepted() {
    assert!(Args::try_parse_from(["aster-acme", "daemon"]).is_err());
    parse(&[]);
    let resident =
        Args::try_parse_from(["aster-acme", "daemon", "run", "--interval", "90"]).unwrap();
    let Command::Daemon {
        command: daemon::DaemonCommand::Run { interval, .. },
    } = resident.command
    else {
        panic!("expected resident daemon")
    };
    assert_eq!(interval, Some(90));
    for flag in [
        "--request-timeout",
        "--operation-timeout",
        "--poll-interval",
        "--max-polls",
    ] {
        for invalid in ["0", "-1", "86401", "NaN"] {
            assert!(
                Args::try_parse_from(["aster-acme", "daemon", "run-once", flag, invalid]).is_err()
            );
        }
    }
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "daemon",
            "run-once",
            "--request-timeout",
            "301"
        ])
        .is_err()
    );
    for extra in ["--all", "--now", "--yes", "--renew", "--install"] {
        assert!(Args::try_parse_from(["aster-acme", "daemon", "run-once", extra]).is_err());
    }
    for invalid in ["0", "86401", "NaN"] {
        assert!(
            Args::try_parse_from(["aster-acme", "daemon", "run", "--interval", invalid]).is_err()
        );
    }
    assert!(
        Args::try_parse_from(["aster-acme", "daemon", "run-once", "--interval", "30"]).is_err()
    );
}

#[test]
fn cli_overrides_config_and_missing_config_uses_defaults() {
    let mut settings = CliSettings {
        config: Config::default(),
        config_path: "config.toml".into(),
        data_dir: ".".into(),
    };
    let defaults = parse(&[]).options(&settings);
    assert_eq!(defaults.transport.request_timeout.as_secs(), 30);
    assert_eq!(defaults.certificate_timeout.as_secs(), 600);
    settings.config.request_timeout = Some(12);
    settings.config.operation_timeout = Some(45);
    let configured = parse(&[]).options(&settings);
    assert_eq!(configured.transport.request_timeout.as_secs(), 12);
    assert_eq!(configured.certificate_timeout.as_secs(), 45);
    let overridden = parse(&[
        "--request-timeout",
        "1",
        "--operation-timeout",
        "86400",
        "--poll-interval",
        "300",
        "--max-polls",
        "1000",
        "--user-agent",
        "host/1",
    ])
    .options(&settings);
    assert_eq!(overridden.transport.request_timeout.as_secs(), 1);
    assert_eq!(overridden.certificate_timeout.as_secs(), 86400);
    assert_eq!(
        parse(&["--poll-interval", "9", "--max-polls", "12"]).poll_interval,
        Some(9)
    );
    assert_eq!(
        parse(&["--poll-interval", "9", "--max-polls", "12"]).max_polls,
        Some(12)
    );
    assert_eq!(overridden.transport.user_agent.as_deref(), Some("host/1"));
}

fn daemon_report(report: Report) -> DaemonReport {
    DaemonReport {
        ari: report,
        renewals: crate::commands::cert::report::RenewalBatch::empty(),
        deployment_retries: Vec::new(),
        deployment_cancelled: false,
        data_dir: ".".into(),
    }
}

fn entry(outcome: Outcome) -> Entry {
    Entry {
        name: CertificateName::new("test").unwrap(),
        operation_id: "saved-operation".into(),
        outcome,
        renew_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        next_check_at: None,
    }
}

#[test]
fn reports_preserve_partial_results_machine_times_and_disposition() {
    for (outcome, status) in [
        (Outcome::Refreshed, ExitStatus::Success),
        (Outcome::Unavailable, ExitStatus::Success),
        (Outcome::Skipped, ExitStatus::Success),
        (Outcome::RetryScheduled, ExitStatus::Failed),
        (
            Outcome::Failed(IssueError::InvalidInput("broken\nmetadata")),
            ExitStatus::Failed,
        ),
    ] {
        let report = daemon_report(Report {
            entries: vec![entry(outcome)],
            cancelled: false,
        });
        assert_eq!(daemon::exit_status(&report), status);
        let json: serde_json::Value =
            serde_json::from_str(&render::render(&report, Format::plain(true)).unwrap()).unwrap();
        assert_eq!(
            json["ari"]["entries"][0]["renew_at"],
            "1970-01-01T00:00:00Z"
        );
        let text = render::render(&report, Format::plain(false)).unwrap();
        assert!(text.contains("1970-01-01 00:00:00 UTC"));
        assert!(!text.contains("broken\nmetadata"));
    }
    let report = daemon_report(Report {
        entries: vec![
            entry(Outcome::Refreshed),
            entry(Outcome::Cancelled),
            entry(Outcome::NotStarted),
        ],
        cancelled: true,
    });
    assert_eq!(daemon::exit_status(&report), ExitStatus::Cancelled);
    let json: serde_json::Value =
        serde_json::from_str(&render::render(&report, Format::plain(true)).unwrap()).unwrap();
    assert_eq!(json["ari"]["entries"].as_array().unwrap().len(), 3);
    assert_eq!(json["cancelled"], true);
}

#[tokio::test]
async fn empty_inventory_is_noninteractive_and_needs_no_account_or_http() {
    let temp = tempfile::tempdir().unwrap();
    let args = parse(&["--json", "--data-dir", temp.path().to_str().unwrap()]);
    let cli = CommandContext::new(true);
    let daemon::DaemonExecution::Cycle(report) =
        daemon::execute(daemon::DaemonCommand::RunOnce(args), &cli)
            .await
            .unwrap()
    else {
        panic!("run-once must return a completed cycle")
    };
    assert!(report.ari.entries.is_empty());
    assert_eq!(daemon::exit_status(&report), ExitStatus::Success);
    assert!(!temp.path().join("accounts").exists());
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            &render::render(&report, Format::plain(true)).unwrap()
        )
        .unwrap()["ari"]["entries"],
        serde_json::json!([])
    );
    let human = render::render(&report, Format::plain(false)).unwrap();
    assert_eq!(
        human,
        "[INFO] No ARI refreshes, automatic renewals, or deployment retries were due."
    );
    assert!(!human.contains("NAME"));
}

#[test]
fn native_daemon_help_paths_include_cron_and_never_require_execution_inputs() {
    use clap::CommandFactory;
    let root = crate::common::help::configure(Args::command());
    for path in [
        vec!["daemon", "--help"],
        vec!["daemon", "help"],
        vec!["help", "daemon"],
        vec!["daemon", "help", "run-once"],
        vec!["daemon", "run-once", "--help"],
    ] {
        let error = root
            .clone()
            .try_get_matches_from(["aster-acme"].into_iter().chain(path))
            .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.starts_with("AsterACME "));
        assert!(help.contains("crontab -e"));
        assert!(help.contains("*/15 * * * * /absolute/path/to/aster-acme daemon run-once --data-dir /absolute/path/to/state"));
        assert!(!help.contains("--run-once"));
    }
    let resident = root
        .clone()
        .try_get_matches_from(["aster-acme", "daemon", "run", "--help"])
        .unwrap_err();
    assert_eq!(resident.kind(), clap::error::ErrorKind::DisplayHelp);
    assert!(resident.to_string().contains("--interval"));
    assert!(resident.to_string().contains("ASTER_ACME_DATA_DIR"));
    assert!(Args::try_parse_from(["aster-acme", "daemon", "--run-once"]).is_err());
}

#[test]
fn maintenance_lists_use_shared_header_status_and_diagnostic_styles() {
    for (outcome, status_style, badge) in [
        (
            Outcome::Refreshed,
            crate::common::output::Style::Green,
            "[INFO]",
        ),
        (
            Outcome::RetryScheduled,
            crate::common::output::Style::Yellow,
            "[WARN]",
        ),
        (
            Outcome::Failed(IssueError::InvalidInput("bad\u{001b}[2J")),
            crate::common::output::Style::Red,
            "[ERROR]",
        ),
    ] {
        let report = daemon_report(Report {
            entries: vec![entry(outcome)],
            cancelled: false,
        });
        let plain = render::render(&report, Format::plain(false)).unwrap();
        let colored = render::render(
            &report,
            Format {
                json: false,
                color: true,
            },
        )
        .unwrap();
        assert!(plain.starts_with(badge));
        assert!(!plain.contains('\u{001b}'));
        assert!(colored.contains(&crate::common::output::styled(
            "NAME",
            crate::common::output::Style::BoldCyan,
            true
        )));
        assert!(colored.contains(&crate::common::output::styled(
            render::status(&report.ari.entries[0].outcome),
            status_style,
            true
        )));
        assert!(plain.contains("Unchanged ARI windows retain the selected renewal time."));
        let json = render::render(
            &report,
            Format {
                json: true,
                color: true,
            },
        )
        .unwrap();
        assert!(!json.contains('\u{001b}'));
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["ari"]["entries"].as_array().unwrap().len(), 1);
        assert_eq!(value["renewal"]["results"], serde_json::json!([]));
    }
}
