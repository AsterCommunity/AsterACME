//! CLI policy does not become protocol logic; persisted definitions are authoritative.
use crate::commands::cert::validation::*;
use aster_acme::{issuance::ValidationRequirement, solver::ExecutionContext};
use clap::Parser;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub(super) fn execution() -> ExecutionContext {
    ExecutionContext {
        cancellation: CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(2),
    }
}
pub(super) fn progress() -> Arc<Progress> {
    Arc::new(Progress::new(crate::common::session::OutputSession::new(
        true,
    )))
}

#[tokio::test]
async fn manual_http_scripts_first_expose_material_then_confirm_without_dns_bypass() {
    let requirements = [ValidationRequirement::Http01 {
        url: "http://example.com/path".into(),
        path: "/.well-known/acme-challenge/token".into(),
        content: "key.authorization".into(),
    }];
    for yes in [false, true] {
        let manual = manual::Manual {
            prompt: std::sync::Mutex::new(None),
            method: ChallengeKind::Http01,
            saved: false,
            interactive: false,
            yes,
            progress: progress(),
        };
        assert!(!manual.ready(&requirements, &execution()).await.unwrap());
    }
    let manual = manual::Manual {
        prompt: std::sync::Mutex::new(None),
        method: ChallengeKind::Http01,
        saved: true,
        interactive: false,
        yes: true,
        progress: progress(),
    };
    assert!(manual.ready(&requirements, &execution()).await.unwrap());
    let cancelled = execution();
    cancelled.cancellation.cancel();
    assert!(manual.ready(&requirements, &cancelled).await.is_err());
}

#[test]
fn webroot_arguments_are_scoped_and_resume_cannot_override_saved_configuration() {
    use crate::app::Args;
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "-d",
            "example.com",
            "-c",
            "webroot",
            "-w",
            "/srv/www"
        ])
        .is_ok()
    );
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "-d",
            "example.com",
            "-c",
            "webroot"
        ])
        .is_ok()
    );
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "-d",
            "example.com",
            "-c",
            "webroot",
            "--webroot",
            "/srv/www"
        ])
        .is_ok()
    );
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "-d",
            "example.com",
            "-c",
            "manual_http"
        ])
        .is_ok()
    );
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "--resume",
            "web",
            "--webroot",
            "/srv/www"
        ])
        .is_err()
    );
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "renew",
            "web",
            "--webroot",
            "/srv/www"
        ])
        .is_err()
    );
    assert!(
        configuration(
            ValidationMethod::ManualDns,
            Some(std::path::Path::new("/tmp")),
            None
        )
        .is_err()
    );
    let temp = tempfile::tempdir().unwrap();
    let value = configuration(ValidationMethod::Webroot, Some(temp.path()), None).unwrap();
    let config: WebrootConfig = serde_json::from_value(value).unwrap();
    assert_eq!(config.root, temp.path().canonicalize().unwrap());
}

#[tokio::test]
async fn webroot_honors_cancellation_and_keeps_material_when_cleanup_cannot_finish() {
    let temp = tempfile::tempdir().unwrap();
    let handler = webroot::Webroot {
        workers: crate::commands::cert::validation::webroot::workers::Workers::default(),
        root: temp.path().into(),
        operation: "a".repeat(43),
        progress: progress(),
    };
    let requirements = [ValidationRequirement::Http01 {
        url: "http://example.com/file".into(),
        path: "/.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz012345".into(),
        content: "key.authorization".into(),
    }];
    assert!(handler.ready(&requirements, &execution()).await.unwrap());
    let cancelled = execution();
    cancelled.cancellation.cancel();
    assert!(handler.cleanup(&requirements, &cancelled).await.is_err());
    assert!(
        temp.path()
            .join(requirements_path(&requirements[0]))
            .is_file()
    );
    assert!(handler.cleanup(&requirements, &execution()).await.unwrap());
}
fn requirements_path(requirement: &ValidationRequirement) -> &str {
    let ValidationRequirement::Http01 { path, .. } = requirement else {
        panic!("expected HTTP");
    };
    path.trim_start_matches('/')
}

#[test]
fn execution_limit_precedence_is_cli_then_config_then_builtin() {
    fn args(extra: &[&str]) -> super::super::args::RunArgs {
        let mut command_line = vec!["aster-acme", "cert", "issue", "--resume", "web"];
        command_line.extend_from_slice(extra);
        let crate::app::Command::Cert {
            command: super::super::args::CertCommand::Issue(args),
        } = crate::app::Args::parse_from(command_line).command
        else {
            panic!("expected issue");
        };
        args.run
    }
    let defaults = crate::config::Config::default();
    assert_eq!(args(&[]).limits(&defaults), (600, 30, 5));
    let config = crate::config::Config {
        operation_timeout: Some(120),
        max_polls: Some(12),
        ..defaults
    };
    assert_eq!(args(&[]).limits(&config), (120, 12, 5));
    assert_eq!(
        args(&["--operation-timeout", "90"]).limits(&config),
        (90, 12, 5)
    );
    assert_eq!(args(&["--max-polls", "10"]).limits(&config), (120, 10, 5));
    assert_eq!(
        args(&["--operation-timeout", "90", "--max-polls", "10"]).limits(&config),
        (90, 10, 5)
    );
    for flag in ["--timeout", "--wait-timeout"] {
        assert!(
            crate::app::Args::try_parse_from([
                "aster-acme",
                "cert",
                "issue",
                "--resume",
                "web",
                flag,
                "30"
            ])
            .is_err()
        );
    }
}

#[test]
fn poll_interval_cli_overrides_config_and_does_not_leak_into_read_only_commands() {
    fn run(extra: &[&str]) -> super::super::args::RunArgs {
        let mut command_line = vec!["aster-acme", "cert", "issue", "--resume", "web"];
        command_line.extend_from_slice(extra);
        let crate::app::Command::Cert {
            command: super::super::args::CertCommand::Issue(options),
        } = crate::app::Args::parse_from(command_line).command
        else {
            panic!("expected issue");
        };
        options.run
    }
    let config = crate::config::Config {
        poll_interval: Some(8),
        ..crate::config::Config::default()
    };
    assert_eq!(run(&[]).limits(&crate::config::Config::default()).2, 5);
    assert_eq!(run(&[]).limits(&config).2, 8);
    assert_eq!(run(&["--poll-interval", "12"]).limits(&config).2, 12);
    for value in ["0", "301", "-1", "slow"] {
        assert!(
            crate::app::Args::try_parse_from([
                "aster-acme",
                "cert",
                "renew",
                "web",
                "--poll-interval",
                value
            ])
            .is_err()
        );
    }
    assert!(
        crate::app::Args::try_parse_from([
            "aster-acme",
            "cert",
            "renew",
            "--all",
            "--poll-interval",
            "5"
        ])
        .is_ok()
    );
    for command in ["show", "list", "remove", "revoke"] {
        assert!(
            crate::app::Args::try_parse_from([
                "aster-acme",
                "cert",
                command,
                "--poll-interval",
                "5"
            ])
            .is_err()
        );
    }
}

mod flow;

#[test]
fn standalone_configuration_defaults_persist_and_reject_irrelevant_flags() {
    let value = configuration(ValidationMethod::Standalone, None, None).unwrap();
    let saved: StandaloneConfig = serde_json::from_value(value).unwrap();
    assert_eq!(saved.listen_address.to_string(), "0.0.0.0:80");
    for address in ["127.0.0.1:8080", "[::]:80"] {
        let value = configuration(
            ValidationMethod::Standalone,
            None,
            Some(address.parse().unwrap()),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_value::<StandaloneConfig>(value)
                .unwrap()
                .listen_address
                .to_string(),
            address
        );
    }
    assert!(
        configuration(
            ValidationMethod::Standalone,
            None,
            Some("127.0.0.1:0".parse().unwrap())
        )
        .is_err()
    );
    assert!(
        configuration(
            ValidationMethod::Standalone,
            Some(std::path::Path::new("/tmp")),
            None
        )
        .is_err()
    );
    for method in [
        ValidationMethod::ManualDns,
        ValidationMethod::ManualHttp,
        ValidationMethod::Webroot,
    ] {
        assert!(configuration(method, None, Some("127.0.0.1:8080".parse().unwrap())).is_err());
    }
}

#[test]
fn standalone_arguments_expose_only_new_issuance_and_preserve_saved_settings() {
    for address in ["127.0.0.1:8080", "[::]:80"] {
        assert!(
            crate::app::Args::try_parse_from([
                "aster-acme",
                "cert",
                "issue",
                "-c",
                "standalone",
                "-d",
                "example.com",
                "--listen-address",
                address
            ])
            .is_ok()
        );
    }
    for address in ["localhost:80", "0.0.0.0", "127.0.0.1:65536"] {
        assert!(
            crate::app::Args::try_parse_from([
                "aster-acme",
                "cert",
                "issue",
                "-c",
                "standalone",
                "-d",
                "example.com",
                "--listen-address",
                address
            ])
            .is_err()
        );
    }
    for args in [
        vec![
            "aster-acme",
            "cert",
            "issue",
            "--resume",
            "web",
            "--listen-address",
            "127.0.0.1:8080",
        ],
        vec![
            "aster-acme",
            "cert",
            "renew",
            "web",
            "--listen-address",
            "127.0.0.1:8080",
        ],
    ] {
        assert!(crate::app::Args::try_parse_from(args).is_err());
    }
}

#[test]
fn tls_alpn_configuration_defaults_to_public_port_443_and_is_immutable_on_resume() {
    let value = configuration(ValidationMethod::TlsAlpn, None, None).unwrap();
    let saved: StandaloneConfig = serde_json::from_value(value).unwrap();
    assert_eq!(saved.listen_address.to_string(), "0.0.0.0:443");
    let value = configuration(
        ValidationMethod::TlsAlpn,
        None,
        Some("127.0.0.1:8443".parse().unwrap()),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_value::<StandaloneConfig>(value)
            .unwrap()
            .listen_address
            .to_string(),
        "127.0.0.1:8443"
    );
    assert!(
        crate::app::Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "-d",
            "example.com",
            "-c",
            "tls_alpn"
        ])
        .is_ok()
    );
    assert!(
        crate::app::Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "-d",
            "example.com",
            "-c",
            "tls_alpn",
            "--listen-address",
            "127.0.0.1:8443"
        ])
        .is_ok()
    );
    assert!(
        crate::app::Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "--resume",
            "example.com",
            "--listen-address",
            "127.0.0.1:8443"
        ])
        .is_err()
    );
}

#[test]
fn old_dns_bypass_flags_are_not_retained_as_compatibility_aliases() {
    for flag in ["--skip-dns-check", "--skip-local-dns", "--force", "-f"] {
        assert!(
            crate::app::Args::try_parse_from([
                "aster-acme",
                "cert",
                "issue",
                "--resume",
                "web",
                flag
            ])
            .is_err()
        );
    }
}

#[test]
fn poll_budget_defaults_and_cli_bounds_apply_to_both_issue_and_renew() {
    for command in ["issue", "renew"] {
        for value in ["0", "1001", "-1", "many"] {
            let mut args = vec!["aster-acme", "cert", command, "--max-polls", value];
            if command == "issue" {
                args.extend(["--resume", "web"]);
            }
            assert!(crate::app::Args::try_parse_from(args).is_err());
        }
        let mut args = vec!["aster-acme", "cert", command, "--max-polls", "10"];
        if command == "issue" {
            args.extend(["--resume", "web"]);
        }
        let crate::app::Command::Cert { command } = crate::app::Args::parse_from(args).command
        else {
            panic!("expected cert");
        };
        match command {
            super::super::args::CertCommand::Issue(args) => {
                assert_eq!(args.run.max_polls, Some(10));
            }
            super::super::args::CertCommand::Renew(args) => {
                assert_eq!(args.run.max_polls, Some(10));
            }
            _ => panic!("wrong command"),
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn webroot_rejects_replaced_directory_components_and_removes_only_inside_pinned_root() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let handler = webroot::Webroot {
        workers: crate::commands::cert::validation::webroot::workers::Workers::default(),
        root: temp.path().into(),
        operation: "b".repeat(43),
        progress: progress(),
    };
    let requirement = [ValidationRequirement::Http01 {
        url: "http://example.com/file".into(),
        path: "/.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz012345".into(),
        content: "key.authorization".into(),
    }];
    handler.ready(&requirement, &execution()).await.unwrap();
    let pinned = temp.path().join(".well-known");
    let moved = temp.path().join("moved");
    std::fs::rename(&pinned, &moved).unwrap();
    std::os::unix::fs::symlink(outside.path(), &pinned).unwrap();
    assert!(handler.cleanup(&requirement, &execution()).await.is_err());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    assert!(
        moved
            .join(
                requirements_path(&requirement[0])
                    .strip_prefix(".well-known/")
                    .unwrap()
            )
            .is_file()
    );
}
