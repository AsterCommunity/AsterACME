//! CLI scope, positional identities and deliberately removed legacy syntax.
use crate::{
    app::{Args, Command},
    commands::cert::args::{CertCommand, deployment::DeployCommand},
};
use clap::Parser as _;

fn parse(arguments: &[&str]) -> Result<Args, clap::Error> {
    Args::try_parse_from(
        ["aster-acme", "cert", "deploy"]
            .into_iter()
            .chain(arguments.iter().copied()),
    )
}

#[test]
fn actions_expose_only_their_own_arguments_and_use_positional_identities() {
    for arguments in [
        vec!["run", "web"],
        vec!["run", "web", "-n", "nginx"],
        vec!["list", "web"],
        vec!["remove", "web", "-n", "nginx"],
        vec!["run"],
        vec!["list"],
        vec!["remove"],
        vec!["add"],
        vec!["add", "web", "--name", "nginx", "--target", "/tmp"],
        vec![
            "add",
            "web",
            "-n",
            "nginx",
            "--target",
            "/tmp",
            "--reload-cmd",
            "systemctl reload nginx",
        ],
        vec![
            "add",
            "web",
            "-n",
            "nginx",
            "--cert-path",
            "/tmp/cert",
            "--key-path",
            "/tmp/key",
            "--reload-cmd",
            "systemctl reload nginx",
        ],
    ] {
        assert!(
            parse(&arguments).is_ok(),
            "unexpected rejection: {arguments:?}"
        );
    }
    let parsed = parse(&[
        "run",
        "web",
        "-n",
        "nginx",
        "--json",
        "--data-dir",
        "custom-root",
        "--debug",
    ])
    .unwrap();
    assert!(parsed.json());
    let Command::Cert {
        command: CertCommand::Deploy(args),
    } = parsed.command
    else {
        panic!("expected deploy");
    };
    assert_eq!(args.name(), Some("web"));
    assert_eq!(
        args.local().data_dir.as_deref(),
        Some(std::path::Path::new("custom-root"))
    );
    let DeployCommand::Run(args) = args.command else {
        panic!("expected run");
    };
    assert_eq!(args.id.as_deref(), Some("nginx"));
    for action in ["run", "list", "remove"] {
        for flag in [
            "--target",
            "--reload-cmd",
            "--reload-timeout",
            "--max-retries",
        ] {
            assert!(parse(&[action, "web", flag, "1"]).is_err());
        }
    }
    assert!(parse(&["list", "web", "nginx"]).is_err());
    assert!(parse(&["run", "web", "nginx", "extra"]).is_err());
}

#[test]
fn add_paths_are_independent_and_reload_limits_remain_valid() {
    for flag in ["--cert-path", "--key-path", "--ca-path", "--fullchain-path"] {
        assert!(
            parse(&["add", "web", flag, "/tmp/file"]).is_ok(),
            "single path rejected: {flag}"
        );
        assert!(parse(&["add", "web", "--target", "/tmp", flag, "/tmp/file"]).is_err());
    }
    for (flag, good, bad) in [
        ("--reload-timeout", ["1", "3600"], ["0", "3601"]),
        ("--max-retries", ["0", "10"], ["-1", "11"]),
    ] {
        for value in good {
            assert!(
                parse(&[
                    "add",
                    "web",
                    "-n",
                    "nginx",
                    "--target",
                    "/tmp",
                    "--reload-cmd",
                    "true",
                    flag,
                    value
                ])
                .is_ok()
            );
        }
        for value in bad {
            assert!(
                parse(&[
                    "add",
                    "web",
                    "-n",
                    "nginx",
                    "--target",
                    "/tmp",
                    "--reload-cmd",
                    "true",
                    flag,
                    value
                ])
                .is_err()
            );
        }
    }
    for id in ["../escape", "has space", "", &"x".repeat(65)] {
        for action in ["run", "remove"] {
            assert!(parse(&[action, "web", "-n", id]).is_err());
        }
    }
}

#[test]
fn legacy_operations_and_ambiguous_timeout_are_not_accepted_as_aliases() {
    for arguments in [
        vec!["web"],
        vec!["web", "--list"],
        vec!["web", "--remove-deploy", "nginx"],
        vec!["web", "--add-deploy", "nginx"],
        vec!["run", "web", "--retry"],
        vec!["run", "web", "--deployment", "nginx"],
        vec!["retry", "web", "nginx"],
        vec![
            "add",
            "web",
            "-n",
            "nginx",
            "--target",
            "/tmp",
            "--reload-cmd",
            "true",
            "--timeout",
            "30",
        ],
    ] {
        assert!(
            parse(&arguments).is_err(),
            "legacy syntax accepted: {arguments:?}"
        );
    }
    for action in ["add", "run", "remove"] {
        assert!(parse(&[action, "web", "nginx"]).is_err());
    }
    assert!(parse(&["add", "web", "--name", "nginx", "--target", "/tmp"]).is_ok());
    assert!(parse(&[]).is_err());
}

#[test]
fn help_exposes_deployment_actions_and_scopes_configuration_to_add_and_update() {
    let help = parse(&["--help"]).err().unwrap();
    assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
    let root = help.to_string();
    for action in ["run", "add", "list", "show", "update", "remove"] {
        assert!(root.contains(action));
    }
    for flag in [
        "--target",
        "--reload-cmd",
        "--reload-timeout",
        "--max-retries",
        "--deployment",
        "--retry",
    ] {
        assert!(!root.contains(flag));
    }
    for action in ["run", "list", "remove"] {
        let help = parse(&[action, "--help"]).err().unwrap().to_string();
        assert!(!help.contains("--target"));
        assert!(!help.contains("--reload-timeout"));
        assert!(help.contains("--json"));
        assert!(help.contains("--data-dir"));
    }
    let add = parse(&["add", "--help"]).err().unwrap().to_string();
    assert!(add.contains("--reload-timeout"));
    assert!(!add.contains("--timeout "));
    assert!(add.contains("[CERT_NAME]"));
    assert!(add.contains("-n, --name <DEPLOY_NAME>"));
    assert!(!add.contains("[CERT_NAME] [DEPLOY_NAME]"));
    let run = parse(&["run", "--help"]).err().unwrap().to_string();
    assert!(run.contains("omit to run all configured bindings"));
    assert!(!run.contains("remove asks"));
    let remove = parse(&["remove", "--help"]).err().unwrap().to_string();
    assert!(remove.contains("Deployment name; omit to select interactively"));
}

#[test]
fn positional_arity_is_explicit_with_only_deployment_show_allowing_two() {
    use clap::CommandFactory as _;
    fn check(command: &clap::Command, path: &str) {
        let arity = command.get_positionals().count();
        if path == "aster-acme cert deploy show" {
            assert_eq!(arity, 2);
        } else {
            assert!(arity <= 1, "too many positional arguments in {path}");
        }
        for child in command.get_subcommands() {
            check(child, &format!("{path} {}", child.get_name()));
        }
    }
    check(&Args::command(), "aster-acme");
}

#[test]
fn show_accepts_two_optional_positionals_and_local_options_only() {
    for words in [
        vec!["show"],
        vec!["show", "web"],
        vec!["show", "web", "nginx"],
        vec!["show", "web", "nginx", "--json", "--data-dir", "custom"],
    ] {
        let parsed = parse(&words).unwrap();
        let Command::Cert {
            command: CertCommand::Deploy(args),
        } = parsed.command
        else {
            panic!("expected deploy");
        };
        let DeployCommand::Show(options) = args.command else {
            panic!("expected show");
        };
        assert_eq!(options.name.as_deref(), words.get(1).copied());
        assert_eq!(options.deployment.as_deref(), words.get(2).copied());
    }
    for words in [
        vec!["show", "web", "nginx", "extra"],
        vec!["show", "web", "--name", "nginx"],
        vec!["show", "web", "--target", "/tmp"],
        vec!["show", "web", "--verify"],
        vec!["show", "web", "../invalid"],
        vec!["show", "../invalid", "nginx"],
    ] {
        assert!(parse(&words).is_err(), "unexpected acceptance: {words:?}");
    }
    let help = parse(&["show", "--help"]).err().unwrap().to_string();
    assert!(help.contains("[CERT_NAME] [DEPLOY_NAME]"));
}

#[test]
fn unix_modes_and_update_changes_have_strict_parameter_boundaries() {
    for mode in ["600", "0644", "0640", "000", "0777"] {
        assert!(parse(&["add", "web", "--target", "/tmp", "--file-mode", mode]).is_ok());
    }
    for mode in ["7777", "888", "0x644", "", "12", "-1"] {
        assert!(parse(&["add", "web", "--target", "/tmp", "--key-mode", mode]).is_err());
    }
    for words in [
        vec!["update", "web", "-n", "nginx", "--clear-reload"],
        vec!["update", "web", "-n", "nginx", "--file-mode", "0644"],
        vec![
            "update",
            "web",
            "-n",
            "nginx",
            "--fullchain-path",
            "/tmp/chain.pem",
        ],
    ] {
        assert!(parse(&words).is_ok());
    }
    for words in [
        vec!["update", "web", "-n", "nginx"],
        vec![
            "update",
            "web",
            "-n",
            "nginx",
            "--clear-reload",
            "--reload-cmd",
            "true",
        ],
        vec![
            "update",
            "web",
            "-n",
            "nginx",
            "--target",
            "/tmp",
            "--key-path",
            "/tmp/key.pem",
        ],
    ] {
        assert!(parse(&words).is_err());
    }
}
