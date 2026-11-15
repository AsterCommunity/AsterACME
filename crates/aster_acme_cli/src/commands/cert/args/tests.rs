use crate::app::{Args, Command};
use crate::commands::cert::args::*;
use clap::Parser;

#[test]
fn failed_cleanup_is_explicit_and_conflicts_with_other_scopes_and_operations() {
    let parsed = crate::app::Args::try_parse_from([
        "aster-acme",
        "cert",
        "remove",
        "web",
        "--failed",
        "--yes",
    ])
    .unwrap();
    assert!(matches!(
        parsed.command,
        crate::app::Command::Cert {
            command: crate::commands::cert::args::CertCommand::Remove {
                failed: true,
                yes: true,
                ..
            }
        }
    ));
    for other in ["--all", "--history", "--revoked"] {
        assert!(
            crate::app::Args::try_parse_from([
                "aster-acme",
                "cert",
                "remove",
                "web",
                "--failed",
                other
            ])
            .is_err()
        );
    }
    assert!(
        crate::app::Args::try_parse_from([
            "aster-acme",
            "cert",
            "remove",
            "web",
            "--failed",
            "--operation",
            &"a".repeat(43)
        ])
        .is_err()
    );
}

#[test]
fn revoke_supports_interaction_names_exact_requests_and_script_confirmation() {
    for target in [
        vec![],
        vec!["example.com"],
        vec!["-n", "example.com"],
        vec!["--operation", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
    ] {
        let args = Args::try_parse_from(
            ["aster-acme", "cert", "revoke"]
                .into_iter()
                .chain(target)
                .chain([
                    "-y",
                    "--reason",
                    "key-compromise",
                    "--json",
                    "--data-dir",
                    "/tmp/acme-test",
                ]),
        )
        .unwrap();
        let Command::Cert { command } = args.command else {
            panic!("certificate command expected")
        };
        assert!(matches!(
            command,
            CertCommand::Revoke(RevokeArgs {
                yes: true,
                reason: Some(RevocationReason::KeyCompromise),
                ..
            })
        ));
    }
    for args in [
        vec!["example.com", "-n", "other.com"],
        vec!["--skip-dns-check"],
        vec!["--accept-terms"],
        vec!["--verify"],
        vec!["--reason", "7"],
        vec!["--reason", "unassigned"],
        vec!["--operation", "short"],
    ] {
        assert!(
            Args::try_parse_from(["aster-acme", "cert", "revoke"].into_iter().chain(args)).is_err()
        );
    }
}
#[test]
fn remove_accepts_only_name_confirmation_and_local_options() {
    for target in [vec![], vec!["example.com"], vec!["-n", "example.com"]] {
        let args = Args::try_parse_from(
            ["aster-acme", "cert", "remove"]
                .into_iter()
                .chain(target)
                .chain(["-y", "--json", "--data-dir", "/tmp/acme-remove-test"]),
        )
        .unwrap();
        let Command::Cert { command } = args.command else {
            panic!("certificate command expected")
        };
        assert!(matches!(command, CertCommand::Remove { yes: true, .. }));
    }
    for scope in [
        vec!["--all"],
        vec!["--history"],
        vec!["--revoked"],
        vec!["--operation", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
    ] {
        assert!(
            Args::try_parse_from(
                ["aster-acme", "cert", "remove", "example.com", "--yes"]
                    .into_iter()
                    .chain(scope)
            )
            .is_ok()
        );
    }
    for args in [
        vec!["--revoked", "--all"],
        vec!["--revoked", "--history"],
        vec![
            "--revoked",
            "--operation",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        vec!["example.com", "-n", "other.com"],
        vec!["--all", "--history"],
        vec![
            "--all",
            "--operation",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        vec![
            "--history",
            "--operation",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        vec!["--verify"],
        vec!["--skip-dns-check"],
        vec!["--request-timeout", "30"],
        vec!["--reason", "key-compromise"],
        vec!["--accept-terms"],
    ] {
        assert!(
            Args::try_parse_from(["aster-acme", "cert", "remove"].into_iter().chain(args)).is_err()
        );
    }
}
#[test]
fn all_certificate_key_types_parse_with_default_p256_and_cannot_replace_resumed_material() {
    for algorithm in KeyAlgorithm::ALL {
        let args = Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "-d",
            "example.com",
            "-k",
            algorithm.name(),
            "-c",
            "manual_dns",
        ])
        .unwrap();
        let Command::Cert { command } = args.command else {
            panic!("certificate command expected")
        };
        let CertCommand::Issue(options) = command else {
            panic!("issue expected")
        };
        assert_eq!(options.key_algorithm, algorithm);
    }
    let args = Args::try_parse_from([
        "aster-acme",
        "cert",
        "issue",
        "-d",
        "example.com",
        "-c",
        "manual_dns",
    ])
    .unwrap();
    let Command::Cert { command } = args.command else {
        panic!("certificate command expected")
    };
    let CertCommand::Issue(options) = command else {
        panic!("issue expected")
    };
    assert_eq!(options.key_algorithm, KeyAlgorithm::EcdsaP256);
    assert!(Args::try_parse_from(["aster-acme", "cert", "issue", "--resume", "web"]).is_ok());
    for args in [
        vec!["--resume", "web", "--key-type", "ecdsa-p256"],
        vec!["-d", "example.com", "-k", "rsa-1024"],
        vec!["-d", "example.com", "-k", "unknown"],
    ] {
        assert!(
            Args::try_parse_from(
                ["aster-acme", "cert", "issue", "-c", "manual_dns"]
                    .into_iter()
                    .chain(args)
            )
            .is_err()
        );
    }
}

#[test]
fn revocation_reason_choices_follow_public_enum_without_a_second_cli_registry() {
    for reason in RevocationReason::ALL {
        let args = Args::try_parse_from([
            "aster-acme",
            "cert",
            "revoke",
            "web",
            "--reason",
            reason.name(),
            "--yes",
        ])
        .unwrap();
        let Command::Cert { command } = args.command else {
            panic!("certificate command expected")
        };
        let CertCommand::Revoke(RevokeArgs { reason: actual, .. }) = command else {
            panic!("revoke expected")
        };
        assert_eq!(actual, Some(reason));
    }
}
#[test]
fn renew_reuses_saved_definition_and_has_distinct_timing_dns_and_confirmation_flags() {
    for args in [
        vec![],
        vec!["web"],
        vec!["-n", "web", "--now", "--yes", "--json"],
    ] {
        assert!(
            Args::try_parse_from(["aster-acme", "cert", "renew"].into_iter().chain(args)).is_ok()
        );
    }
    for args in [
        vec!["--force"],
        vec!["-f"],
        vec!["--key-type", "rsa-2048"],
        vec!["-d", "example.com"],
        vec!["-a", "other"],
        vec!["--resume", "web"],
        vec!["--operation", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        vec!["web", "-n", "other"],
    ] {
        assert!(
            Args::try_parse_from(["aster-acme", "cert", "renew"].into_iter().chain(args)).is_err()
        );
    }
    for flag in ["--force", "-f"] {
        assert!(
            Args::try_parse_from([
                "aster-acme",
                "cert",
                "issue",
                "-d",
                "example.com",
                flag,
                "-c",
                "manual_dns"
            ])
            .is_err()
        );
    }
    let parsed = Args::try_parse_from(["aster-acme", "cert", "renew", "web", "--now"]).unwrap();
    let Command::Cert { command } = parsed.command else {
        panic!("cert expected")
    };
    let CertCommand::Renew(args) = command else {
        panic!("renew expected")
    };
    assert!(args.now);
    assert!(!args.run.yes);
}
#[test]
fn batch_renewal_all_conflicts_with_names_but_not_explicit_execution_policies() {
    for args in [vec!["--all"], vec!["--all", "--now", "--yes", "--json"]] {
        let parsed =
            Args::try_parse_from(["aster-acme", "cert", "renew"].into_iter().chain(args)).unwrap();
        let Command::Cert { command } = parsed.command else {
            panic!("expected cert")
        };
        let CertCommand::Renew(args) = command else {
            panic!("expected renew")
        };
        assert!(args.all);
    }
    for args in [
        vec!["web", "--all"],
        vec!["--all", "--name", "web"],
        vec![
            "--all",
            "--operation",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
        vec!["--all", "--force"],
    ] {
        assert!(
            Args::try_parse_from(["aster-acme", "cert", "renew"].into_iter().chain(args)).is_err()
        );
    }
}
#[test]
fn resume_distinguishes_absent_flag_interactive_selection_and_explicit_name() {
    for (args, expected) in [
        (vec!["-c", "manual_dns"], None),
        (vec!["--resume"], Some(ResumeTarget::Choose)),
        (
            vec!["--resume", "web"],
            Some(ResumeTarget::Named("web".to_owned())),
        ),
    ] {
        let parsed =
            Args::try_parse_from(["aster-acme", "cert", "issue"].into_iter().chain(args)).unwrap();
        let Command::Cert { command } = parsed.command else {
            panic!("cert expected")
        };
        let CertCommand::Issue(args) = command else {
            panic!("issue expected")
        };
        assert_eq!(args.resume, expected);
    }
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "--resume",
            "--operation",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ])
        .is_ok()
    );
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "--resume",
            "-d",
            "example.com"
        ])
        .is_err()
    );
}
#[test]
fn missing_issue_inputs_defer_to_completion_and_resume_cannot_override_method() {
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "--resume",
            "web",
            "-c",
            "manual_dns"
        ])
        .is_err()
    );
    for words in [
        vec![],
        vec!["-d", "example.com"],
        vec!["-d", "example.com", "--yes"],
        vec!["-c", "webroot"],
    ] {
        assert!(
            Args::try_parse_from(["aster-acme", "cert", "issue"].into_iter().chain(words)).is_ok()
        );
    }
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "-d",
            "example.com",
            "-c",
            "manual_dns",
            "--yes"
        ])
        .is_ok()
    );
    assert!(
        Args::try_parse_from(["aster-acme", "cert", "issue", "--resume", "web", "--yes"]).is_ok()
    );
    assert!(
        Args::try_parse_from(["aster-acme", "cert", "renew", "web", "-c", "manual_dns"]).is_err()
    );
}
