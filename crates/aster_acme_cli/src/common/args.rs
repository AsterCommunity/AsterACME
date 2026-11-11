//! Shared storage/output and HTTP flags. Command owners compose only applicable groups.

use aster_acme::crypto::key_algorithm::KeyAlgorithm;
use std::path::PathBuf;

#[derive(clap::Args, Default, Clone)]
pub(crate) struct LocalArgs {
    /// Unified state root (default: system directory for com.astercosm.acme).
    #[arg(long, value_name = "PATH", help_heading = "Storage and output")]
    pub(crate) data_dir: Option<PathBuf>,
    /// Structured JSON; disables interactive prompts and terminal styling.
    #[arg(long, help_heading = "Storage and output")]
    pub(crate) json: bool,
}

#[derive(clap::Args, Default, Clone)]
pub(crate) struct HttpArgs {
    /// HTTP User-Agent override; an explicit value during registration is saved for this account.
    #[arg(long)]
    pub(crate) user_agent: Option<String>,
    /// Whole-request timeout in seconds (1–300); used only for HTTP.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub(crate) timeout: Option<u64>,
}

/// Account names are local storage identifiers, shared by account targets and cert -a.
pub(crate) fn parse_account_name(value: &str) -> Result<String, String> {
    if aster_acme_cli_storage::valid_account_name(value) {
        Ok(value.to_owned())
    } else {
        Err("Use 1–64 ASCII letters, digits, hyphens or underscores for the account name.".into())
    }
}

pub(crate) fn key_algorithm_parser() -> impl clap::builder::TypedValueParser<Value = KeyAlgorithm> {
    clap::builder::TypedValueParser::try_map(
        clap::builder::PossibleValuesParser::new(KeyAlgorithm::ALL.map(KeyAlgorithm::name)),
        |value: String| {
            KeyAlgorithm::from_name(&value).ok_or_else(|| "unknown key algorithm".to_owned())
        },
    )
}

#[cfg(test)]
mod tests {
    use crate::app::{Args, Command};
    use clap::{CommandFactory, Parser};

    #[test]
    fn confirmation_and_bypass_flags_exist_only_on_their_own_commands() {
        let root = Args::command();
        for (group, commands) in [
            (
                "account",
                vec![
                    "list",
                    "show",
                    "switch",
                    "register",
                    "recover",
                    "update-contact",
                    "rotate-key",
                    "deactivate",
                    "remove",
                ],
            ),
            ("cert", vec!["issue", "renew", "list", "show"]),
        ] {
            for name in commands {
                let command = root
                    .find_subcommand(group)
                    .unwrap()
                    .find_subcommand(name)
                    .unwrap();
                let longs = command
                    .get_arguments()
                    .filter_map(clap::Arg::get_long)
                    .collect::<Vec<_>>();
                assert_eq!(
                    longs.contains(&"yes"),
                    matches!(
                        (group, name),
                        (
                            "account",
                            "register" | "update-contact" | "rotate-key" | "deactivate" | "remove"
                        ) | ("cert", "issue" | "renew")
                    ),
                    "{group} {name}"
                );
                assert_eq!(
                    longs.contains(&"skip-dns-check"),
                    matches!((group, name), ("cert", "issue" | "renew"))
                );
                assert_eq!(
                    longs.contains(&"accept-terms"),
                    (group, name) == ("account", "register")
                );
                assert!(longs.contains(&"json") && longs.contains(&"data-dir"));
                if let Some(yes) = command
                    .get_arguments()
                    .find(|arg| arg.get_long() == Some("yes"))
                {
                    assert_eq!(yes.get_short(), Some('y'));
                }
                assert!(!longs.contains(&"config") && !longs.contains(&"solver"));
            }
        }
    }

    #[test]
    fn account_contact_and_certificate_target_short_options_are_consistent() {
        for command in ["register", "update-contact"] {
            assert!(
                Args::try_parse_from([
                    "aster-acme",
                    "account",
                    command,
                    "work",
                    "-m",
                    "a@example.com",
                    "-y"
                ])
                .is_ok()
            );
        }
        for target in [
            vec!["example.com"],
            vec!["-n", "example.com"],
            vec!["--name", "example.com"],
        ] {
            assert!(
                Args::try_parse_from(["aster-acme", "cert", "show"].into_iter().chain(target))
                    .is_ok()
            );
        }
        assert!(
            Args::try_parse_from([
                "aster-acme",
                "cert",
                "show",
                "example.com",
                "-n",
                "other.example"
            ])
            .is_err()
        );
        for invalid in ["../escape", "a/b", ""] {
            assert!(Args::try_parse_from(["aster-acme", "cert", "show", invalid]).is_err());
            assert!(
                Args::try_parse_from([
                    "aster-acme",
                    "cert",
                    "issue",
                    "-d",
                    "example.com",
                    "-a",
                    invalid
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn json_and_yes_do_not_imply_terms_force_or_other_confirmation() {
        let parsed = Args::try_parse_from([
            "aster-acme",
            "account",
            "register",
            "work",
            "--yes",
            "--json",
        ])
        .unwrap();
        let Command::Account { command } = parsed.command else {
            panic!("expected account");
        };
        let crate::commands::account::args::AccountCommand::Register(args) = command else {
            panic!("expected register");
        };
        assert!(args.yes);
        assert!(!args.accept_terms);
        let parsed = Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "-d",
            "example.com",
            "--json",
            "-c",
            "manual_dns",
        ])
        .unwrap();
        let Command::Cert { command } = parsed.command else {
            panic!("expected cert");
        };
        let crate::commands::cert::args::CertCommand::Issue(args) = command else {
            panic!("expected issue");
        };
        assert!(!args.run.yes);
        assert!(!args.run.skip_dns_check);
    }

    #[test]
    fn account_key_choices_share_certificate_spellings_and_only_apply_to_registration_or_rotation()
    {
        use crate::commands::account::args::AccountCommand;
        use aster_acme::crypto::key_algorithm::KeyAlgorithm;
        for algorithm in KeyAlgorithm::ALL {
            for command in ["register", "rotate-key"] {
                let args = Args::try_parse_from([
                    "aster-acme",
                    "account",
                    command,
                    "-k",
                    algorithm.name(),
                ])
                .unwrap();
                let Command::Account { command } = args.command else {
                    panic!("expected account");
                };
                let choice = match command {
                    AccountCommand::Register(args) => args.key_algorithm,
                    AccountCommand::RotateKey(args) => args.key_algorithm,
                    _ => panic!("wrong command"),
                };
                assert_eq!(choice, Some(algorithm));
            }
        }
        for command in ["register", "rotate-key"] {
            for unsupported in ["rsa-1024", "ec-256", "ES256", "unknown"] {
                assert!(
                    Args::try_parse_from([
                        "aster-acme",
                        "account",
                        command,
                        "--key-type",
                        unsupported
                    ])
                    .is_err()
                );
            }
        }
        for command in [
            "show",
            "list",
            "recover",
            "switch",
            "remove",
            "deactivate",
            "update-contact",
        ] {
            assert!(
                Args::try_parse_from([
                    "aster-acme",
                    "account",
                    command,
                    "--key-type",
                    "ecdsa-p256"
                ])
                .is_err()
            );
        }
    }
}
