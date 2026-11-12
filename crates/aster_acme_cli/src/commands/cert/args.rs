//! Certificate issuance and read-only order command arguments.

use crate::common::args::{HttpArgs, LocalArgs, key_algorithm_parser, parse_account_name};
use aster_acme::crypto::key_algorithm::KeyAlgorithm;
use aster_acme_protocol::revocation::RevocationReason;
use clap::{Args, Subcommand, builder::TypedValueParser as _};

pub(crate) mod deployment;

#[derive(Subcommand)]
pub(crate) enum CertCommand {
    /// Issue using a selected validation implementation, or resume a saved request.
    Issue(IssueArgs),
    /// Renew the `in_use` certificate using its saved definition, or resume its renewal.
    Renew(RenewArgs),
    /// Configure and run deployments bound to a managed certificate.
    Deploy(deployment::DeployArgs),
    /// List managed certificates; use --history to include every saved request.
    List {
        /// Include historical versions and unfinished requests instead of one row per certificate.
        #[arg(long)]
        history: bool,
        /// Restrict the list to one certificate name.
        #[arg(short = 'n', long,value_parser=parse_certificate_name)]
        name: Option<String>,
        #[command(flatten)]
        local: LocalArgs,
    },
    /// Show a local certificate request, or explicitly refresh its CA resources without advancing it.
    #[command(group(clap::ArgGroup::new("certificate_http").args(["user_agent","request_timeout"]).multiple(true).requires("verify")))]
    Show {
        #[command(flatten)]
        target: SavedTargetArgs,
        /// Select a historical request rather than defaulting to `in_use`.
        #[arg(long, conflicts_with = "operation")]
        history: bool,
        /// Query existing order/authorizations and refresh due ARI; never advance issuance.
        #[arg(long)]
        verify: bool,
        #[command(flatten)]
        http: HttpArgs,
        #[command(flatten)]
        local: LocalArgs,
    },
    /// Permanently revoke one issued certificate at its CA; local files are retained.
    Revoke {
        #[command(flatten)]
        target: SavedTargetArgs,
        /// Permanent revocation reason; omitted by default, or retained from an unconfirmed request.
        #[arg(long, value_parser = revocation_reason_parser())]
        reason: Option<RevocationReason>,
        /// Confirm revocation without an interactive prompt.
        #[arg(short = 'y', long)]
        yes: bool,
        #[command(flatten)]
        http: HttpArgs,
        #[command(flatten)]
        local: LocalArgs,
    },
    /// Remove one local request, or explicitly select history/all; does not revoke certificates.
    Remove {
        #[command(flatten)]
        target: SavedTargetArgs,
        /// Remove every local request and key under this certificate name.
        #[arg(long, conflicts_with_all = ["operation", "history", "revoked", "failed"])]
        all: bool,
        /// Remove issued historical versions; retain `in_use` and unfinished requests.
        #[arg(long, conflicts_with_all = ["operation", "all", "revoked", "failed"])]
        history: bool,
        /// Remove versions with a saved CA revocation confirmation, including `in_use` if matched.
        #[arg(long, conflicts_with_all = ["operation", "all", "history", "failed"])]
        revoked: bool,
        /// Remove terminally failed, unissued requests that cannot resume; retain uncertain requests.
        #[arg(long, conflicts_with_all = ["operation", "all", "history", "revoked"])]
        failed: bool,
        /// Confirm deletion of local certificate material without prompting.
        #[arg(short = 'y', long)]
        yes: bool,
        #[command(flatten)]
        local: LocalArgs,
    },
}

/// One saved generation, shared by read-only inspection and revocation.
#[derive(Args)]
pub(crate) struct SavedTargetArgs {
    #[command(flatten)]
    pub identity: CertificateNameArgs,
    /// Exact request ID when the name has multiple generations.
    #[arg(long,value_parser=parse_operation)]
    pub operation: Option<String>,
}

/// A local certificate name, independent of generation selection.
#[derive(Args)]
pub(crate) struct CertificateNameArgs {
    /// Certificate name; omit to select interactively.
    #[arg(value_parser=parse_certificate_name,conflicts_with="named_name")]
    pub name: Option<String>,
    /// Local certificate name; equivalent to the positional NAME.
    #[arg(short='n',long="name",value_name="NAME",conflicts_with="name",value_parser=parse_certificate_name)]
    pub named_name: Option<String>,
}

fn revocation_reason_parser() -> impl clap::builder::TypedValueParser<Value = RevocationReason> {
    clap::builder::PossibleValuesParser::new(RevocationReason::ALL.map(RevocationReason::name))
        .try_map(|value: String| {
            RevocationReason::from_name(&value)
                .ok_or_else(|| "unknown revocation reason".to_owned())
        })
}

/// Explicit recovery intent distinguishes an omitted flag from terminal selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResumeTarget {
    Choose,
    Named(String),
}

fn parse_resume(value: &str) -> Result<ResumeTarget, String> {
    match value {
        "" => Ok(ResumeTarget::Choose),
        name => parse_certificate_name(name).map(ResumeTarget::Named),
    }
}

#[derive(Args)]
pub(crate) struct IssueArgs {
    /// Local certificate name; default is the primary domain plus a random suffix.
    #[arg(short = 'n', long, conflicts_with = "resume",value_parser=parse_certificate_name)]
    pub name: Option<String>,
    /// DNS identifier; repeat for SANs. First is the primary domain.
    #[arg(
        short = 'd',
        long,
        conflicts_with = "resume",
        value_parser = parse_domain
    )]
    pub domain: Vec<aster_acme::identifier::DnsIdentifier>,
    /// Local account; default is the configured default account.
    #[arg(short = 'a', long, conflicts_with = "resume",value_parser=parse_account_name)]
    pub account: Option<String>,
    /// Certificate key algorithm; CA acceptance varies. Account signing key is unchanged.
    #[arg(short = 'k', long = "key-type", value_parser = key_algorithm_parser(), default_value = "ecdsa-p256", conflicts_with = "resume")]
    pub key_algorithm: KeyAlgorithm,
    /// Validation implementation; omitted prompts on terminals, required in scripts.
    #[arg(short = 'c', long, value_enum, conflicts_with = "resume")]
    pub challenge: Option<super::validation::ValidationMethod>,
    /// Resume one fully matching unfinished request; multiple matches require an explicit target.
    #[arg(long, conflicts_with_all = ["resume", "name"])]
    pub if_similar_order: bool,
    /// Document root of your existing public HTTP server; persisted for resume/renew.
    #[arg(short = 'w', long, value_name = "PATH", conflicts_with = "resume")]
    pub webroot: Option<std::path::PathBuf>,
    /// Temporary validation listener socket: port 80 for standalone or 443 for `tls_alpn`; saved for resume/renew.
    #[arg(long, value_name = "IP:PORT", conflicts_with = "resume")]
    pub listen_address: Option<std::net::SocketAddr>,
    /// Resume a saved request; omit the name to choose unfinished requests interactively.
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_name = "CERTIFICATE", value_parser = parse_resume)]
    pub resume: Option<ResumeTarget>,
    /// Exact saved request ID; required for ambiguous noninteractive recovery.
    #[arg(long, requires = "resume",value_parser=parse_operation, conflicts_with_all = ["domain", "name", "account"])]
    pub operation: Option<String>,
    #[command(flatten)]
    pub run: RunArgs,
}

/// Foreground validation policy shared by initial issuance and renewal.
#[derive(Args, Clone)]
pub(crate) struct RunArgs {
    /// Local CA polling interval in seconds (1–300); config `poll_interval`, default 5; Retry-After wins.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub poll_interval: Option<u64>,
    /// Maximum order-poll rounds per certificate/invocation; CA Retry-After still applies.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub max_polls: Option<u32>,
    /// Automatically accept all operation confirmations; does not supply inputs or bypass validation.
    #[arg(short = 'y', long)]
    pub yes: bool,
    /// Overall invocation budget in seconds; expiry is an independent CA deadline.
    #[arg(long,value_parser=clap::value_parser!(u64).range(1..=86400))]
    pub operation_timeout: Option<u64>,
    #[command(flatten)]
    pub http: HttpArgs,
    #[command(flatten)]
    pub local: LocalArgs,
}

/// Resolve execution defaults once for all issue/resume/renew paths. Clap keeps
/// omitted options as None so its defaults never mask explicit configuration.
impl RunArgs {
    pub(super) fn limits(&self, config: &crate::config::Config) -> (u64, u32, u64) {
        (
            self.operation_timeout
                .or(config.operation_timeout)
                .unwrap_or(600),
            self.max_polls.or(config.max_polls).unwrap_or(30),
            self.poll_interval.or(config.poll_interval).unwrap_or(5),
        )
    }
}

#[derive(Args)]
pub(crate) struct RenewArgs {
    #[command(flatten)]
    pub target: CertificateNameArgs,
    /// Check every managed certificate sequentially; report each outcome without prompts.
    #[arg(long, conflicts_with_all = ["name", "named_name"])]
    pub all: bool,
    /// Renew before the saved renewal time; does not bypass validation or confirmation.
    #[arg(long)]
    pub now: bool,
    #[command(flatten)]
    pub run: RunArgs,
}

impl CertCommand {
    pub(crate) fn json(&self) -> bool {
        match self {
            Self::Issue(args) => args.run.local.json,
            Self::Renew(args) => args.run.local.json,
            Self::List { local, .. }
            | Self::Show { local, .. }
            | Self::Revoke { local, .. }
            | Self::Remove { local, .. } => local.json,
            Self::Deploy(args) => args.local().json,
        }
    }
}

fn parse_domain(value: &str) -> Result<aster_acme::identifier::DnsIdentifier, String> {
    aster_acme::identifier::DnsIdentifier::new(value).map_err(|error| error.to_string())
}

fn parse_certificate_name(value: &str) -> Result<String, String> {
    aster_acme::issuance::CertificateName::new(value)
        .map(|name| name.as_str().to_owned())
        .map_err(|error| error.to_string())
}

fn parse_operation(value: &str) -> Result<String, String> {
    if aster_acme_cli_storage::issuance::valid_operation_id(value) {
        Ok(value.to_owned())
    } else {
        Err("Use the complete saved request ID shown by cert show.".into())
    }
}

#[cfg(test)]
mod tests {
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
                CertCommand::Revoke {
                    yes: true,
                    reason: Some(RevocationReason::KeyCompromise),
                    ..
                }
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
                Args::try_parse_from(["aster-acme", "cert", "revoke"].into_iter().chain(args))
                    .is_err()
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
                Args::try_parse_from(["aster-acme", "cert", "remove"].into_iter().chain(args))
                    .is_err()
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
            let CertCommand::Revoke { reason: actual, .. } = command else {
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
                Args::try_parse_from(["aster-acme", "cert", "renew"].into_iter().chain(args))
                    .is_ok()
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
                Args::try_parse_from(["aster-acme", "cert", "renew"].into_iter().chain(args))
                    .is_err()
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
                Args::try_parse_from(["aster-acme", "cert", "renew"].into_iter().chain(args))
                    .unwrap();
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
                Args::try_parse_from(["aster-acme", "cert", "renew"].into_iter().chain(args))
                    .is_err()
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
                Args::try_parse_from(["aster-acme", "cert", "issue"].into_iter().chain(args))
                    .unwrap();
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
                Args::try_parse_from(["aster-acme", "cert", "issue"].into_iter().chain(words))
                    .is_ok()
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
            Args::try_parse_from(["aster-acme", "cert", "issue", "--resume", "web", "--yes"])
                .is_ok()
        );
        assert!(
            Args::try_parse_from(["aster-acme", "cert", "renew", "web", "-c", "manual_dns"])
                .is_err()
        );
    }
}
