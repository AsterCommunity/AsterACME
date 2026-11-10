//! Certificate issuance and read-only order command arguments.

use crate::common::args::{HttpArgs, LocalArgs, parse_account_name};
use aster_acme::issuance::key_algorithm::CertificateKeyAlgorithm;
use aster_acme_protocol::revocation::RevocationReason;
use clap::{Args, Subcommand, ValueEnum, builder::TypedValueParser as _};

#[derive(Subcommand)]
pub(crate) enum CertCommand {
    /// Issue a certificate with manual DNS publication, or resume a saved request.
    Issue(IssueArgs),
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
    #[command(group(clap::ArgGroup::new("certificate_http").args(["user_agent","timeout"]).multiple(true).requires("verify")))]
    Show {
        #[command(flatten)]
        target: SavedTargetArgs,
        /// Select a historical request rather than defaulting to current.
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
        #[arg(long, conflicts_with_all = ["operation", "history", "revoked"])]
        all: bool,
        /// Remove issued historical versions; retain current and unfinished requests.
        #[arg(long, conflicts_with_all = ["operation", "all", "revoked"])]
        history: bool,
        /// Remove versions with a saved CA revocation confirmation, including current if matched.
        #[arg(long, conflicts_with_all = ["operation", "all", "history"])]
        revoked: bool,
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

fn key_algorithm_parser() -> impl clap::builder::TypedValueParser<Value = CertificateKeyAlgorithm> {
    clap::builder::PossibleValuesParser::new(
        CertificateKeyAlgorithm::ALL.map(CertificateKeyAlgorithm::name),
    )
    .try_map(|value: String| {
        CertificateKeyAlgorithm::from_name(&value)
            .ok_or_else(|| "unknown certificate key algorithm".to_owned())
    })
}

/// User-facing verification implementation; the ACME wire method stays internal.
#[derive(Clone, Copy, ValueEnum, Default)]
pub(crate) enum Challenge {
    /// Publish the requested DNS TXT records yourself.
    #[default]
    #[value(name = "manual_dns")]
    ManualDns,
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
    pub key_algorithm: CertificateKeyAlgorithm,
    /// How to validate domain ownership.
    #[arg(short = 'c', long, value_enum, default_value = "manual_dns")]
    pub challenge: Challenge,
    /// Resume by certificate name; select interactively when several requests are unfinished.
    #[arg(long, value_name = "CERTIFICATE",value_parser=parse_certificate_name)]
    pub resume: Option<String>,
    /// Exact saved request ID; required for ambiguous noninteractive recovery.
    #[arg(long, requires = "resume",value_parser=parse_operation, conflicts_with_all = ["domain", "name", "account"])]
    pub operation: Option<String>,
    /// Skip the manual TXT confirmation when resuming; DNS checks still run.
    #[arg(short = 'y', long)]
    pub yes: bool,
    /// Skip only local DNS visibility checks; the CA still validates the challenge.
    #[arg(short = 'f', long)]
    pub force: bool,
    /// Overall invocation budget in seconds; expiry is an independent CA deadline.
    #[arg(long,default_value="600",value_parser=clap::value_parser!(u64).range(1..=86400))]
    pub wait_timeout: u64,
    #[command(flatten)]
    pub http: HttpArgs,
    #[command(flatten)]
    pub local: LocalArgs,
}

impl CertCommand {
    pub(crate) fn json(&self) -> bool {
        match self {
            Self::Issue(args) => args.local.json,
            Self::List { local, .. }
            | Self::Show { local, .. }
            | Self::Revoke { local, .. }
            | Self::Remove { local, .. } => local.json,
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
    use super::*;
    use crate::app::{Args, Command};
    use clap::Parser;

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
                *command,
                CertCommand::Revoke {
                    yes: true,
                    reason: Some(RevocationReason::KeyCompromise),
                    ..
                }
            ));
        }
        for args in [
            vec!["example.com", "-n", "other.com"],
            vec!["--force"],
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
            assert!(matches!(*command, CertCommand::Remove { yes: true, .. }));
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
            vec!["--force"],
            vec!["--timeout", "30"],
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
        for algorithm in CertificateKeyAlgorithm::ALL {
            let args = Args::try_parse_from([
                "aster-acme",
                "cert",
                "issue",
                "-d",
                "example.com",
                "-k",
                algorithm.name(),
            ])
            .unwrap();
            let Command::Cert { command } = args.command else {
                panic!("certificate command expected")
            };
            let CertCommand::Issue(options) = *command else {
                panic!("issue expected")
            };
            assert_eq!(options.key_algorithm, algorithm);
        }
        let args =
            Args::try_parse_from(["aster-acme", "cert", "issue", "-d", "example.com"]).unwrap();
        let Command::Cert { command } = args.command else {
            panic!("certificate command expected")
        };
        let CertCommand::Issue(options) = *command else {
            panic!("issue expected")
        };
        assert_eq!(options.key_algorithm, CertificateKeyAlgorithm::EcdsaP256);
        assert!(Args::try_parse_from(["aster-acme", "cert", "issue", "--resume", "web"]).is_ok());
        for args in [
            vec!["--resume", "web", "--key-type", "ecdsa-p256"],
            vec!["-d", "example.com", "-k", "rsa-1024"],
            vec!["-d", "example.com", "-k", "unknown"],
        ] {
            assert!(
                Args::try_parse_from(["aster-acme", "cert", "issue"].into_iter().chain(args))
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
            let CertCommand::Revoke { reason: actual, .. } = *command else {
                panic!("revoke expected")
            };
            assert_eq!(actual, Some(reason));
        }
    }
}
