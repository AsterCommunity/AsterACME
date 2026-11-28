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
    #[command(group(clap::ArgGroup::new("certificate_http").args(["user_agent","request_timeout","operation_timeout"]).multiple(true).requires("verify")))]
    Show {
        #[command(flatten)]
        target: SavedTargetArgs,
        /// Select a historical request rather than defaulting to `in_use`.
        #[arg(long, conflicts_with = "operation")]
        history: bool,
        /// Query existing order/authorizations and refresh due ARI; never advance issuance.
        #[arg(long)]
        verify: bool,
        /// Overall CA inspection budget in seconds; defaults to the configured operation timeout.
        #[arg(long,value_parser=clap::value_parser!(u64).range(1..=86400))]
        operation_timeout: Option<u64>,
        #[command(flatten)]
        http: HttpArgs,
        #[command(flatten)]
        local: LocalArgs,
    },
    /// Permanently revoke one issued certificate at its CA; local files are retained.
    Revoke(RevokeArgs),
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

/// Explicit revocation parameters; certificate-key authority never loads an account.
#[derive(Args)]
pub(crate) struct RevokeArgs {
    #[command(flatten)]
    pub target: SavedTargetArgs,
    /// Signature authority; never inferred from missing or rejected account credentials.
    #[arg(long="sign-with",value_parser=revocation_signing_parser(),default_value="account")]
    pub sign_with: aster_acme::revocation::RevocationSigningMethod,
    /// Revocation reason; omitted by default or retained from an unconfirmed request.
    #[arg(long,value_parser=revocation_reason_parser())]
    pub reason: Option<RevocationReason>,
    /// Confirm revocation without a prompt.
    #[arg(short = 'y', long)]
    pub yes: bool,
    /// Overall operation budget in seconds; includes discovery and confirmation.
    #[arg(long,value_parser=clap::value_parser!(u64).range(1..=86400))]
    pub operation_timeout: Option<u64>,
    #[command(flatten)]
    pub http: HttpArgs,
    #[command(flatten)]
    pub local: LocalArgs,
}

fn revocation_signing_parser()
-> impl clap::builder::TypedValueParser<Value = aster_acme::revocation::RevocationSigningMethod> {
    use aster_acme::revocation::RevocationSigningMethod;
    clap::builder::PossibleValuesParser::new(
        RevocationSigningMethod::ALL.map(RevocationSigningMethod::name),
    )
    .try_map(|value: String| {
        RevocationSigningMethod::ALL
            .into_iter()
            .find(|method| method.name() == value)
            .ok_or_else(|| "unknown revocation signing method".to_owned())
    })
}

/// One saved generation, shared by read-only inspection and revocation.
#[derive(Args)]
pub(crate) struct SavedTargetArgs {
    #[command(flatten)]
    pub identity: CertificateNameArgs,
    /// Exact request ID when the name has multiple generations.
    #[arg(long, allow_hyphen_values = true,value_parser=parse_operation)]
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
    /// DNS identifier; repeat for SANs. With DNS identifiers present the first -d is primary; otherwise the first --ip is.
    #[arg(
        short = 'd',
        long,
        conflicts_with = "resume",
        value_parser = parse_domain
    )]
    pub domain: Vec<aster_acme::identifier::DnsIdentifier>,
    /// IP identifier ([RFC 8738](https://datatracker.ietf.org/doc/html/rfc8738)); repeat for SANs. Requires HTTP-01 or TLS-ALPN-01 validation.
    #[arg(
        long = "ip",
        value_name = "ADDRESS",
        conflicts_with = "resume",
        value_parser = parse_ip
    )]
    pub ip: Vec<aster_acme::identifier::IpIdentifier>,
    /// Local account; default is the configured default account.
    #[arg(short = 'a', long, conflicts_with = "resume",value_parser=parse_account_name)]
    pub account: Option<String>,
    /// Certificate key algorithm; CA acceptance varies. Account signing key is unchanged.
    #[arg(short = 'k', long = "key-type", value_parser = key_algorithm_parser(), default_value = "ecdsa-p256", conflicts_with = "resume")]
    pub key_algorithm: KeyAlgorithm,
    /// CA certificate profile (e.g. shortlived for IP identifiers on Let's Encrypt);
    /// the CA directory must advertise it. Omitted keeps the CA default.
    #[arg(long, value_name = "NAME", conflicts_with = "resume", value_parser = parse_profile)]
    pub profile: Option<String>,
    /// Certificate chain to use for this issuance only among the CA's offered chains
    /// ([RFC 8555 §7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2));
    /// matched case-insensitively against the top-most certificate's RFC 4514
    /// distinguished name or its common name. It is not saved for renewals
    /// and may be supplied together with --resume to replace the saved choice.
    #[arg(
        long = "chain",
        value_name = "CHAIN",
        conflicts_with_all = ["preferred_chain", "default_chain"],
        value_parser = parse_chain_name
    )]
    pub chain: Option<aster_acme::issuance::ChainName>,
    /// Certificate chain to use now and retain as a soft preference for future renewals.
    #[arg(
        long,
        value_name = "CHAIN",
        conflicts_with = "default_chain",
        value_parser = parse_chain_name
    )]
    pub preferred_chain: Option<aster_acme::issuance::ChainName>,
    /// Use the CA default certificate chain for this issuance and do not save a preference.
    #[arg(long, conflicts_with_all = ["chain", "preferred_chain"])]
    pub default_chain: bool,
    /// Validation implementation; omitted prompts on terminals, required in scripts.
    #[arg(short = 'c', long, value_enum, conflicts_with = "resume")]
    pub challenge: Option<crate::commands::cert::validation::ValidationMethod>,
    /// Resume one fully matching unfinished request; multiple matches require an explicit target.
    #[arg(long, conflicts_with_all = ["resume", "name"])]
    pub if_similar_order: bool,
    /// Document root of your existing public HTTP server; persisted for resume/renew.
    #[arg(short = 'w', long, value_name = "PATH", conflicts_with = "resume")]
    pub webroot: Option<std::path::PathBuf>,
    /// Temporary validation listener socket: port 80 for standalone or 443 for `tls_alpn`; saved for resume/renew.
    #[arg(long, value_name = "IP:PORT", conflicts_with = "resume")]
    pub listen_address: Option<std::net::SocketAddr>,
    /// DNS provider profile; valid only with `-c dns_provider`.
    #[arg(long, value_parser = parse_certificate_name, conflicts_with = "resume")]
    pub provider: Option<String>,
    /// Map a requested DOMAIN to its complete final `TXT_NAME`; repeat for multiple domains.
    /// Example: example.com=_acme-challenge.example.com
    #[arg(
        long = "dns-target",
        value_name = "DOMAIN=TXT_NAME",
        conflicts_with = "resume"
    )]
    pub dns_targets: Vec<String>,
    /// Resume a saved request; omit the name to choose unfinished requests interactively.
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_name = "CERTIFICATE", value_parser = parse_resume)]
    pub resume: Option<ResumeTarget>,
    /// Exact saved request ID; required for ambiguous noninteractive recovery.
    #[arg(long, allow_hyphen_values = true, requires = "resume",value_parser=parse_operation, conflicts_with_all = ["domain", "name", "account"])]
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
            Self::List { local, .. } | Self::Show { local, .. } | Self::Remove { local, .. } => {
                local.json
            }
            Self::Deploy(args) => args.local().json,
            Self::Revoke(args) => args.local.json,
        }
    }
}

fn parse_domain(value: &str) -> Result<aster_acme::identifier::DnsIdentifier, String> {
    aster_acme::identifier::DnsIdentifier::new(value).map_err(|error| error.to_string())
}

fn parse_ip(value: &str) -> Result<aster_acme::identifier::IpIdentifier, String> {
    aster_acme::identifier::IpIdentifier::new(value).map_err(|error| error.to_string())
}

pub(crate) fn parse_profile(value: &str) -> Result<String, String> {
    // The profiles draft caps nothing about the name; only emptiness and
    // control characters are rejected here. CA advertisement decides the rest.
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err("a certificate profile is a nonempty name without control characters".into());
    }
    Ok(value.to_owned())
}

fn parse_chain_name(value: &str) -> Result<aster_acme::issuance::ChainName, String> {
    aster_acme::issuance::ChainName::new(value).map_err(|error| error.to_string())
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
mod tests;

#[test]
fn profile_names_reject_emptiness_control_characters_and_multibyte_names_pass() {
    assert_eq!(parse_profile("shortlived").unwrap().as_str(), "shortlived");
    assert!(parse_profile("").is_err());
    assert!(parse_profile("short\nlived").is_err());
    // The profiles draft caps nothing about length or encoding: a CA may
    // advertise multibyte names (22 chars of 型 = 66 bytes) and must parse.
    let multibyte = "\u{578b}".repeat(22);
    assert_eq!(parse_profile(&multibyte).unwrap().as_str(), multibyte);
}

#[test]
fn chain_flags_are_mutually_exclusive_and_off_resume() {
    let command = IssueArgs::augment_args(clap::Command::new("issue"));
    let parse = |arguments: &[&str]| {
        command
            .clone()
            .try_get_matches_from(arguments.to_vec())
            .is_ok()
    };
    assert!(parse(&["issue", "--chain", "ISRG Root X1"]));
    assert!(parse(&["issue", "--preferred-chain", "ISRG Root X1"]));
    assert!(parse(&["issue", "--default-chain"]));
    assert!(!parse(&[
        "issue",
        "--preferred-chain",
        "X",
        "--default-chain"
    ]));
    assert!(parse(&["issue", "--resume", "web", "--chain", "X"]));
    assert!(parse(&[
        "issue",
        "--resume",
        "web",
        "--preferred-chain",
        "X"
    ]));
}

#[test]
fn chain_names_accept_distinguished_and_common_names_but_reject_unsafe_input() {
    parse_chain_name("CN=ISRG Root X1,O=ISRG,C=US").unwrap();
    parse_chain_name("ISRG Root X1").unwrap();
    assert!(parse_chain_name("").is_err());
    assert!(parse_chain_name("root\nx1").is_err());
}
