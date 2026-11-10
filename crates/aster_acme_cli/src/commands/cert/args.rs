//! Certificate issuance and read-only order command arguments.

use crate::common::args::{HttpArgs, LocalArgs, parse_account_name};
use clap::{Args, Subcommand, ValueEnum};

#[derive(Subcommand)]
pub(crate) enum CertCommand {
    /// Issue a certificate with manual DNS publication, or resume a saved request.
    Issue(IssueArgs),
    /// List saved certificate requests without HTTP.
    List {
        /// Restrict the list to one certificate name.
        #[arg(short = 'n', long,value_parser=parse_certificate_name)]
        name: Option<String>,
        #[command(flatten)]
        local: LocalArgs,
    },
    /// Show a local certificate request, or explicitly refresh its CA resources without advancing it.
    #[command(group(clap::ArgGroup::new("certificate_http").args(["user_agent","timeout"]).multiple(true).requires("verify")))]
    Show {
        /// Certificate name; omit to select interactively.
        #[arg(value_parser=parse_certificate_name,conflicts_with="named_name")]
        name: Option<String>,
        /// Local certificate name; equivalent to the positional NAME.
        #[arg(short='n',long="name",value_name="NAME",conflicts_with="name",value_parser=parse_certificate_name)]
        named_name: Option<String>,
        /// Exact request ID when the name has multiple generations.
        #[arg(long,value_parser=parse_operation)]
        operation: Option<String>,
        /// Query existing order and authorizations; never submit validation or finalize.
        #[arg(long)]
        verify: bool,
        #[command(flatten)]
        http: HttpArgs,
        #[command(flatten)]
        local: LocalArgs,
    },
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
    /// Local certificate name; default is the first normalized domain (wildcard retained).
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
            Self::List { local, .. } | Self::Show { local, .. } => local.json,
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
