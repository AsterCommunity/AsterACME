//! Provider command-line inputs.
use crate::common::args::{LocalArgs, parse_account_name};
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum ProviderCommand {
    /// List backend types available in this build and their configuration fields.
    Backends(LocalArgs),
    /// Register a named DNS provider profile.
    Add(AddArgs),
    /// List configured provider profile names and safe metadata.
    List(LocalArgs),
    /// Show one provider profile with all custom values redacted.
    Show(ShowArgs),
    /// Retry owned DNS cleanup for terminal requests using this provider profile.
    Cleanup(ShowArgs),
    /// Update configuration for a DNS provider profile.
    Update(UpdateArgs),
    /// Remove a provider profile that no retained certificate references.
    Remove(RemoveArgs),
}

impl ProviderCommand {
    pub(crate) fn local(&self) -> &LocalArgs {
        match self {
            Self::Add(args) => &args.local,
            Self::List(local) | Self::Backends(local) => local,
            Self::Show(args) | Self::Cleanup(args) => &args.local,
            Self::Update(args) => &args.local,
            Self::Remove(args) => &args.local,
        }
    }
}

#[derive(Args)]
pub(crate) struct AddArgs {
    /// Stable provider profile name; prompt when omitted on a terminal.
    #[arg(value_parser = parse_account_name)]
    pub(super) name: Option<String>,
    /// Absolute executable path; no shell is used.
    #[arg(long, value_name = "PATH")]
    pub(super) exec: Option<PathBuf>,
    /// Backend type ID; defaults to ADPP when --exec is supplied.
    #[arg(long, value_name = "ID")]
    pub(super) backend: Option<String>,
    #[arg(skip)]
    pub(super) custom: serde_json::Map<String, serde_json::Value>,
    /// Private TOML file containing backend-owned configuration values.
    #[arg(long, value_name = "PATH")]
    pub(super) settings_file: Option<PathBuf>,
    /// Exact argument; repeat to build argv. Never put secrets here.
    #[arg(long = "arg", value_name = "VALUE")]
    pub(super) args: Vec<String>,
    /// Optional allowed DNS zone suffix; repeat to restrict, omit to allow all zones.
    #[arg(long = "allow-zone", value_name = "DOMAIN")]
    pub(super) allowed_zones: Vec<String>,
    /// Requested DNS TTL in seconds (0..=2147483647); backends may apply their limits.
    #[arg(long, value_parser = clap::value_parser!(u32).range(0..=2_147_483_647))]
    pub(super) ttl_seconds: Option<u32>,
    #[command(flatten)]
    pub(super) local: LocalArgs,
}

#[derive(Args)]
pub(crate) struct ShowArgs {
    /// Stable provider profile name; choose interactively when omitted.
    #[arg(value_parser = parse_account_name)]
    pub(super) name: Option<String>,
    #[command(flatten)]
    pub(super) local: LocalArgs,
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("provider_changes").args(["exec", "args", "clear_args", "allowed_zones", "clear_zones", "settings_file"]).multiple(true)))]
pub(crate) struct UpdateArgs {
    /// Stable provider profile name; choose interactively when omitted.
    #[arg(value_parser = parse_account_name)]
    pub(super) name: Option<String>,
    /// Replace the executable path.
    #[arg(long, value_name = "PATH")]
    pub(super) exec: Option<PathBuf>,
    /// Replace argv with the supplied exact arguments.
    #[arg(long = "arg", value_name = "VALUE", num_args = 1.., conflicts_with = "clear_args")]
    pub(super) args: Option<Vec<String>>,
    /// Remove all saved argv values.
    #[arg(long, conflicts_with = "args")]
    pub(super) clear_args: bool,
    /// Replace the allowed zone suffix set.
    #[arg(long = "allow-zone", value_name = "DOMAIN", num_args = 1.., conflicts_with = "clear_zones")]
    pub(super) allowed_zones: Option<Vec<String>>,
    /// Clear zone restrictions and allow all valid publication owners.
    #[arg(long, conflicts_with = "allowed_zones")]
    pub(super) clear_zones: bool,
    /// Replace backend-owned configuration from a private TOML file.
    #[arg(long, value_name = "PATH")]
    pub(super) settings_file: Option<PathBuf>,
    /// Requested DNS TTL in seconds (0..=2147483647); backends may apply their limits.
    #[arg(long, value_parser = clap::value_parser!(u32).range(0..=2_147_483_647))]
    pub(super) ttl_seconds: Option<u32>,
    #[command(flatten)]
    pub(super) local: LocalArgs,
}

#[derive(Args)]
pub(crate) struct RemoveArgs {
    /// Stable provider profile name; choose interactively when omitted.
    #[arg(value_parser = parse_account_name)]
    pub(super) name: Option<String>,
    /// Confirm removal without prompting.
    #[arg(short = 'y', long)]
    pub(super) yes: bool,
    #[command(flatten)]
    pub(super) local: LocalArgs,
}
