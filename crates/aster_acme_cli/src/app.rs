//! Static root command tree, following `AsterDrive` CLI ownership.

use crate::{commands::account::args::AccountCommand, common::help};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aster-acme", version, about = "An ACME client for certificate issuance and management.", styles = help::help_styles())]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Manage ACME accounts and the local default selection.
    Account {
        #[command(subcommand)]
        command: Box<AccountCommand>,
    },
    /// Issue and manage certificates.
    Cert {
        #[command(subcommand)]
        command: Box<crate::commands::cert::args::CertCommand>,
    },
    /// Show version, revision, target, profile, enabled features and build time.
    Version {
        /// Structured JSON build metadata.
        #[arg(long)]
        json: bool,
    },
}

impl Args {
    /// Build the shared help layout before parsing so nested help uses the same identity.
    pub(crate) fn parse() -> Self {
        let matches = help::configure(Self::command()).get_matches();
        Self::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
    }

    /// Resolve error output before moving the command into the dispatcher.
    pub(crate) fn json(&self) -> bool {
        match &self.command {
            Command::Cert { command } => command.json(),
            Command::Version { json } => *json,
            Command::Account { command } => command.json(),
        }
    }
}
