//! Static root command tree, following `AsterDrive` CLI ownership.

use crate::{commands::account::args::AccountCommand, common::help};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aster-acme", version, about = "An ACME client for certificate issuance and management.", styles = help::help_styles())]
pub(crate) struct Args {
    /// Show safe diagnostic stages and HTTP metadata; JSON suppresses human logs.
    #[arg(long, global = true)]
    pub(crate) debug: bool,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Manage ACME accounts and the local default selection.
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// Issue and manage certificates.
    Cert {
        #[command(subcommand)]
        command: crate::commands::cert::args::CertCommand,
    },
    /// Run noninteractive certificate maintenance for an external scheduler.
    Daemon {
        #[command(subcommand)]
        command: crate::commands::daemon::DaemonCommand,
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
            Command::Daemon { command } => match command {
                crate::commands::daemon::DaemonCommand::RunOnce(args) => args.local.json,
                crate::commands::daemon::DaemonCommand::Run { options, .. } => options.local.json,
            },
            Command::Account { command } => command.json(),
        }
    }
}
