//! Static root command tree, following `AsterDrive` CLI ownership.

use crate::{commands::account::args::AccountCommand, common::help};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aster-acme", version, about = "ACME account registration and recovery", styles = help::help_styles())]
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
    /// Show version, revision, target, profile, enabled features and build time.
    Version {
        /// Structured JSON build metadata.
        #[arg(long)]
        json: bool,
    },
}

impl Args {
    /// Resolve error output before moving the command into the dispatcher.
    pub(crate) fn json(&self) -> bool {
        match &self.command {
            Command::Version { json } => *json,
            Command::Account { command } => command.json(),
        }
    }
}
