//! Root dispatch keeps command execution separate from terminal presentation.

use crate::{
    app::{Args, Command},
    commands::account,
    common::error::CliResult,
};

pub(crate) async fn execute(args: Args) -> CliResult<()> {
    match args.command {
        Command::Cert { command } => crate::commands::cert::execute::execute(*command).await,
        Command::Version { json } => {
            println!("{}", crate::commands::build_info::render(json)?);
            Ok(())
        }
        Command::Account { command } => {
            let json = command.json();
            let report = account::execute::execute(*command).await?;
            println!("{}", account::render::render(&report, json)?);
            if report.has_failures() {
                return Err(
                    "Some accounts could not be verified; see the per-account results.".into(),
                );
            }
            Ok(())
        }
    }
}
