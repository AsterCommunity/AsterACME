//! Root command execution returns one typed report; the session alone writes the final document.
use crate::{
    app::{Args, Command},
    commands::{account, cert},
    common::{
        context::CommandContext,
        error::CliResult,
        session::{ExitStatus, Format},
    },
};

pub(crate) enum CommandReport {
    // Account snapshots dominate the other command reports; box once at this boundary.
    Account(Box<account::report::AccountReport>),
    Certificate(cert::report::CertificateReport),
    Version,
}
impl CommandReport {
    pub(crate) fn render(&self, format: Format) -> CliResult<String> {
        match self {
            Self::Account(report) => account::render::render(report, format),
            Self::Certificate(report) => cert::render::render(report, format),
            Self::Version => crate::commands::build_info::render(format.json),
        }
    }
    pub(crate) fn exit_status(&self) -> ExitStatus {
        match self {
            Self::Account(report) if report.has_failures() => ExitStatus::Failed,
            Self::Account(_) | Self::Version => ExitStatus::Success,
            Self::Certificate(report) => report.exit_status(),
        }
    }
}

pub(crate) async fn execute(args: Args, cli: &CommandContext) -> CliResult<CommandReport> {
    match args.command {
        Command::Cert { command } => Ok(CommandReport::Certificate(
            cert::execute::execute(command, cli).await?,
        )),
        Command::Account { command } => Ok(CommandReport::Account(Box::new(
            account::execute::execute(command, cli).await?,
        ))),
        Command::Version { .. } => Ok(CommandReport::Version),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_layout_keeps_large_owned_snapshots_out_of_every_command_frame() {
        use aster_acme::issuance::{IssueOutcome, IssueRecord};
        use aster_acme::transport::TransportError;
        use aster_acme_cli_storage::issuance::RenewalPreparation;
        use aster_acme_protocol::problem::Problem;
        use std::mem::size_of;
        println!(
            "AccountReport={} CertificateReport={} CommandReport={} IssueRecord={} IssueOutcome={} Problem={} TransportError={} RenewalPreparation={}",
            size_of::<account::report::AccountReport>(),
            size_of::<cert::report::CertificateReport>(),
            size_of::<CommandReport>(),
            size_of::<IssueRecord>(),
            size_of::<IssueOutcome>(),
            size_of::<Problem>(),
            size_of::<TransportError>(),
            size_of::<RenewalPreparation>()
        );
        assert!(size_of::<CommandReport>() < size_of::<account::report::AccountReport>() / 2);
        assert!(size_of::<cert::report::CertificateReport>() < size_of::<IssueRecord>() / 2);
        assert!(size_of::<IssueOutcome>() < size_of::<IssueRecord>() / 2);
        assert!(size_of::<RenewalPreparation>() < size_of::<IssueRecord>() / 2);
        assert!(size_of::<TransportError>() < size_of::<Problem>());
    }
}
