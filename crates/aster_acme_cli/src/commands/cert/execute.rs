//! CLI execution wires account leases, generation sessions, and manual DNS UI into the library.

use crate::commands::cert::args::CertCommand;
use crate::commands::cert::execute::inspection::show;
use crate::commands::cert::execute::issuance::issue;
use crate::common::args::{HttpArgs, LocalArgs};
use crate::{
    commands::account::args::AccountArgs,
    common::{context::CliSettings, error::CliResult},
};
use aster_acme::issuance::{CertificateName, IssueRecord, IssueRequest};
use aster_acme::storage::issuance::IssueStore;
use aster_acme::storage::query::{IssueQuery, IssueView};
use aster_acme_cli_storage::issuance::CliIssueStore;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub(super) fn options(local: &LocalArgs, http: &HttpArgs, account: Option<String>) -> AccountArgs {
    AccountArgs {
        data_dir: local.data_dir.clone(),
        json: local.json,
        name: account,
        user_agent: http.user_agent.clone(),
        request_timeout: http.request_timeout,
        ..AccountArgs::default()
    }
}

pub(crate) mod chain_selector;
pub(crate) mod failure;
pub(crate) mod foreground;
pub(crate) mod inspection;
pub(crate) mod issuance;
pub(crate) mod transaction;
pub(super) enum IssueInput {
    // A saved journal is large; keep it off the transaction frame. New input holds
    // only the desired definition, not the entire parsed CLI/output/HTTP args.
    Resume {
        record: Box<IssueRecord>,
        chain_override: Option<aster_acme::issuance::ChainSelection>,
    },
    New {
        request: IssueRequest,
        naming: Naming,
    },
}

pub(super) enum Start {
    Issue(IssueInput),
    Renew {
        name: CertificateName,
        expected_in_use: String,
        now: bool,
    },
}

pub(super) enum RunMode {
    Single(CancellationToken),
    Batch(CancellationToken),
}

pub(crate) async fn execute(
    command: CertCommand,
    cli: &crate::common::context::CommandContext,
) -> CliResult<crate::commands::cert::report::CertificateReport> {
    match command {
        CertCommand::Issue(args) => issue(args, cli).await,
        CertCommand::Renew(args) => crate::commands::cert::renewal::execute(args, cli).await,
        CertCommand::Deploy(args) => {
            crate::commands::cert::deployment::command::execute(args, cli, CancellationToken::new())
                .await
        }
        CertCommand::Remove {
            target,
            all,
            history,
            revoked,
            failed,
            yes,
            local,
        } => {
            use crate::commands::cert::removal::RemovalFilter;
            let filter = match (all, history, revoked, failed) {
                (false, false, false, false) => RemovalFilter::Request,
                (true, false, false, false) => RemovalFilter::All,
                (false, true, false, false) => RemovalFilter::History,
                (false, false, true, false) => RemovalFilter::Revoked,
                (false, false, false, true) => RemovalFilter::Failed,
                _ => {
                    return Err(
                        "--all, --history, --revoked and --failed are mutually exclusive.".into(),
                    );
                }
            };
            crate::commands::cert::removal::execute(target, filter, yes, local, cli).await
        }
        CertCommand::List {
            name,
            history,
            local,
        } => {
            let options = AccountArgs {
                data_dir: local.data_dir.clone(),
                json: local.json,
                ..AccountArgs::default()
            };
            let settings = CliSettings::load(&options).await?;
            let store = CliIssueStore::new(settings.data_dir, Duration::from_secs(5));
            let filter = name.as_deref().map(CertificateName::new).transpose()?;
            let records = store
                .query(IssueQuery {
                    name: filter,
                    view: if history {
                        IssueView::All
                    } else {
                        IssueView::Managed
                    },
                    ..IssueQuery::default()
                })
                .await?;
            Ok(crate::commands::cert::report::CertificateReport::List(
                records,
            ))
        }
        CertCommand::Show {
            target,
            history,
            verify,
            operation_timeout,
            http,
            local,
        } => show(target, history, verify, operation_timeout, http, local, cli).await,
        CertCommand::Revoke(args) => crate::commands::cert::revocation::execute(args, cli).await,
    }
}

pub(super) enum Naming {
    Explicit,
    Automatic,
}

#[cfg(test)]
pub(crate) mod tests;
