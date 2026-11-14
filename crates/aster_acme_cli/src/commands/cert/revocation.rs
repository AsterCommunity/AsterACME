//! Explicit authority selection and confirmation around the shared library revocation transaction.
use crate::{
    commands::cert::{
        args::RevokeArgs,
        execute::{options, selected_record},
        report::CertificateReport,
        selection::RequestSelection,
    },
    common::{
        context::{CliSettings, CommandContext},
        error::CliResult,
        terminal,
    },
};
use aster_acme::{
    issuance::{IssueError, IssueRecord},
    solver::ExecutionContext,
    storage::revocation::RevocationSession,
};
use aster_acme_cli_storage::issuance::CliIssueStore;
use aster_acme_core::revocation::RevocationState;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub(super) async fn execute(
    args: RevokeArgs,
    cli: &CommandContext,
) -> CliResult<CertificateReport> {
    let settings = CliSettings::load(&options(&args.local, &args.http, None)).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    let selected = selected_record(&store, &args.target, cli, RequestSelection::Completed).await?;
    // Preserve the existing local-only idempotent path, validating its exact leaf binding.
    if selected.revocation.state == RevocationState::Confirmed {
        let session = store
            .open_revocation(&selected.name, &selected.operation_id)
            .await?;
        let record = session.certificate_record().await?;
        record
            .revocation
            .check_request(&session.target().await?, args.reason)?;
        if record.revocation.state != RevocationState::Confirmed {
            return Err("Revocation state changed during selection.".into());
        }
        return Ok(CertificateReport::Revoked(Box::new(record)));
    }
    let cancellation = CancellationToken::new();
    let _signal = crate::common::signal::InterruptGuard::new(cancellation.clone());
    let execution = ExecutionContext {
        cancellation: cancellation.clone(),
        deadline: Instant::now()
            + Duration::from_secs(
                args.operation_timeout
                    .or(settings.config.operation_timeout)
                    .unwrap_or(600),
            ),
    };
    let result = run(&store, &settings, &selected, &args, cli, &execution).await;
    if cancellation.is_cancelled() && result.is_err() {
        return Err(Box::new(terminal::Canceled));
    }
    result
}

async fn run(
    store: &CliIssueStore,
    settings: &CliSettings,
    selected: &IssueRecord,
    args: &RevokeArgs,
    cli: &CommandContext,
    execution: &ExecutionContext,
) -> CliResult<CertificateReport> {
    let prepared = match preparation::prepare(store, settings, selected, args, cli, execution)
        .await?
    {
        preparation::Prepared::Confirmed(record) => return Ok(CertificateReport::Revoked(record)),
        preparation::Prepared::Submit(prepared) => prepared,
    };
    let client = tokio::select! {
        biased;
        ()=execution.cancellation.cancelled()=>return Err(Box::new(terminal::Canceled)),
        result=tokio::time::timeout_at(execution.deadline.into(),cli.http.discover(prepared.directory.clone(),prepared.transport.clone()))=>Arc::new(result.map_err(|_|IssueError::RevocationInterrupted)??),
    };
    Ok(CertificateReport::Revoked(Box::new(
        prepared.submit(client, execution).await?,
    )))
}

mod preparation;

#[cfg(test)]
mod tests;
