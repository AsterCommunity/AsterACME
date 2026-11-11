//! Single and batch renewal orchestration. Transactions return data; rendering happens once.
use super::{
    args::{RenewArgs, RunArgs},
    execute::{RunMode, Start, transact},
    progress::Progress,
    render,
    report::{
        BatchDisposition, CertificateResult, RenewalBatch, RenewalEntry, RenewalResult,
        RenewalWork, SkipReason,
    },
    selection,
};
use crate::common::{
    context::CliSettings,
    error::{CliResult, ReportedFailure, diagnostic},
};
use aster_acme::issuance::{IssueRecord, IssueStore};
use aster_acme_cli_storage::issuance::CliIssueStore;
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

pub(super) async fn execute(args: RenewArgs) -> CliResult<()> {
    let options = super::execute::options(&args.run.local, &args.run.http, None);
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    let records = store.list().await?;
    if args.all {
        let work = RenewalWork::from_records(&records, args.now, time::OffsetDateTime::now_utc());
        if work.scheduled > 0 {
            Progress::new(options.json).log.line(
                crate::common::log::Level::Info,
                &format!(
                    "Renewing {} certificates; {} not due.",
                    work.scheduled, work.not_due
                ),
            );
        }
        let candidates = selection::managed_records(records)?;
        let cancellation = CancellationToken::new();
        let _signal = BatchSignal(tokio::spawn({
            let cancellation = cancellation.clone();
            async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    cancellation.cancel();
                }
            }
        }));
        let executor = Transaction {
            settings: &settings,
            store: &store,
            run: &args.run,
            immediate: args.now,
            cancellation: Some(&cancellation),
        };
        let report = run_batch(candidates, &executor, &cancellation).await;
        crate::common::output::print_result(
            &render::batch(&report, options.json, &settings.data_dir)?,
            options.json,
            if work.scheduled > 0 {
                crate::common::output::ResultPreceding::Progress
            } else {
                crate::common::output::ResultPreceding::None
            },
        );
        match report.disposition() {
            BatchDisposition::Cancelled => Err(Box::new(ReportedFailure::Cancelled)),
            BatchDisposition::PartialFailure => Err(Box::new(ReportedFailure::Failed)),
            BatchDisposition::Completed | BatchDisposition::ActionRequired => Ok(()),
        }
    } else {
        let name = selection::certificate_name(
            &records,
            args.target
                .name
                .as_deref()
                .or(args.target.named_name.as_deref()),
            None,
            options.json,
        )?;
        let selected = records
            .iter()
            .find(|record| record.name == name && record.is_in_use)
            .ok_or(
                "No in-use certificate is selected. Complete an initial issuance before renewing.",
            )?;
        let executor = Transaction {
            settings: &settings,
            store: &store,
            run: &args.run,
            immediate: args.now,
            cancellation: None,
        };
        let result = executor.run(selected).await?;
        crate::common::output::print_result(
            &render::result(&result, options.json, &settings.data_dir)?,
            options.json,
            match &result {
                CertificateResult::NotDue(_) => crate::common::output::ResultPreceding::None,
                CertificateResult::Issuance(_) => crate::common::output::ResultPreceding::Progress,
            },
        );
        Ok(())
    }
}

// The task is command-scoped, including while an account/certificate lease is being
// acquired. Dropping an interrupted batch must not leave a global signal listener.
struct BatchSignal(tokio::task::JoinHandle<()>);
impl Drop for BatchSignal {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[async_trait(?Send)]
trait RenewalExecutor {
    async fn run(&self, record: &IssueRecord) -> CliResult<CertificateResult>;
}

struct Transaction<'a> {
    settings: &'a CliSettings,
    store: &'a CliIssueStore,
    run: &'a RunArgs,
    immediate: bool,
    cancellation: Option<&'a CancellationToken>,
}

#[async_trait(?Send)]
impl RenewalExecutor for Transaction<'_> {
    async fn run(&self, record: &IssueRecord) -> CliResult<CertificateResult> {
        let progress = Arc::new(Progress::new(self.run.local.json));
        let options = super::execute::options(
            &self.run.local,
            &self.run.http,
            Some(record.account_name.clone()),
        );
        let mode = match self.cancellation {
            Some(cancellation) => RunMode::Batch(cancellation.clone()),
            None => RunMode::Single,
        };
        transact(
            self.settings.clone(),
            options,
            self.store,
            Start::Renew {
                name: record.name.clone(),
                expected_in_use: record.operation_id.clone(),
                now: self.immediate,
            },
            self.run,
            mode,
            progress,
        )
        .await
    }
}

// Input is an inventory snapshot of stable managed identities, not all historical
// orders. The transaction rechecks in_use under lease before creating any material.
async fn run_batch(
    records: Vec<IssueRecord>,
    executor: &dyn RenewalExecutor,
    cancellation: &CancellationToken,
) -> RenewalBatch {
    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        let result = if cancellation.is_cancelled() {
            RenewalResult::Skipped(SkipReason::BatchCancelled)
        } else if !record.is_in_use {
            RenewalResult::Skipped(SkipReason::NoInUseCertificate)
        } else {
            let result = tokio::select! {
                biased;
                () = cancellation.cancelled() => None,
                result = executor.run(&record) => Some(result),
            };
            match result {
                None => RenewalResult::Cancelled,
                Some(Ok(outcome)) => RenewalResult::Outcome(outcome),
                Some(Err(_)) if cancellation.is_cancelled() => RenewalResult::Cancelled,
                Some(Err(error)) if error.is::<crate::common::terminal::Canceled>() => {
                    cancellation.cancel();
                    RenewalResult::Cancelled
                }
                Some(Err(error)) => {
                    let (message, hint) = diagnostic(error.as_ref());
                    RenewalResult::Failed { message, hint }
                }
            }
        };
        entries.push(RenewalEntry {
            name: record.name.as_str().into(),
            result,
        });
    }
    RenewalBatch {
        entries,
        cancelled: cancellation.is_cancelled(),
    }
}

#[cfg(test)]
mod tests;
