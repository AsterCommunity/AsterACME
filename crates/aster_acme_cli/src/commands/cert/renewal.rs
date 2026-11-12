//! Single and batch renewal orchestration. Transactions return data; rendering happens once.
use crate::commands::cert::{
    args::{RenewArgs, RunArgs},
    execute::{RunMode, Start, transact},
    report::{
        CertificateResult, RenewalBatch, RenewalEntry, RenewalResult, RenewalWork, SkipReason,
    },
    selection,
};
use crate::common::{
    context::CliSettings,
    error::{CliResult, diagnostic},
};
use aster_acme::issuance::IssueRecord;
use aster_acme::storage::issuance::IssueStore;
use aster_acme::storage::query::{IssueQuery, IssueView};
use aster_acme_cli_storage::issuance::CliIssueStore;
use async_trait::async_trait;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub(super) async fn execute(
    args: RenewArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<super::report::CertificateReport> {
    let options = super::execute::options(&args.run.local, &args.run.http, None);
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    match (
        args.all,
        args.target
            .name
            .as_deref()
            .or(args.target.named_name.as_deref()),
    ) {
        (true, _) => {
            let records = store
                .query(IssueQuery {
                    view: IssueView::Managed,
                    ..IssueQuery::default()
                })
                .await?;
            let work =
                RenewalWork::from_records(&records, args.now, time::OffsetDateTime::now_utc());
            if work.scheduled > 0 {
                cli.output.progress(
                    crate::common::output::MessageKind::Info,
                    &format!(
                        "Renewing {} certificates; {} not due.",
                        work.scheduled, work.not_due
                    ),
                );
            }
            let cancellation = CancellationToken::new();
            let _signal = crate::common::signal::InterruptGuard::new(cancellation.clone());
            let executor = Transaction {
                settings: &settings,
                store: &store,
                run: &args.run,
                immediate: args.now,
                automatic: false,
                cancellation: Some(&cancellation),
                cli,
            };
            let report = run_batch(records, &executor, &cancellation).await;
            Ok(super::report::CertificateReport::Batch {
                report,
                data_dir: settings.data_dir,
            })
        }
        (false, explicit) => {
            let records = store
                .query(IssueQuery {
                    name: explicit
                        .map(aster_acme::issuance::CertificateName::new)
                        .transpose()?,
                    in_use: Some(true),
                    ..IssueQuery::default()
                })
                .await?;
            let name = selection::certificate_name(
                &records,
                args.target
                    .name
                    .as_deref()
                    .or(args.target.named_name.as_deref()),
                None,
                selection::CertificateLabel::Standard,
                &cli.output,
            )?;
            let selected = records.iter().find(|record| record.name == name).ok_or(
                "No in-use certificate is selected. Complete an initial issuance before renewing.",
            )?;
            let executor = Transaction {
                settings: &settings,
                store: &store,
                run: &args.run,
                immediate: args.now,
                automatic: false,
                cancellation: None,
                cli,
            };
            let result = executor.run(selected).await?;
            Ok(super::report::CertificateReport::Result {
                result,
                data_dir: settings.data_dir,
            })
        }
    }
}

/// Run unattended renewals for daemon-owned candidates. Method eligibility is
/// checked before the existing transaction, which still revalidates under lease.
pub(crate) async fn execute_automatic(
    settings: CliSettings,
    store: &CliIssueStore,
    run: &RunArgs,
    cli: &crate::common::context::CommandContext,
    cancellation: &CancellationToken,
) -> CliResult<RenewalBatch> {
    let records = store
        .query(IssueQuery {
            in_use: Some(true),
            renewal_due_at: Some(time::OffsetDateTime::now_utc()),
            ..IssueQuery::default()
        })
        .await?;
    let candidates = records;
    let executor = Transaction {
        settings: &settings,
        store,
        run,
        immediate: false,
        automatic: true,
        cancellation: Some(cancellation),
        cli,
    };
    Ok(run_batch(candidates, &executor, cancellation).await)
}

#[async_trait(?Send)]
trait RenewalExecutor {
    async fn run(&self, record: &IssueRecord) -> CliResult<CertificateResult>;
    fn skip_reason(&self, _record: &IssueRecord) -> Option<SkipReason> {
        None
    }
}

pub(crate) struct Transaction<'a> {
    settings: &'a CliSettings,
    store: &'a CliIssueStore,
    run: &'a RunArgs,
    immediate: bool,
    automatic: bool,
    cancellation: Option<&'a CancellationToken>,
    cli: &'a crate::common::context::CommandContext,
}

#[async_trait(?Send)]
impl RenewalExecutor for Transaction<'_> {
    async fn run(&self, record: &IssueRecord) -> CliResult<CertificateResult> {
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
            self.cli,
        )
        .await
    }

    fn skip_reason(&self, record: &IssueRecord) -> Option<SkipReason> {
        if !self.automatic {
            return None;
        }
        match super::validation::ValidationMethod::from_record(record) {
            Ok(method) if method.automatic() => None,
            Ok(_) | Err(_) => Some(SkipReason::ManualValidation),
        }
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
        } else if let Some(reason) = executor.skip_reason(&record) {
            RenewalResult::Skipped(reason)
        } else {
            // Executor owns cancellation through durable issuance completion and
            // deployment reporting. Do not drop committed work at this outer boundary.
            match executor.run(&record).await {
                Ok(outcome) => RenewalResult::Outcome(outcome),
                Err(_) if cancellation.is_cancelled() => RenewalResult::Cancelled,
                Err(error) if error.is::<crate::common::terminal::Canceled>() => {
                    cancellation.cancel();
                    RenewalResult::Cancelled
                }
                Err(error) => {
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
