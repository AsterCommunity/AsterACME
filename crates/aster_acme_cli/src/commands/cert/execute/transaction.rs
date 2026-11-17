//! Certificate transaction execution.
use crate::commands::cert::execute::failure::report_issue_failure;
use crate::commands::cert::execute::foreground::Foreground;
use crate::commands::cert::execute::issuance::prepare_session;
use crate::commands::cert::execute::{IssueInput, RunMode, Start};
use crate::commands::cert::progress::Progress;
use crate::common::output::MessageKind;
use crate::{
    commands::account::args::AccountArgs,
    common::{
        context::{CliContext, CliSettings},
        error::CliResult,
    },
};
use aster_acme::storage::account::{AccountKeyStore, AccountStore};
use aster_acme::{
    issuance::{IssueError, IssueIdentity, IssueOutcome, IssueRecord},
    solver::ExecutionContext,
};
use aster_acme_cli_storage::issuance::CliIssueStore;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(in crate::commands::cert) async fn transact(
    settings: CliSettings,
    options: AccountArgs,
    store: &CliIssueStore,
    start: Start,
    run: &crate::commands::cert::args::RunArgs,
    mode: RunMode,
    cli: &crate::common::context::CommandContext,
) -> CliResult<crate::commands::cert::report::CertificateResult> {
    let progress = Arc::new(Progress::new(cli.output.clone()));
    let data_dir = settings.data_dir.clone();
    let context = settings.account(&options).await?;
    let (operation_timeout, _, _) = run.limits(&context.config);
    let cancellation = match &mode {
        RunMode::Single(token) | RunMode::Batch(token) => token.clone(),
    };
    let _signal = matches!(mode, RunMode::Single(_))
        .then(|| crate::common::signal::InterruptGuard::new(cancellation.clone()));
    let execution = ExecutionContext {
        cancellation,
        deadline: Instant::now() + Duration::from_secs(operation_timeout),
    };
    let signer = context
        .store
        .signer(
            &context.directory,
            &context.name,
            aster_acme::storage::account::KeyAccess::Existing,
        )
        .await
        .map_err(|error| match error.kind {
            aster_acme::storage::account::AccountStoreErrorKind::LockUnavailable => {
                IssueError::LeaseUnavailable("account", error.to_string())
            }
            aster_acme::storage::account::AccountStoreErrorKind::Other => IssueError::Store(error),
        })?;
    let thumbprint = signer.jwk()?.thumbprint()?;
    // Lock order is account, then certificate. Rotation/deactivation/removal cannot
    // change the account identity during challenge material derivation or signing.
    let _account_lease = context
        .store
        .lock_account(&context.directory, &thumbprint)
        .await
        .map_err(|error| match error.kind {
            aster_acme::storage::account::AccountStoreErrorKind::LockUnavailable => {
                IssueError::LeaseUnavailable("account", error.to_string())
            }
            aster_acme::storage::account::AccountStoreErrorKind::Other => IssueError::Store(error),
        })?;
    let account = context
        .store
        .load(&context.directory, &thumbprint)
        .await?
        .ok_or("No registered account exists.")?;
    let _providers = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        data_dir.clone(),
        Duration::from_secs(5),
    )
    .lease()
    .await?;
    validate_new_provider_binding(&start, &data_dir).await?;
    let mut session = match start {
        Start::Issue(input) => prepare_session(store, input, &account, &progress).await?,
        Start::Renew {
            name,
            expected_in_use,
            now,
        } => {
            match store
                .prepare_renewal(&name, &expected_in_use, now, &account)
                .await
            {
                Ok(aster_acme_cli_storage::issuance::RenewalPreparation::Ready(session)) => session,
                Ok(aster_acme_cli_storage::issuance::RenewalPreparation::NotDue(record)) => {
                    return Ok(crate::commands::cert::report::CertificateResult::NotDue(
                        record,
                    ));
                }
                Err(error) => return Err(error.into()),
            }
        }
    };
    let record = session.record().await?;
    report_material(&context, &record, &progress)?;
    let foreground = Foreground {
        context: &context,
        options: &options,
        args: run,
        mode,
        cli,
        progress: progress.clone(),
        execution: execution.clone(),
    };
    let outcome = match foreground
        .run(IssueIdentity { account, signer }, session.as_mut())
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            return report_issue_failure(session.as_mut(), &record, &progress, &execution, error)
                .await;
        }
    };
    drop(session);
    Ok(attach_deployment_results(outcome, store, &execution).await)
}

pub(in crate::commands::cert) async fn validate_new_provider_binding(
    start: &Start,
    data_dir: &std::path::Path,
) -> CliResult<()> {
    let Start::Issue(IssueInput::New { request, .. }) = start else {
        return Ok(());
    };
    let method = crate::commands::cert::validation::ValidationMethod::from_id(&request.solver_id)?;
    if method == crate::commands::cert::validation::ValidationMethod::DnsProvider {
        crate::commands::cert::validation::provider::validate_provider_binding(
            &request.solver_config,
            data_dir,
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn attach_deployment_results(
    outcome: IssueOutcome,
    store: &CliIssueStore,
    execution: &ExecutionContext,
) -> crate::commands::cert::report::CertificateResult {
    let deployment_results = match &outcome {
        IssueOutcome::Completed { record, .. } => {
            let name = record.name.clone();
            let generation = record.generation_name();
            crate::commands::cert::deployment::automatic::after_issuance(
                store,
                &name,
                &generation,
                execution,
            )
            .await
        }
        IssueOutcome::ActionRequired { .. } => (Vec::new(), Vec::new()),
    };
    let (deployments, deployment_events) = deployment_results;
    if deployments.is_empty() && deployment_events.is_empty() {
        crate::commands::cert::report::CertificateResult::Issuance(outcome)
    } else {
        crate::commands::cert::report::CertificateResult::Issued {
            outcome,
            deployments,
            deployment_events,
        }
    }
}

pub(super) fn report_material(
    context: &CliContext,
    record: &IssueRecord,
    progress: &Progress,
) -> CliResult<()> {
    if record.renewal_of.is_some() {
        progress.output.progress(
            MessageKind::Info,
            &format!(
                "Renewing {} with {}",
                record.name.as_str(),
                record.key_algorithm.name()
            ),
        );
    }
    progress.output.progress(
        MessageKind::Info,
        &format!(
            "Using CA: {} (account {})",
            context.directory.as_str(),
            context.name
        ),
    );
    let root = context
        .config_path
        .parent()
        .ok_or("Missing data directory.")?;
    let generation = root
        .join("certs")
        .join(record.name.as_str())
        .join(record.generation_name());
    progress.output.progress(
        MessageKind::Info,
        &format!(
            "Certificate key: {}",
            generation.join("private-key.pk8").display()
        ),
    );
    Ok(())
}
