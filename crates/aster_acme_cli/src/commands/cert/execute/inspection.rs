//! Certificate inspection execution.
use crate::commands::cert::execute::options;
use crate::commands::cert::{render, selection};
use crate::common::args::{HttpArgs, LocalArgs};
use crate::{
    commands::account::args::AccountArgs,
    common::{
        context::{CliContext, CliSettings},
        error::CliResult,
    },
};
use aster_acme::issuance::service::IssueService;
use aster_acme::issuance::{CertificateName, IssueIdentity, IssueRecord};
use aster_acme::storage::account::{AccountKeyStore, AccountStore};
use aster_acme::storage::issuance::IssueStore;
use aster_acme::storage::query::{IssueQuery, IssueView};
use aster_acme_cli_storage::issuance::CliIssueStore;
use std::{sync::Arc, time::Duration};

pub(super) async fn show(
    target: crate::commands::cert::args::SavedTargetArgs,
    history: bool,
    verify: bool,
    http: HttpArgs,
    local: LocalArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<crate::commands::cert::report::CertificateReport> {
    let options = options(&local, &http, None);
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    let mut record = selected_record(
        &store,
        &target,
        cli,
        if history {
            selection::RequestSelection::Any
        } else {
            selection::RequestSelection::InUse
        },
    )
    .await?;
    if verify {
        let context = settings
            .account(&AccountArgs {
                name: Some(record.account_name.clone()),
                ..options
            })
            .await?;
        record = inspect_remote(context, &http, &record, &store, cli).await?;
    }
    let view = if history || target.operation.is_some() {
        render::inspection::DetailView::Version
    } else {
        render::inspection::DetailView::InUse
    };
    Ok(crate::commands::cert::report::CertificateReport::Show {
        record: Box::new(record),
        verified: verify,
        view,
    })
}

pub(in crate::commands::cert) async fn selected_record(
    store: &CliIssueStore,
    target: &crate::commands::cert::args::SavedTargetArgs,
    cli: &crate::common::context::CommandContext,
    mode: selection::RequestSelection,
) -> CliResult<IssueRecord> {
    let query = IssueQuery {
        name: target
            .identity
            .name
            .as_deref()
            .or(target.identity.named_name.as_deref())
            .map(CertificateName::new)
            .transpose()?,
        operation_id: target.operation.clone(),
        unfinished: if matches!(mode, selection::RequestSelection::Completed) {
            Some(false)
        } else {
            None
        },
        view: if matches!(mode, selection::RequestSelection::InUse) && target.operation.is_none() {
            IssueView::CurrentOrUnfinished
        } else {
            IssueView::All
        },
        ..IssueQuery::default()
    };
    let records = store.query(query).await?;
    let name = selection::certificate_name(
        &records,
        target
            .identity
            .name
            .as_deref()
            .or(target.identity.named_name.as_deref()),
        target.operation.as_deref(),
        selection::CertificateLabel::Standard,
        &cli.output,
    )?;
    selection::choose(records, &name, target.operation.as_deref(), &cli.output)
}

pub(super) async fn inspect_remote(
    context: CliContext,
    http: &HttpArgs,
    record: &IssueRecord,
    store: &CliIssueStore,
    cli: &crate::common::context::CommandContext,
) -> CliResult<IssueRecord> {
    let signer = context
        .store
        .signer(
            &context.directory,
            &context.name,
            aster_acme::storage::account::KeyAccess::Existing,
        )
        .await?;
    let thumbprint = signer.jwk()?.thumbprint()?;
    let _lease = context
        .store
        .lock_account(&context.directory, &thumbprint)
        .await?;
    let account = context
        .store
        .load(&context.directory, &thumbprint)
        .await?
        .ok_or("Account metadata missing.")?;
    let mut session = store.open(&record.name, &record.operation_id).await?;
    let transport = context.transport_options(&AccountArgs {
        user_agent: http.user_agent.clone(),
        request_timeout: http.request_timeout,
        ..AccountArgs::default()
    })?;
    let client = Arc::new(cli.http.discover(context.directory, transport).await?);
    let identity = IssueIdentity { account, signer };
    Ok(IssueService::new(client, identity)?
        .inspect(session.as_mut())
        .await?)
}
