//! Certificate issuance execution.
use crate::commands::cert::execute::transaction::transact;
use crate::commands::cert::execute::{IssueInput, Naming, RunMode, Start, options};
use crate::commands::cert::progress::Progress;
use crate::commands::cert::{args::IssueArgs, selection};
use crate::common::output::MessageKind;
use crate::common::{context::CliSettings, error::CliResult, terminal};
use aster_acme::storage::issuance::{IssueSession, IssueStore};
use aster_acme::storage::query::{IssueQuery, SimilarIssue};
use aster_acme::{
    identifier::DnsIdentifier,
    issuance::{CertificateName, IssueError, IssueRecord, IssueRequest},
};
use aster_acme_cli_storage::issuance::CliIssueStore;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub(super) async fn issue(
    mut args: IssueArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<crate::commands::cert::report::CertificateReport> {
    let interactive = terminal::interactive(args.run.local.json);
    crate::commands::cert::interaction::complete(
        &mut args,
        interactive,
        &mut crate::commands::cert::interaction::TerminalPrompts(&cli.output),
    )
    .await?;
    let mut options = options(&args.run.local, &args.run.http, args.account.clone());
    let settings = CliSettings::load(&options).await?;
    let store = CliIssueStore::new(settings.data_dir.clone(), Duration::from_secs(5));
    let mut proposed = if args.resume.is_none() {
        let context = settings.clone().account(&options).await?;
        context.require_account().await?;
        let account = context
            .store
            .metadata()
            .await?
            .ok_or("No registered account exists.")?;
        Some((request(&args, &context.name)?, account))
    } else {
        None
    };

    let selected = select_saved_issue(&args, &store, proposed.as_ref(), cli).await?;
    if let Some(record) = &selected {
        options.name = Some(record.account_name.clone());
    }
    let run = args.run.clone();
    let root = settings.data_dir.clone();
    let input = if let Some(record) = selected {
        IssueInput::Resume(Box::new(record))
    } else {
        IssueInput::New {
            request: proposed.take().ok_or("Missing new request definition.")?.0,
            naming: if args.name.is_some() {
                Naming::Explicit
            } else {
                Naming::Automatic
            },
        }
    };
    let result = transact(
        settings,
        options,
        &store,
        Start::Issue(input),
        &run,
        RunMode::Single(CancellationToken::new()),
        cli,
    )
    .await?;
    Ok(crate::commands::cert::report::CertificateReport::Result {
        result,
        data_dir: root,
    })
}

pub(super) async fn select_saved_issue(
    args: &IssueArgs,
    store: &CliIssueStore,
    proposed: Option<&(IssueRequest, aster_acme::account::AccountRecord)>,
    cli: &crate::common::context::CommandContext,
) -> CliResult<Option<IssueRecord>> {
    Ok(match &args.resume {
        Some(explicit) => {
            let query = IssueQuery {
                name: match explicit {
                    crate::commands::cert::args::ResumeTarget::Choose => None,
                    crate::commands::cert::args::ResumeTarget::Named(name) => {
                        Some(CertificateName::new(name)?)
                    }
                },
                unfinished: Some(true),
                operation_id: args.operation.clone(),
                resumable: Some(true),
                ..IssueQuery::default()
            };
            let records = store.query(query.clone()).await?;
            if records.is_empty() && query.name.is_some() {
                let inventory = store
                    .query(IssueQuery {
                        resumable: None,
                        ..query
                    })
                    .await?;
                selection::check_explicit_resume(&inventory, explicit, args.operation.as_deref())?;
            }
            let name = selection::certificate_name(
                &records,
                match explicit {
                    crate::commands::cert::args::ResumeTarget::Choose => None,
                    crate::commands::cert::args::ResumeTarget::Named(name) => Some(name.as_str()),
                },
                args.operation.as_deref(),
                selection::CertificateLabel::Standard,
                &cli.output,
            )?;
            Some(selection::choose(
                records,
                &name,
                args.operation.as_deref(),
                &cli.output,
            )?)
        }
        None => {
            if args.name.is_some() {
                None
            } else {
                let (request, account) = proposed.ok_or("Missing new request definition.")?;
                let now = time::OffsetDateTime::now_utc();
                let candidates = store
                    .query(IssueQuery {
                        unfinished: Some(true),
                        similar: Some(SimilarIssue {
                            request: request.clone(),
                            account: account.clone(),
                            now,
                        }),
                        ..IssueQuery::default()
                    })
                    .await?
                    .into_iter()
                    .collect();
                crate::commands::cert::similar::choose(
                    candidates,
                    args.if_similar_order,
                    &cli.output,
                )?
            }
        }
    })
}

pub(super) fn request(args: &IssueArgs, account: &str) -> CliResult<IssueRequest> {
    let method = args
        .challenge
        .ok_or("Specify -c/--challenge for a new certificate.")?;
    let solver_config =
        if method == crate::commands::cert::validation::ValidationMethod::DnsExternal {
            crate::commands::cert::validation::external_configuration(args.provider.as_deref())?
        } else {
            crate::commands::cert::validation::configuration(
                method,
                args.webroot.as_deref(),
                args.listen_address,
            )?
        };
    let identifiers = args.domain.clone();
    let primary = identifiers
        .first()
        .ok_or("At least one domain is required.")?;
    let request = IssueRequest {
        challenge: method.kind(),
        solver_id: method.id().into(),
        solver_config,
        key_algorithm: args.key_algorithm,
        name: match args.name.as_deref() {
            Some(name) => CertificateName::new(name)?,
            None => CertificateName::generated(primary)?,
        },
        identifiers,
        account_name: account.into(),
    };
    request.validate()?;
    Ok(request)
}

// Resolve recovery and new-generation creation together with their user-visible intent.
pub(super) async fn prepare_session(
    store: &CliIssueStore,
    input: IssueInput,
    account: &aster_acme::account::AccountRecord,
    progress: &Progress,
) -> CliResult<Box<dyn IssueSession>> {
    let session = match input {
        IssueInput::Resume(record) => {
            progress.output.progress(
                MessageKind::Info,
                &format!(
                    "Resuming {} requested at {}",
                    record.name.as_str(),
                    crate::common::time::timestamp(Some(record.created_at))
                ),
            );
            progress.output.progress(
                MessageKind::Info,
                &format!(
                    "Certificate key type: {} (saved)",
                    record.key_algorithm.name()
                ),
            );
            store.open(&record.name, &record.operation_id).await?
        }
        IssueInput::New { request, naming } => {
            progress.output.progress(
                MessageKind::Info,
                &format!(
                    "Domains: {}",
                    request
                        .identifiers
                        .iter()
                        .map(DnsIdentifier::value)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
            progress.output.progress(
                MessageKind::Info,
                &format!("Certificate key type: {}", request.key_algorithm.name()),
            );
            progress.output.progress(
                MessageKind::Info,
                &format!(
                    "Creating certificate key and fixed CSR for {}",
                    request.name.as_str()
                ),
            );
            allocate_certificate(store, request, account, naming).await?
        }
    };
    Ok(session)
}

/// Only automatic naming retries a typed allocation collision; other failures propagate.
pub(super) async fn allocate_certificate(
    store: &dyn IssueStore,
    mut request: IssueRequest,
    account: &aster_acme::account::AccountRecord,
    naming: Naming,
) -> Result<Box<dyn IssueSession>, IssueError> {
    for _ in 0..16 {
        match store.create(&request, account).await {
            Err(IssueError::NameAlreadyExists(_)) if matches!(naming, Naming::Automatic) => {
                request.name = CertificateName::generated(
                    request
                        .identifiers
                        .first()
                        .ok_or(IssueError::InvalidInput("missing primary domain"))?,
                )?;
            }
            result => return result,
        }
    }
    Err(IssueError::InvalidInput(
        "automatic certificate name allocation exceeded its collision budget",
    ))
}
