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
    identifier::Identifier,
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
        let mut request = request(&args, &context.name, account.preferred_profile.as_deref())?;
        // Draft-ietf-acme-profiles: interactive issuance without an explicit
        // --profile picks from the CA's advertised list (account default
        // preselected); scripts and --profile keep the flag requirement.
        if interactive && args.profile.is_none() {
            prompt_profile(&mut request, &context, &options, &account, cli).await?;
        }
        if args.challenge == Some(crate::commands::cert::validation::ValidationMethod::DnsProvider)
        {
            request.solver_config =
                crate::commands::cert::validation::provider::bound_provider_configuration(
                    args.provider.as_deref(),
                    &settings.data_dir,
                )
                .await?;
            let targets =
                crate::commands::cert::validation::provider::parse_dns_targets(&args.dns_targets)?;
            request.solver_config["dns_targets"] = serde_json::to_value(targets)?;
        }
        Some((request, account))
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

/// Interactive default-profile selection against the bound CA's directory:
/// advertised names with descriptions, account default preselected, Esc
/// cancels the issuance. CAs without advertisements keep the CA default.
async fn prompt_profile(
    request: &mut IssueRequest,
    context: &crate::common::context::CliContext,
    options: &crate::commands::account::args::AccountArgs,
    account: &aster_acme::account::AccountRecord,
    cli: &crate::common::context::CommandContext,
) -> CliResult<()> {
    let transport = context.transport_options(options)?;
    let advertised = cli
        .http
        .discover(context.directory.clone(), transport)
        .await?
        .directory()
        .meta
        .profiles
        .clone();
    let Some(advertised) = advertised.filter(|map| !map.is_empty()) else {
        return Ok(());
    };
    let names = advertised.keys().cloned().collect::<Vec<_>>();
    // CA-provided names/descriptions are untrusted terminal text: escape the
    // display labels, while selection still indexes the original names.
    let mut choices = names
        .iter()
        .map(|name| match advertised.get(name).map(String::as_str) {
            None | Some("") => crate::common::output::safe(name),
            Some(description) => {
                format!(
                    "{} — {}",
                    crate::common::output::safe(name),
                    crate::common::output::safe(description)
                )
            }
        })
        .collect::<Vec<_>>();
    choices.push("(no default; the CA default applies)".to_owned());
    let default = names
        .iter()
        .position(|name| account.preferred_profile.as_deref() == Some(name.as_str()))
        .unwrap_or(0);
    let selection = crate::common::terminal::select_index_or_back(
        "Default certificate profile:",
        &choices,
        default,
        &cli.output,
    )?
    .ok_or(crate::common::terminal::Canceled)?;
    request.profile = names.get(selection).cloned();
    Ok(())
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

/// The explicit `--profile` flag wins; otherwise the account's saved default
/// ([draft-ietf-acme-profiles](https://datatracker.ietf.org/doc/html/draft-ietf-acme-profiles)) applies; without either the CA default is used.pub(super)
fn request(
    args: &IssueArgs,
    account: &str,
    account_default_profile: Option<&str>,
) -> CliResult<IssueRequest> {
    let method = args
        .challenge
        .ok_or("Specify -c/--challenge for a new certificate.")?;
    let solver_config =
        if method == crate::commands::cert::validation::ValidationMethod::DnsProvider {
            crate::commands::cert::validation::provider::provider_configuration(
                args.provider.as_deref(),
            )?
        } else {
            crate::commands::cert::validation::configuration(
                method,
                args.webroot.as_deref(),
                args.listen_address,
            )?
        };
    // Command-line order is preserved per flag; DNS entries precede IP
    // entries in the certificate SAN list, and the first entry is primary.
    let mut identifiers = args
        .domain
        .iter()
        .map(|dns| Identifier::Dns(dns.clone()))
        .collect::<Vec<_>>();
    identifiers.extend(args.ip.iter().map(|ip| Identifier::Ip(ip.clone())));
    let primary = identifiers
        .first()
        .ok_or("At least one domain or IP address is required.")?;
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
        profile: args
            .profile
            .clone()
            .or_else(|| account_default_profile.map(str::to_owned)),
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
                    "Identifiers: {}",
                    request
                        .identifiers
                        .iter()
                        .map(Identifier::value)
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
                        .ok_or(IssueError::InvalidInput("missing primary identifier"))?,
                )?;
            }
            result => return result,
        }
    }
    Err(IssueError::InvalidInput(
        "automatic certificate name allocation exceeded its collision budget",
    ))
}
