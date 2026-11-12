//! Account execution injects storage and signers; offline reads never construct HTTP clients.

use crate::commands::account::{
    args::{AccountArgs, AccountCommand},
    report::{AccountReport, LocalAccountReport},
};
use crate::common::{
    context::{CliContext, CliSettings},
    error::CliResult,
};
use aster_acme::storage::account::{AccountKeyStore, AccountStore};
use aster_acme::storage::query::AccountQuery;
use aster_acme::{
    account::{AccountError, AccountService, RegistrationOptions},
    crypto::{AccountSigner, ExternalAccountCredentials},
};
use std::sync::Arc;

enum Operation {
    Register,
    Deactivate,
    Recover,
    Show { verify: bool },
    Switch,
    Remove,
}

impl Operation {
    fn key_access(
        &self,
        algorithm: Option<aster_acme::crypto::key_algorithm::KeyAlgorithm>,
    ) -> aster_acme::storage::account::KeyAccess {
        match self {
            Self::Register => aster_acme::storage::account::KeyAccess::Create(algorithm),
            Self::Recover | Self::Deactivate | Self::Show { .. } | Self::Switch | Self::Remove => {
                aster_acme::storage::account::KeyAccess::Existing
            }
        }
    }
}

pub(crate) async fn execute(
    command: AccountCommand,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let (mut options, operation) = match command {
        AccountCommand::UpdateContact(args) => {
            return super::mutation::update_contacts(args, cli).await;
        }
        AccountCommand::RotateKey(args) => return super::mutation::rotate_key(args, cli).await,
        AccountCommand::List(args) => return list(args, cli).await,
        AccountCommand::Remove(options) => (AccountArgs::from(options), Operation::Remove),
        AccountCommand::Deactivate(options) => (AccountArgs::from(options), Operation::Deactivate),
        AccountCommand::Register(options) => (AccountArgs::from(options), Operation::Register),
        AccountCommand::Recover(options) => (AccountArgs::from(options), Operation::Recover),
        AccountCommand::Show { options, verify } => {
            (AccountArgs::from(options), Operation::Show { verify })
        }
        AccountCommand::Switch(options) => (AccountArgs::from(options), Operation::Switch),
    };
    let settings = CliSettings::load(&options).await?;
    let mode = match operation {
        Operation::Register => super::selection::Mode::Register,
        Operation::Recover | Operation::Remove | Operation::Show { .. } => {
            super::selection::Mode::Existing
        }
        Operation::Deactivate => super::selection::Mode::Operation(
            aster_acme_core::account::AccountOperation::Deactivate,
        ),
        Operation::Switch => super::selection::Mode::Registered,
    };
    super::selection::complete(&mut options, &settings, mode, cli).await?;
    if matches!(operation, Operation::Switch) && options.name.is_none() {
        return Err(
            "Specify account switch <NAME> or --name <NAME>, or use an interactive terminal to select an account."
                .into(),
        );
    }
    let context = settings.account(&options).await?;
    match operation {
        Operation::Register => {}
        Operation::Recover
        | Operation::Remove
        | Operation::Show { .. }
        | Operation::Deactivate
        | Operation::Switch => {
            context.require_account().await?;
        }
    }
    if matches!(operation, Operation::Remove) {
        return remove(context, &options, cli).await;
    }
    // Check before loading/creating keys, changing contacts, or constructing HTTP.
    // Both registered accounts and interrupted pending identities require explicit reuse.
    let reused =
        matches!(operation, Operation::Register) && context.store.metadata().await?.is_some();
    if reused {
        crate::common::terminal::confirm_write(
            &format!(
                "Local account '{}' already exists for {}. Reuse its saved key and resume/query that account? This will not create a separate identity.",
                crate::common::output::safe(&context.name),
                crate::common::output::safe(context.directory.as_str()),
            ),
            options.yes,
            &cli.output,
        )?;
    }
    if let Operation::Switch = operation {
        return switch(context).await;
    }
    if matches!(operation, Operation::Show { verify: false }) {
        return offline(&context).await;
    }
    let name = context.name.clone();
    let signer = context
        .store
        .signer(
            &context.directory,
            &name,
            operation.key_access(options.key_algorithm),
        )
        .await?;
    if matches!(operation, Operation::Deactivate) {
        return deactivate(context, signer, options, cli).await;
    }
    match operation {
        Operation::Show { verify } => {
            if verify {
                let client = Arc::new(
                    cli.http
                        .discover(
                            context.directory.clone(),
                            context.transport_options(&options)?,
                        )
                        .await?,
                );
                AccountService::new(client, context.store.clone())
                    .inspect(signer.as_ref())
                    .await?;
            }
            local(&context, signer.as_ref(), name, verify).await
        }
        operation => remote(context, signer, name, options, operation, reused, cli).await,
    }
}

/// Verification is sequential and bounded per request. Each failure is a row result,
/// so one unavailable CA does not discard the rest of the local account inventory.
async fn list(
    args: super::args::ListArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let options = AccountArgs {
        user_agent: args.http.user_agent,
        request_timeout: args.http.request_timeout,
        ..args.local.into()
    };
    let settings = CliSettings::load(&options).await?;
    let mut accounts = aster_acme_cli_storage::inventory::query_accounts(
        settings.data_dir.clone(),
        AccountQuery::default(),
    )
    .await?;
    let verification = if args.verify {
        let mut results = Vec::with_capacity(accounts.len());
        for account in &mut accounts {
            let selected = AccountArgs {
                name: Some(account.name.clone()),
                ..AccountArgs::default()
            };
            let result = async {
                let context = settings.clone().account(&selected).await?;
                let signer = context
                    .store
                    .signer(
                        &context.directory,
                        &context.name,
                        aster_acme::storage::account::KeyAccess::Existing,
                    )
                    .await?;
                let transport = context.transport_options(&options)?;
                let client = Arc::new(cli.http.discover(context.directory, transport).await?);
                let observed = AccountService::new(client, context.store.clone())
                    .inspect(signer.as_ref())
                    .await?;
                let saved = context
                    .store
                    .metadata()
                    .await?
                    .ok_or("account metadata disappeared after verification")?;
                Ok::<_, Box<dyn std::error::Error>>((observed, saved))
            }
            .await;
            let (status, error) = match result {
                Ok((observed, saved)) => {
                    *account = aster_acme_cli_storage::inventory::LocalAccount::from_record(
                        account.name.clone(),
                        saved,
                    );
                    (Some(observed.status), None)
                }
                Err(error) => (
                    None,
                    Some(crate::common::error::diagnostic(error.as_ref()).0),
                ),
            };
            results.push(super::report::AccountVerification {
                name: account.name.clone(),
                status,
                error,
            });
        }
        Some(results)
    } else {
        None
    };
    Ok(AccountReport::List {
        accounts,
        default: settings
            .config
            .default_account
            .unwrap_or_else(|| "default".into()),
        verification,
    })
}

/// Local removal deliberately never initializes HTTP or decodes the private key.
async fn remove(
    context: CliContext,
    options: &AccountArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let confirmed = context
        .store
        .metadata()
        .await?
        .ok_or("No local account record exists for this name.")?;
    let root = context
        .config_path
        .parent()
        .ok_or("Data directory is missing.")?;
    crate::common::terminal::confirm_action(
        &format!(
            "Remove local account\n  Name: {}\n  CA: {}\n  Directory: {}\n\nLocal metadata and the account private key will be deleted.\nThis does not deactivate the account at the CA or revoke certificates.\nWithout a backup of this key, access to the CA account will be lost.",
            crate::common::output::safe(&context.name),
            crate::common::output::safe(context.directory.as_str()),
            crate::common::output::safe(
                &root
                    .join("accounts")
                    .join(&context.name)
                    .display()
                    .to_string()
            ),
        ),
        "Remove this local account?",
        options.yes,
        &cli.output,
    )?;
    context.store.remove(&confirmed).await?;
    crate::config::clear_removed_default(context.config_path, context.name.clone()).await
        .map_err(|error| format!("Local account was removed, but default-account configuration cleanup failed: {error}"))?;
    Ok(AccountReport::Removed {
        name: context.name,
        directory: context.directory,
    })
}

/// Confirm from local metadata before discovery, then let the protocol service persist
/// its intent under the operation lock. No unknown account URL is recovered implicitly.
async fn deactivate(
    context: CliContext,
    signer: Arc<dyn AccountSigner>,
    options: AccountArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let thumbprint = signer.jwk()?.thumbprint()?;
    let record = context
        .store
        .load(&context.directory, &thumbprint)
        .await?
        .ok_or(AccountError::AccountDoesNotExist)?;
    let account_url = record
        .account_url
        .clone()
        .ok_or(AccountError::AccountDoesNotExist)?;
    match record
        .action(aster_acme_core::account::AccountOperation::Deactivate)
        .map_err(AccountError::from)?
    {
        aster_acme_core::account::AccountAction::AlreadyDeactivated => {
            return Ok(AccountReport::Deactivated {
                name: context.name,
                verified: false,
                account: aster_acme::account::AcmeAccount {
                    key_algorithm: record.key_algorithm,
                    times: record.times,
                    account_id: record.account_id,
                    directory_url: context.directory,
                    account_url,
                    status: aster_acme_core::protocol::AccountStatus::Deactivated,
                    contacts: record.server_contacts.unwrap_or_default(),
                    recovered: false,
                },
            });
        }
        aster_acme_core::account::AccountAction::SendDeactivation => {}
        aster_acme_core::account::AccountAction::Inspect
        | aster_acme_core::account::AccountAction::LookupExisting
        | aster_acme_core::account::AccountAction::Select
        | aster_acme_core::account::AccountAction::Update
        | aster_acme_core::account::AccountAction::SendKeyChange
        | aster_acme_core::account::AccountAction::ReconcileKeyChange
        | aster_acme_core::account::AccountAction::FinalizeKeyChange => {
            return Err(AccountError::InvalidResponse.into());
        }
    }
    crate::common::terminal::confirm_action(
        &format!(
            "Permanently deactivate account\n  Name: {}\n  CA: {}\n  Account URL: {}\n\nThis cannot be undone.\nThe account key will no longer authorize ACME requests.\nLocal key and metadata will be retained.",
            crate::common::output::safe(&context.name),
            crate::common::output::safe(context.directory.as_str()),
            crate::common::output::safe(account_url.as_str()),
        ),
        "Deactivate this account?",
        options.yes,
        &cli.output,
    )?;
    let transport = context.transport_options(&options)?;
    let client = Arc::new(cli.http.discover(context.directory, transport).await?);
    let account = AccountService::new(client, context.store)
        .deactivate(signer.as_ref())
        .await?;
    Ok(AccountReport::Deactivated {
        name: context.name,
        account,
        verified: true,
    })
}

/// Switching validates a registered local identity and edits only the shared configuration.
async fn switch(context: CliContext) -> CliResult<AccountReport> {
    let target = context.name.clone();
    let signer = context
        .store
        .signer(
            &context.directory,
            &target,
            aster_acme::storage::account::KeyAccess::Existing,
        )
        .await?;
    let thumbprint = signer.jwk()?.thumbprint()?;
    let _lease = context
        .store
        .lock_account(&context.directory, &thumbprint)
        .await?;
    let record = context
        .store
        .load(&context.directory, &thumbprint)
        .await?
        .ok_or("No local registration record exists.")?;
    if !record.is_usable() {
        return Err("Switch requires a registered local account with no pending deactivation or inactive status.".into());
    }
    crate::config::persist(context.config_path, Some(target.clone()), None).await?;
    Ok(AccountReport::Switched {
        name: target,
        directory: context.directory,
    })
}

async fn offline(context: &CliContext) -> CliResult<AccountReport> {
    let expected = context.require_account().await?;
    let _lease = context
        .store
        .lock_account(&context.directory, &expected.key_thumbprint)
        .await?;
    let record = context
        .store
        .load(&context.directory, &expected.key_thumbprint)
        .await?;
    Ok(AccountReport::Local(LocalAccountReport {
        verified: false,
        name: context.name.clone(),
        directory: context.directory.clone(),
        key_thumbprint: expected.key_thumbprint,
        record,
    }))
}

/// Read a consistent local snapshot; no discovery, recovery, or metadata refresh occurs.
async fn local(
    context: &CliContext,
    signer: &dyn AccountSigner,
    name: String,
    verified: bool,
) -> CliResult<AccountReport> {
    let thumbprint = signer.jwk()?.thumbprint()?;
    let _lease = context
        .store
        .lock_account(&context.directory, &thumbprint)
        .await?;
    let record = context.store.load(&context.directory, &thumbprint).await?;
    if let Some(record) = &record
        && (record.directory_url != context.directory || record.key_thumbprint != thumbprint)
    {
        return Err(AccountError::IdentityMismatch.into());
    }
    Ok(AccountReport::Local(LocalAccountReport {
        verified,
        name,
        directory: context.directory.clone(),
        key_thumbprint: thumbprint,
        record,
    }))
}

async fn remote(
    context: CliContext,
    signer: Arc<dyn AccountSigner>,
    name: String,
    options: AccountArgs,
    operation: Operation,
    reused: bool,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let transport = context.transport_options(&options)?;
    let interactive = crate::common::terminal::interactive(options.json);
    let account_user_agent = options.user_agent.clone();
    let mut persist_contacts = !options.contact.is_empty();
    let thumbprint = signer.jwk()?.thumbprint()?;
    let saved = context.store.load(&context.directory, &thumbprint).await?;
    if matches!(operation, Operation::Register)
        && let Some(saved) = &saved
    {
        saved
            .action(aster_acme_core::account::AccountOperation::Register)
            .map_err(AccountError::from)?;
    }
    let mut registration = match operation {
        Operation::Register => Some(registration_options(
            options,
            context.config.contact.clone(),
        )?),
        Operation::Recover
        | Operation::Deactivate
        | Operation::Show { .. }
        | Operation::Switch
        | Operation::Remove => None,
    };
    if let Some(registration) = &mut registration {
        // Existing local input is preferable to asking again when no global default exists.
        if registration.contacts.is_empty()
            && let Some(saved) = &saved
        {
            registration.contacts.clone_from(&saved.contacts);
        }
        persist_contacts |= super::interaction::contact(
            registration,
            interactive,
            &mut super::interaction::TerminalPrompts(&cli.output),
        )?;
    }
    save_registration_intent(
        &context,
        signer.as_ref(),
        registration.as_ref(),
        persist_contacts,
        account_user_agent,
    )
    .await?;
    let client = Arc::new(cli.http.discover(context.directory, transport).await?);
    if let Some(registration) = &mut registration {
        super::interaction::terms(
            registration,
            client.directory().meta.terms_of_service.as_ref(),
            saved
                .as_ref()
                .and_then(|record| record.accepted_terms_url.as_ref()),
            interactive,
            &mut super::interaction::TerminalPrompts(&cli.output),
        )?;
    }
    let service = AccountService::new(client, context.store);
    let account = match operation {
        Operation::Register => {
            service
                .register_or_recover(
                    signer.as_ref(),
                    registration.ok_or("Missing registration options.")?,
                )
                .await?
        }
        Operation::Recover => service.recover(signer.as_ref()).await?,
        Operation::Show { .. } | Operation::Deactivate | Operation::Switch | Operation::Remove => {
            return Err("Local command was dispatched to the network executor.".into());
        }
    };
    let action = match operation {
        Operation::Register => {
            crate::config::default_after_registration(context.config_path, name.clone())
                .await
                .map_err(|error| {
                    format!("Account registered, but saving its default selection failed: {error}")
                })?;
            super::report::RemoteAction::Register
        }
        Operation::Recover => super::report::RemoteAction::Recover,
        Operation::Show { .. } | Operation::Deactivate | Operation::Switch | Operation::Remove => {
            return Err("Unexpected remote action.".into());
        }
    };
    Ok(AccountReport::Remote {
        action,
        name,
        account,
        reused,
    })
}

/// Persist local input before discovery so transient HTTP failures cannot lose it.
/// This does not claim the CA has accepted a contact or changed an existing account.
async fn save_registration_intent(
    context: &CliContext,
    signer: &dyn AccountSigner,
    registration: Option<&RegistrationOptions>,
    persist_contacts: bool,
    user_agent: Option<String>,
) -> CliResult<()> {
    if persist_contacts && let Some(registration) = registration {
        crate::config::persist(
            context.config_path.clone(),
            None,
            Some(registration.contacts.clone()),
        )
        .await?;
    }
    if let Some(registration) = registration
        && (!registration.contacts.is_empty() || user_agent.is_some())
    {
        // Discovery failure must not lose local input; this is not CA acceptance.
        let thumbprint = signer.jwk()?.thumbprint()?;
        let lease = context
            .store
            .lock_account(&context.directory, &thumbprint)
            .await?;
        let mut record = context
            .store
            .load(&context.directory, &thumbprint)
            .await?
            .ok_or("Local account identity record is missing.")?;
        if !registration.contacts.is_empty() {
            record.contacts.clone_from(&registration.contacts);
        }
        if user_agent.is_some() {
            record.user_agent = user_agent;
        }
        AccountStore::save(context.store.as_ref(), &record, &lease).await?;
    }
    Ok(())
}

pub(super) fn registration_options(
    options: AccountArgs,
    default_contacts: Vec<String>,
) -> CliResult<RegistrationOptions> {
    let external_account = match (options.eab_kid, options.eab_key_file) {
        (Some(kid), Some(path)) => {
            use std::io::Read as _;
            let file = std::fs::File::open(path)?;
            if !file.metadata()?.is_file() {
                return Err("EAB key must be a regular file.".into());
            }
            let mut secret = zeroize::Zeroizing::new(String::new());
            file.take(8193).read_to_string(&mut secret)?;
            if secret.len() > 8192 {
                return Err("EAB key file exceeds 8 KiB.".into());
            }
            Some(ExternalAccountCredentials::new(&kid, secret.trim())?)
        }
        (None, None) => None,
        _ => return Err("EAB requires both --eab-kid and --eab-key-file.".into()),
    };
    Ok(RegistrationOptions {
        contacts: super::contact::normalize(if options.contact.is_empty() {
            default_contacts
        } else {
            options.contact
        })?,
        terms_accepted: options.accept_terms,
        external_account,
    })
}
