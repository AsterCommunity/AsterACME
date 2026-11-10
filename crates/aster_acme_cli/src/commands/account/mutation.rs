//! Confirmed account mutations share selection, normalization, and service boundaries.
use super::{
    args::{AccountArgs, RotateKeyArgs, UpdateContactArgs},
    report::{AccountReport, RemoteAction},
};
use crate::common::{
    context::{CliContext, CliSettings},
    error::CliResult,
    terminal,
};
use aster_acme::{
    account::{AccountError, AccountKeyStore, AccountService, AccountStore},
    transport::AcmeClient,
};
use std::sync::Arc;

async fn context(options: &mut AccountArgs) -> CliResult<CliContext> {
    let settings = CliSettings::load(options).await?;
    super::selection::complete(options, &settings, super::selection::Mode::Existing).await?;
    settings.account(options).await
}

pub(super) async fn update_contacts(args: UpdateContactArgs) -> CliResult<AccountReport> {
    let mut options = AccountArgs::from(args.network);
    let context = context(&mut options).await?;
    let contacts = super::interaction::replacement_contacts(
        args.contact,
        args.clear_contacts,
        terminal::interactive(options.json),
        &mut super::interaction::TerminalPrompts,
    )?;
    let signer = context
        .store
        .signer(&context.directory, &context.name, false)
        .await?;
    let record = context
        .store
        .load(&context.directory, &signer.jwk()?.thumbprint()?)
        .await?
        .ok_or(AccountError::AccountDoesNotExist)?;
    record
        .action(aster_acme_core::account::AccountOperation::Update)
        .map_err(AccountError::from)?;
    terminal::confirm_action(
        &format!(
            "Update account contacts\n  Name: {}\n  CA: {}\n  Contacts: {}",
            terminal::safe(&context.name),
            terminal::safe(context.directory.as_str()),
            if contacts.is_empty() {
                "(clear all)".into()
            } else {
                terminal::safe(&contacts.join(", "))
            }
        ),
        "Replace these contacts?",
        args.yes,
        options.json,
    )?;
    let transport = context.transport_options(&options)?;
    let client = Arc::new(AcmeClient::discover(context.directory, transport).await?);
    let account = AccountService::new(client, context.store)
        .update_contacts(signer.as_ref(), contacts)
        .await?;
    Ok(AccountReport::Remote {
        name: context.name,
        account,
        action: RemoteAction::UpdateContact,
        reused: false,
    })
}

pub(super) async fn rotate_key(args: RotateKeyArgs) -> CliResult<AccountReport> {
    let mut options = AccountArgs::from(args.network);
    let context = context(&mut options).await?;
    terminal::confirm_action(
        &format!(
            "Rotate account signing key\n  Name: {}\n  CA: {}\n\nThe new key will replace this account's signing key.\nAn unfinished rotation will be reconciled using its saved new key.",
            terminal::safe(&context.name),
            terminal::safe(context.directory.as_str())
        ),
        "Rotate or reconcile this key?",
        args.yes,
        options.json,
    )?;
    let transport = context.transport_options(&options)?;
    let client = Arc::new(AcmeClient::discover(context.directory, transport).await?);
    let record = AccountService::new(client, context.store.clone())
        .rotate_key(context.store.as_ref())
        .await?;
    Ok(AccountReport::KeyRotated {
        name: context.name,
        record,
    })
}
