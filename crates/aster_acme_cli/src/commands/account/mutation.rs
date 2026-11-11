//! Confirmed account mutations share selection, normalization, and service boundaries.
use super::{
    args::{AccountArgs, RotateKeyArgs, UpdateContactArgs},
    report::{AccountReport, RemoteAction},
};
use crate::common::output;
use crate::common::{
    context::{CliContext, CliSettings},
    error::CliResult,
    terminal,
};
use aster_acme::account::{
    AccountError, AccountKeyStore, AccountRotationStore, AccountService, AccountStore,
};
use std::sync::Arc;

async fn context(
    options: &mut AccountArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<CliContext> {
    let settings = CliSettings::load(options).await?;
    super::selection::complete(options, &settings, super::selection::Mode::Existing, cli).await?;
    let context = settings.account(options).await?;
    context.require_account().await?;
    Ok(context)
}

pub(super) async fn update_contacts(
    args: UpdateContactArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let mut options = AccountArgs::from(args.network);
    let context = context(&mut options, cli).await?;
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
    let contacts = super::interaction::replacement_contacts(
        args.contact,
        args.clear_contacts,
        terminal::interactive(options.json),
        &mut super::interaction::TerminalPrompts(&cli.output),
    )?;
    terminal::confirm_action(
        &format!(
            "Update account contacts\n  Name: {}\n  CA: {}\n  Contacts: {}",
            output::safe(&context.name),
            output::safe(context.directory.as_str()),
            if contacts.is_empty() {
                "(clear all)".into()
            } else {
                output::safe(&contacts.join(", "))
            }
        ),
        "Replace these contacts?",
        args.yes,
        &cli.output,
    )?;
    let transport = context.transport_options(&options)?;
    let client = Arc::new(cli.http.discover(context.directory, transport).await?);
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

pub(super) async fn rotate_key(
    args: RotateKeyArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let mut options = AccountArgs::from(args.network);
    let context = context(&mut options, cli).await?;
    // Opening a rotation session validates the existing old/staged key identity without
    // generating material. Release it before user input; service revalidates under lease.
    let checked = context.store.rotation(&context.directory).await?;
    drop(checked);
    terminal::confirm_action(
        &format!(
            "Rotate account signing key\n  Name: {}\n  CA: {}\n\nThe new key will replace this account's signing key.\nAn unfinished rotation will be reconciled using its saved new key.",
            output::safe(&context.name),
            output::safe(context.directory.as_str())
        ),
        "Rotate or reconcile this key?",
        args.yes,
        &cli.output,
    )?;
    let transport = context.transport_options(&options)?;
    let client = Arc::new(cli.http.discover(context.directory, transport).await?);
    let record = AccountService::new(client, context.store.clone())
        .rotate_key(context.store.as_ref())
        .await?;
    Ok(AccountReport::KeyRotated {
        name: context.name,
        record,
    })
}
