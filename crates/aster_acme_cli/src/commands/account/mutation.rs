//! Confirmed account mutations share selection, normalization, and service boundaries.
use crate::commands::account::{
    args::{AccountArgs, RotateKeyArgs, UpdateContactArgs},
    report::{AccountReport, RemoteAction},
};
use crate::common::output;
use crate::common::{
    context::{CliContext, CliSettings},
    error::CliResult,
    terminal,
};
use aster_acme::account::{AccountError, AccountService};
use aster_acme::storage::account::{AccountKeyStore, AccountRotationStore, AccountStore};
use std::sync::Arc;

async fn context(
    options: &mut AccountArgs,
    operation: aster_acme_core::account::AccountOperation,
    cli: &crate::common::context::CommandContext,
) -> CliResult<CliContext> {
    let settings = CliSettings::load(options).await?;
    crate::commands::account::selection::complete(
        options,
        &settings,
        crate::commands::account::selection::Mode::Operation(operation),
        cli,
    )
    .await?;
    let context = settings.account(options).await?;
    context.require_account().await?;
    Ok(context)
}

pub(super) async fn update_contacts(
    args: UpdateContactArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let mut options = AccountArgs::from(args.network);
    let context = context(
        &mut options,
        aster_acme_core::account::AccountOperation::Update,
        cli,
    )
    .await?;
    let signer = context
        .store
        .signer(
            &context.directory,
            &context.name,
            aster_acme::storage::account::KeyAccess::Existing,
        )
        .await?;
    let record = context
        .store
        .load(&context.directory, &signer.jwk()?.thumbprint()?)
        .await?
        .ok_or(AccountError::AccountDoesNotExist)?;
    record
        .action(aster_acme_core::account::AccountOperation::Update)
        .map_err(AccountError::from)?;
    let contacts = crate::commands::account::interaction::replacement_contacts(
        args.contact,
        args.clear_contacts,
        terminal::interactive(options.json),
        &mut crate::commands::account::interaction::TerminalPrompts(&cli.output),
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
    submit_contacts(context, signer, contacts, transport, cli).await
}

/// Execute the confirmed replacement using explicit HTTP policy, leaving selection
/// and terminal interaction in the command adapter above.
pub(super) async fn submit_contacts(
    context: CliContext,
    signer: Arc<dyn aster_acme::crypto::JwsSigner>,
    contacts: Vec<String>,
    transport: aster_acme::transport::TransportOptions,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let client = Arc::new(cli.http.discover(context.directory, transport).await?);
    let account = AccountService::new(client, context.store)
        .update_contacts(signer.as_ref(), contacts)
        .await?;
    Ok(AccountReport::Remote {
        name: context.name,
        account,
        action: RemoteAction::UpdateContact,
        auto_accepted_terms: false,
        reused: false,
    })
}

pub(super) async fn rotate_key(
    args: RotateKeyArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let mut options = AccountArgs::from(args.network);
    let context = context(
        &mut options,
        aster_acme_core::account::AccountOperation::RotateKey,
        cli,
    )
    .await?;
    // Opening a rotation session validates the existing old/staged key identity without
    // generating material. Release it before user input; service revalidates under lease.
    let checked = context.store.rotation(&context.directory).await?;
    let expected = checked.record();
    let old_algorithm = checked.old_signer().algorithm();
    let new_label = match args.key_algorithm {
        Some(algorithm) => algorithm.name(),
        None if checked.record().key_rotation.is_some() => "saved staged key",
        None => old_algorithm.name(),
    };
    drop(checked);
    terminal::confirm_action(
        &format!(
            "Rotate account signing key\n  Name: {}\n  CA: {}\n  Key type: {} → {}\n\nThe new key will replace this account's signing key.\nAn unfinished rotation will be reconciled using its saved new key.",
            output::safe(&context.name),
            output::safe(context.directory.as_str()),
            old_algorithm.name(),
            new_label
        ),
        "Rotate or reconcile this key?",
        args.yes,
        &cli.output,
    )?;
    if expected.key_rotation.as_ref().is_some_and(|rotation| {
        rotation.phase == aster_acme_core::account::KeyRotationPhase::Confirmed
    }) {
        let record = AccountService::finalize_confirmed_rotation(
            context.store.as_ref(),
            &context.directory,
            &expected,
            args.key_algorithm,
        )
        .await?;
        return Ok(AccountReport::KeyRotated {
            name: context.name,
            record,
        });
    }
    let transport = context.transport_options(&options)?;
    let client = Arc::new(cli.http.discover(context.directory, transport).await?);
    let record = AccountService::new(client, context.store.clone())
        .rotate_key(context.store.as_ref(), args.key_algorithm, Some(&expected))
        .await?;
    Ok(AccountReport::KeyRotated {
        name: context.name,
        record,
    })
}
