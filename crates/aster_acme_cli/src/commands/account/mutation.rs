//! Confirmed account mutations share selection, normalization, and service boundaries.
use crate::commands::account::{
    args::{AccountArgs, NetworkArgs, RotateKeyArgs, UpdateContactArgs},
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

/// Draft-ietf-acme-profiles (<https://datatracker.ietf.org/doc/html/draft-ietf-acme-profiles>):
/// read-only listing of the certificate profiles a CA advertises. Directory
/// discovery is unauthenticated; no account key or CA mutation is involved.
pub(super) async fn profiles(
    args: NetworkArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let mut options = AccountArgs::from(args);
    let settings = CliSettings::load(&options).await?;
    crate::commands::account::selection::complete(
        &mut options,
        &settings,
        crate::commands::account::selection::Mode::Existing,
        cli,
    )
    .await?;
    let context = settings.account(&options).await?;
    context.require_account().await?;
    let transport = context.transport_options(&options)?;
    let client = cli
        .http
        .discover(context.directory.clone(), transport)
        .await?;
    Ok(AccountReport::Profiles {
        directory: context.directory,
        profiles: client.directory().meta.profiles.clone(),
    })
}

/// Set or clear the account's default certificate profile. The preference is
/// local metadata: an explicit `cert issue --profile` always wins, and saved
/// certificate definitions never adopt a new default implicitly. A new name
/// must be advertised by the CA directory; an unreachable directory never
/// silently accepts a change.
pub(super) async fn set_profile(
    args: crate::commands::account::args::SetProfileArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let mut options = AccountArgs::from(args.network);
    let settings = CliSettings::load(&options).await?;
    crate::commands::account::selection::complete(
        &mut options,
        &settings,
        crate::commands::account::selection::Mode::Existing,
        cli,
    )
    .await?;
    let context = settings.account(&options).await?;
    context.require_account().await?;
    let signer = context
        .store
        .signer(
            &context.directory,
            &context.name,
            aster_acme::storage::account::KeyAccess::Existing,
        )
        .await?;
    let mut record = context
        .store
        .load(&context.directory, &signer.jwk()?.thumbprint()?)
        .await?
        .ok_or(AccountError::AccountDoesNotExist)?;
    record
        .action(aster_acme_core::account::AccountOperation::Update)
        .map_err(AccountError::from)?;
    let target = if args.clear {
        None
    } else {
        Some(
            args.profile
                .clone()
                .ok_or("Specify --profile <NAME> or --clear.")?,
        )
    };
    let transport = context.transport_options(&options)?;
    let client = cli
        .http
        .discover(context.directory.clone(), transport)
        .await?;
    let advertised = client.directory().meta.profiles.clone();
    if let Some(profile) = &target {
        match &advertised {
            None => {
                return Err(format!(
                    "CA directory does not advertise certificate profiles; profile {profile:?} cannot be saved"
                )
                .into());
            }
            Some(advertised) if !advertised.contains_key(profile) => {
                return Err(format!(
                    "CA directory does not advertise profile {profile:?}; available: {}",
                    advertised.keys().cloned().collect::<Vec<_>>().join(", ")
                )
                .into());
            }
            Some(_) => {}
        }
    }
    let previous = record.preferred_profile.clone();
    record.preferred_profile = target;
    terminal::confirm_action(
        &format!(
            "Set account default profile\n  Name: {}\n  CA: {}\n  Profile: {}",
            output::safe(&context.name),
            output::safe(context.directory.as_str()),
            record
                .preferred_profile
                .as_deref()
                .map_or_else(|| "(none; the CA default applies)".to_owned(), output::safe,),
        ),
        "Save this profile preference?",
        args.yes,
        &cli.output,
    )?;
    let lease = context
        .store
        .lock_account(&context.directory, &record.key_thumbprint)
        .await?;
    aster_acme::storage::account::AccountStore::save(context.store.as_ref(), &record, &lease)
        .await?;
    Ok(AccountReport::ProfilePreference {
        name: context.name,
        previous,
        current: record.preferred_profile,
    })
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
