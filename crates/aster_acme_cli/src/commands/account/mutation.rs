//! Confirmed account mutations share selection, normalization, and service boundaries.
use crate::commands::account::{
    args::{AccountArgs, RotateKeyArgs},
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

/// Update account preferences: CA contacts and/or the default certificate
/// profile. Contact changes mutate the CA account; profile preferences are
/// local metadata validated against the advertised list when reachable.
/// Draft-ietf-acme-profiles
/// (<https://datatracker.ietf.org/doc/html/draft-ietf-acme-profiles>):
/// interactive updates pick their scope from a menu, mirroring the provider
/// editor. `None` means cancel; scripts never reach this path.
fn interactive_update_scope(cli: &crate::common::context::CommandContext) -> Option<(bool, bool)> {
    let choices = ["Contact addresses", "Default certificate profile", "Cancel"].map(str::to_owned);
    let selection = terminal::select_index_or_back(
        "Update which account preference?",
        &choices,
        0,
        &cli.output,
    )
    .ok()?;
    match selection {
        Some(0) => Some((true, false)),
        Some(1) => Some((false, true)),
        _ => None,
    }
}

pub(super) async fn update(
    args: crate::commands::account::args::UpdateArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let wants_contacts = args.contact_set() || args.clear_contacts;
    let wants_profile = args.profile_set() || args.clear_profile;
    let explicit_profile_set = args.profile.is_some();
    let profile_target = if args.clear_profile {
        None
    } else {
        args.profile.clone()
    };
    let mut options = AccountArgs::from(args.network);
    let context = context(
        &mut options,
        aster_acme_core::account::AccountOperation::Update,
        cli,
    )
    .await?;
    let interactive = terminal::interactive(options.json);
    let mut wants_contacts = wants_contacts;
    let mut wants_profile = wants_profile;
    let mut profile_target = profile_target;
    if !wants_contacts && !wants_profile {
        if !interactive {
            return Err(
                "Specify contacts with --contact/--clear-contacts, a profile with --profile/--clear-profile, or both.".into(),
            );
        }
        let Some((scope_contacts, scope_profile)) = interactive_update_scope(cli) else {
            return Err(crate::common::terminal::Canceled.into());
        };
        wants_contacts = scope_contacts;
        wants_profile = scope_profile;
    }
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
    if wants_contacts {
        let contacts = crate::commands::account::interaction::replacement_contacts(
            args.contact.clone(),
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
        let report = submit_contacts(&context, signer.clone(), contacts, transport, cli).await?;
        if !wants_profile {
            return Ok(report);
        }
    }
    if wants_profile {
        // Interactive path: pick from the advertised list, or clear explicitly.
        if interactive && profile_target.is_none() && !explicit_profile_set && !args.clear_profile {
            profile_target = interactive_profile_selection(&context, &options, cli).await?;
        }
        // Reload after a contact submission: the CA may have returned fresh
        // server state that this profile save must preserve, never clobber.
        let fresh = context
            .store
            .load(&context.directory, &signer.jwk()?.thumbprint()?)
            .await?
            .ok_or(AccountError::AccountDoesNotExist)?;
        let previous = fresh.preferred_profile.clone();
        let target = profile_target;
        let transport = context.transport_options(&options)?;
        save_profile_preference(&context, &fresh, target.clone(), transport, cli).await?;
        return Ok(AccountReport::ProfilePreference {
            name: context.name,
            previous,
            current: target,
        });
    }
    // Contacts path already returned above when requested.
    Err(
        "Specify contacts with --contact/--clear-contacts, a profile with --profile/--clear-profile, or both.".into(),
    )
}

/// Draft-ietf-acme-profiles interactive default-profile selection: the
/// advertised names plus an explicit clear, or cancellation without a change.
async fn interactive_profile_selection(
    context: &crate::common::context::CliContext,
    options: &AccountArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<Option<String>> {
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
        return Err(
            "CA directory does not advertise certificate profiles; nothing to select. Remove the profile preference with --clear-profile.".into(),
        );
    };
    let mut choices = advertised.keys().cloned().collect::<Vec<_>>();
    choices.push("(no default; the CA default applies)".to_owned());
    let selection =
        terminal::select_index_or_back("Default certificate profile:", &choices, 0, &cli.output)?
            .ok_or(crate::common::terminal::Canceled)?;
    Ok(if selection < advertised.len() {
        Some(choices[selection].clone())
    } else {
        None
    })
}

/// Validate and persist a profile preference; an unreachable directory never
/// silently accepts a change, and unadvertised names are rejected with the list.
async fn save_profile_preference(
    context: &CliContext,
    record: &aster_acme::account::AccountRecord,
    target: Option<String>,
    transport: aster_acme::transport::TransportOptions,
    cli: &crate::common::context::CommandContext,
) -> CliResult<()> {
    if let Some(profile) = &target {
        let advertised = match cli
            .http
            .discover(context.directory.clone(), transport)
            .await
        {
            Ok(client) => client.directory().meta.profiles.clone(),
            Err(error) => {
                return Err(format!(
                    "Cannot verify the profile against the CA directory ({error}); no change was saved. Retry when the CA is reachable."
                )
                .into());
            }
        };
        if let Some(advertised) = &advertised
            && !advertised.contains_key(profile)
        {
            return Err(format!(
                "CA directory does not advertise profile {profile:?}; available: {}",
                advertised.keys().cloned().collect::<Vec<_>>().join(", ")
            )
            .into());
        }
        if advertised.is_none() {
            return Err(format!(
                "CA directory does not advertise certificate profiles; profile {profile:?} cannot be saved"
            )
            .into());
        }
    }
    terminal::confirm_action(
        &format!(
            "Set account default profile\n  Name: {}\n  CA: {}\n  Profile: {}",
            output::safe(&context.name),
            output::safe(context.directory.as_str()),
            target
                .as_deref()
                .map_or_else(|| "(none; the CA default applies)".to_owned(), output::safe,),
        ),
        "Save this profile preference?",
        // The outer command already confirmed contact changes; profile writes
        // ride the same confirmation unless this is the only change.
        true,
        &cli.output,
    )?;
    let mut record = record.clone();
    record.preferred_profile = target;
    let lease = context
        .store
        .lock_account(&context.directory, &record.key_thumbprint)
        .await?;
    aster_acme::storage::account::AccountStore::save(context.store.as_ref(), &record, &lease)
        .await?;
    Ok(())
}

pub(super) async fn submit_contacts(
    context: &CliContext,
    signer: Arc<dyn aster_acme::crypto::JwsSigner>,
    contacts: Vec<String>,
    transport: aster_acme::transport::TransportOptions,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let client = Arc::new(
        cli.http
            .discover(context.directory.clone(), transport)
            .await?,
    );
    let account = AccountService::new(client, context.store.clone())
        .update_contacts(signer.as_ref(), contacts)
        .await?;
    Ok(AccountReport::Remote {
        name: context.name.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::context::CommandContext;
    use aster_acme::storage::account::KeyAccess;
    use aster_acme_cli_storage::account::CliAccountStore;
    use aster_acme_protocol::url::AcmeUrl;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn record(
        directory: &AcmeUrl,
        thumbprint: &str,
        account_url: Option<AcmeUrl>,
    ) -> aster_acme::account::AccountRecord {
        aster_acme::account::AccountRecord {
            key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
            user_agent: None,
            times: aster_acme::account::AccountTimes::default(),
            account_id: aster_acme::account::AccountRecord::stable_id(directory, thumbprint),
            directory_url: directory.clone(),
            key_thumbprint: thumbprint.to_owned(),
            account_url,
            contacts: Vec::new(),
            server_contacts: None,
            last_status: None,
            deactivation: aster_acme_core::account::DeactivationState::NotRequested,
            key_rotation: None,
            accepted_terms_url: None,
            preferred_profile: None,
            auto_accept_terms_updates: false,
            state: aster_acme_core::account::AccountRecordState::Registered,
        }
    }

    /// Registered loopback account bound to a wiremock directory advertising
    /// `meta.profiles` like a profiles-enabled CA.
    struct HarnessHandles {
        _temp: tempfile::TempDir,
    }

    async fn harness() -> (
        MockServer,
        CliContext,
        Arc<dyn aster_acme::crypto::JwsSigner>,
        aster_acme::transport::TransportOptions,
        AcmeUrl,
        HarnessHandles,
    ) {
        let server = MockServer::start().await;
        let temp = tempfile::tempdir().unwrap();
        let store =
            Arc::new(CliAccountStore::open(temp.path(), "work", Duration::from_secs(1)).unwrap());
        let directory = AcmeUrl::new(&format!("{}/directory", server.uri())).unwrap();
        let signer = store
            .signer(&directory, "work", KeyAccess::Create(None))
            .await
            .unwrap();
        let thumbprint = signer.jwk().unwrap().thumbprint().unwrap();
        let account_url = AcmeUrl::new(&format!("{}/acct/1", server.uri())).unwrap();
        let record = record(&directory, &thumbprint, Some(account_url));
        store.save(&record).await.unwrap();
        let options = AccountArgs {
            name: Some("work".into()),
            ca_directory: Some(directory.as_str().to_owned()),
            data_dir: Some(temp.path().into()),
            json: true,
            ..AccountArgs::default()
        };
        let context = CliSettings::load(&options)
            .await
            .unwrap()
            .account(&options)
            .await
            .unwrap();
        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "newNonce": format!("{}/nonce", server.uri()),
                "newAccount": format!("{}/new-account", server.uri()),
                "newOrder": format!("{}/orders", server.uri()),
                "meta": {"profiles": {
                    "classic": "https://ca.example/classic",
                    "shortlived": "https://ca.example/shortlived"
                }}
            })))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "initial"))
            .mount(&server)
            .await;
        let transport = aster_acme::transport::TransportOptions {
            allow_loopback_http: true,
            ..aster_acme::transport::TransportOptions::default()
        };
        (
            server,
            context,
            signer,
            transport,
            directory,
            HarnessHandles { _temp: temp },
        )
    }

    async fn stored(
        context: &CliContext,
        signer: &Arc<dyn aster_acme::crypto::JwsSigner>,
    ) -> aster_acme::account::AccountRecord {
        let thumbprint = signer.jwk().unwrap().thumbprint().unwrap();
        context
            .store
            .load(&context.directory, &thumbprint)
            .await
            .unwrap()
            .expect("registered account record")
    }

    #[tokio::test]
    async fn save_persists_advertised_selection() {
        let (_server, context, signer, transport, _directory, _handles) = harness().await;
        save_profile_preference(
            &context,
            &stored(&context, &signer).await,
            Some("shortlived".into()),
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        assert_eq!(
            stored(&context, &signer).await.preferred_profile.as_deref(),
            Some("shortlived")
        );
    }

    #[tokio::test]
    async fn unadvertised_profile_is_rejected_with_available_names_and_store_untouched() {
        let (_server, context, signer, transport, _directory, _handles) = harness().await;
        let error = save_profile_preference(
            &context,
            &stored(&context, &signer).await,
            Some("premium".into()),
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("premium"), "{text}");
        assert!(
            text.contains("classic") && text.contains("shortlived"),
            "{text}"
        );
        assert_eq!(
            stored(&context, &signer).await.preferred_profile,
            None,
            "a rejected change never half-persists"
        );
    }

    #[tokio::test]
    async fn clear_is_local_and_sets_none() {
        let (_server, context, signer, transport, _directory, _handles) = harness().await;
        save_profile_preference(
            &context,
            &stored(&context, &signer).await,
            Some("classic".into()),
            transport.clone(),
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        save_profile_preference(
            &context,
            &stored(&context, &signer).await,
            None,
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        assert_eq!(stored(&context, &signer).await.preferred_profile, None);
    }

    #[tokio::test]
    async fn unreachable_directory_blocks_change_without_silent_accept() {
        // A fresh server with zero mounts: discovery fails, nothing changes.
        let server = MockServer::start().await;
        let temp = tempfile::tempdir().unwrap();
        let store =
            Arc::new(CliAccountStore::open(temp.path(), "work", Duration::from_secs(1)).unwrap());
        let directory = AcmeUrl::new(&format!("{}/directory", server.uri())).unwrap();
        let signer = store
            .signer(&directory, "work", KeyAccess::Create(None))
            .await
            .unwrap();
        let thumbprint = signer.jwk().unwrap().thumbprint().unwrap();
        let account_url = AcmeUrl::new(&format!("{}/acct/1", server.uri())).unwrap();
        let record = record(&directory, &thumbprint, Some(account_url));
        store.save(&record).await.unwrap();
        let options = AccountArgs {
            name: Some("work".into()),
            ca_directory: Some(directory.as_str().to_owned()),
            data_dir: Some(temp.path().into()),
            json: true,
            ..AccountArgs::default()
        };
        let context = CliSettings::load(&options)
            .await
            .unwrap()
            .account(&options)
            .await
            .unwrap();
        let error = save_profile_preference(
            &context,
            &record,
            Some("shortlived".into()),
            aster_acme::transport::TransportOptions {
                allow_loopback_http: true,
                ..aster_acme::transport::TransportOptions::default()
            },
            &CommandContext::new(true),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("no change was saved"));
        assert_eq!(record.preferred_profile, None);
    }

    /// The review regression: contacts submission lands CA-observed contacts
    /// in storage; the profile save must preserve that fresh server state
    /// instead of reverting to the pre-update snapshot.
    #[tokio::test]
    async fn profile_save_preserves_server_contacts_landed_by_contact_update() {
        let (_server, context, signer, transport, _directory, _handles) = harness().await;
        let stale = stored(&context, &signer).await;
        let mut fresh = stale.clone();
        fresh.server_contacts = Some(vec!["mailto:new@example.com".into()]);
        context.store.save(&fresh).await.unwrap();

        save_profile_preference(
            &context,
            &stored(&context, &signer).await,
            Some("shortlived".into()),
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let final_record = stored(&context, &signer).await;
        assert_eq!(
            final_record.preferred_profile.as_deref(),
            Some("shortlived")
        );
        assert_eq!(
            final_record.server_contacts.as_deref(),
            Some(["mailto:new@example.com".to_owned()].as_slice()),
            "profile save must not revert CA-observed contacts"
        );
    }
}
