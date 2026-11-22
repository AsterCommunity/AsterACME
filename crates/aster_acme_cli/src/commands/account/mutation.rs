//! Confirmed account mutations share selection, normalization, and service boundaries.
use crate::commands::account::{
    args::{AccountArgs, RotateKeyArgs},
    interaction::update_scope_choice,
    report::AccountReport,
};
use crate::common::output;
use crate::common::{
    context::{CliContext, CliSettings},
    error::CliResult,
    terminal,
};
use aster_acme::account::{AccountError, AccountService};
use aster_acme::crypto::JwsSigner;
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

/// Translate the menu outcome into the update intent flags; leaving the menu
/// without a scope (the Cancel entry or Esc) cancels the whole update.
fn scope_intent(
    scope: Option<crate::commands::account::interaction::UpdateScope>,
) -> CliResult<(bool, bool, bool)> {
    use crate::commands::account::interaction::UpdateScope;
    match scope {
        Some(UpdateScope::Contacts) => Ok((true, false, false)),
        Some(UpdateScope::Profile) => Ok((false, true, false)),
        Some(UpdateScope::TermsDelegation) => Ok((false, false, true)),
        None => Err(crate::common::terminal::Canceled.into()),
    }
}

pub(super) async fn update(
    args: crate::commands::account::args::UpdateArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    let mut options = AccountArgs::from(args.network.clone());
    let context = context(
        &mut options,
        aster_acme_core::account::AccountOperation::Update,
        cli,
    )
    .await?;
    let transport = context.transport_options(&options)?;
    update_with_transport(args, &context, transport, cli).await
}

/// Command body after account selection; `transport` is injected so the
/// loopback test harness can exercise the production path unchanged.
/// Resolve the replacement contact list from flags or the interactive prompt.
fn replacement_contacts(
    args: &crate::commands::account::args::UpdateArgs,
    output: &crate::common::session::OutputSession,
) -> CliResult<Vec<String>> {
    crate::commands::account::interaction::replacement_contacts(
        args.contact.clone(),
        args.clear_contacts,
        terminal::interactive(args.network.local.json),
        &mut crate::commands::account::interaction::TerminalPrompts(output),
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "Update dispatch keeps scope admission, contact persistence and profile selection in one auditable flow"
)]
pub(super) async fn update_with_transport(
    args: crate::commands::account::args::UpdateArgs,
    context: &CliContext,
    transport: aster_acme::transport::TransportOptions,
    cli: &crate::common::context::CommandContext,
) -> CliResult<AccountReport> {
    // Explicit flags may combine all scopes; without flags the terminal menu
    // picks exactly one scope.
    let terms_flag = if args.auto_accept_new_terms {
        Some(true)
    } else if args.clear_auto_accept_new_terms {
        Some(false)
    } else {
        None
    };
    let explicit_profile_set = args.profile.is_some();
    let profile_target = if args.clear_profile {
        None
    } else {
        args.profile.clone()
    };
    let interactive = terminal::interactive(args.network.local.json);
    let mut wants_contacts = args.contact_set() || args.clear_contacts;
    let mut wants_profile = args.profile_set() || args.clear_profile;
    let mut terms_scope = terms_flag.is_some();
    let mut profile_target = profile_target;
    if !wants_contacts && !wants_profile && terms_flag.is_none() {
        if !interactive {
            return Err(
                "Specify contacts with --contact/--clear-contacts, a profile with --profile/--clear-profile, or future terms delegation with --auto-accept-new-terms/--clear-auto-accept-new-terms.".into(),
            );
        }
        let (scope_contacts, scope_profile, scope_terms) = scope_intent(update_scope_choice(
            &mut crate::commands::account::interaction::TerminalPrompts(&cli.output),
        )?)?;
        wants_contacts = scope_contacts;
        wants_profile = scope_profile;
        terms_scope = scope_terms;
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
    let terms_target = terms_flag.unwrap_or(!record.auto_accept_terms_updates);
    // Every directory-backed validation happens BEFORE the first side effect
    // (the contact mutation), so an unreachable or disagreeing CA leaves the
    // account untouched instead of half-applying the update.
    let preflight = update_preflight(
        context,
        transport.clone(),
        wants_profile && !args.clear_profile,
        terms_scope && terms_target,
        profile_target.as_deref(),
        cli,
    )
    .await?;
    let mut outcome = crate::commands::account::report::UpdateOutcome {
        name: context.name.clone(),
        contacts: None,
        profile: None,
        terms: None,
    };
    if wants_contacts {
        let contacts = replacement_contacts(&args, &cli.output)?;
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
        outcome.contacts =
            Some(submit_contacts(context, signer.clone(), contacts, transport.clone(), cli).await?);
    }
    if wants_profile {
        if interactive && profile_target.is_none() && !explicit_profile_set && !args.clear_profile {
            profile_target = interactive_profile_selection(
                record.preferred_profile.as_deref(),
                preflight.advertised_profiles.as_ref(),
                cli,
            )?;
        }
        match save_profile_preference(
            context,
            signer.as_ref(),
            profile_target,
            preflight.advertised_profiles.as_ref(),
            args.yes || wants_contacts,
            cli,
        )
        .await
        {
            Ok(change) => outcome.profile = Some(change),
            Err(error) => {
                return Err(partial_update_error(
                    &outcome,
                    "the profile preference update did not complete",
                    error,
                ));
            }
        }
    }
    if terms_scope {
        match apply_terms_change(
            context,
            &signer,
            &record,
            terms_target,
            args.yes && terms_flag.is_some(),
            &preflight,
            cli,
        )
        .await
        {
            Ok(change) => outcome.terms = Some(change),
            Err(error) => {
                return Err(partial_update_error(
                    &outcome,
                    "the terms delegation update did not complete",
                    error,
                ));
            }
        }
    }
    Ok(AccountReport::Updated(outcome))
}

/// Directory-backed inputs for one update: the advertised profile map and the
/// CA's current terms value, read once before any mutation.
struct UpdatePreflight {
    advertised_profiles: Option<std::collections::BTreeMap<String, String>>,
    advertised_terms: Option<String>,
    terms_directory_checked: bool,
}

/// Validate what the CA must confirm before anything changes. Profile names are
/// checked against the advertisement; enabling the terms delegation requires the
/// live directory's current terms value and fails closed without one.
async fn update_preflight(
    context: &CliContext,
    transport: aster_acme::transport::TransportOptions,
    profiles: bool,
    terms_enable: bool,
    profile_target: Option<&str>,
    cli: &crate::common::context::CommandContext,
) -> CliResult<UpdatePreflight> {
    if !profiles && !terms_enable {
        return Ok(UpdatePreflight {
            advertised_profiles: None,
            advertised_terms: None,
            terms_directory_checked: false,
        });
    }
    let client = cli
        .http
        .discover(context.directory.clone(), transport)
        .await
        .map_err(|error| -> Box<dyn std::error::Error> {
            if terms_enable {
                Box::new(crate::common::error::ContextError {
                    context: "Cannot enable automatic terms updates: the CA directory could not be read to confirm its current terms".into(),
                    source: Box::new(error),
                })
            } else {
                error.into()
            }
        })?;
    let advertised_profiles = if profiles {
        let advertised = client.directory().meta.profiles.clone();
        // Draft-ietf-acme-profiles: an invalid name is rejected before any
        // mutation, so the update never half-applies.
        if let Some(target) = profile_target {
            validate_profile_advertisement(advertised.as_ref(), target)?;
        }
        advertised
    } else {
        None
    };
    Ok(UpdatePreflight {
        advertised_profiles,
        // Reading the directory for a profile never grants terms consent.
        advertised_terms: if terms_enable {
            client.directory().meta.terms_of_service.clone()
        } else {
            None
        },
        terms_directory_checked: terms_enable,
    })
}

/// Late-failure context: name the scopes that already took effect before the
/// failed one, so a committed CA mutation keeps its evidence in the error.
fn partial_update_error(
    applied: &crate::commands::account::report::UpdateOutcome,
    failed: &str,
    error: Box<dyn std::error::Error>,
) -> Box<dyn std::error::Error> {
    let mut context = String::new();
    if applied.contacts.is_some() {
        context.push_str("Contacts were updated at the CA; ");
    }
    if applied.profile.is_some() {
        context.push_str("the default profile was saved; ");
    }
    context.push_str(failed);
    Box::new(crate::common::error::ContextError {
        context,
        source: error,
    })
}

/// Toggle the durable future-terms delegation under a lease. Enabling accepts
/// the preflight-read directory terms value; disabling is pure local metadata.
/// Neither path sends a CA account update, so this never claims the CA accepted
/// anything.
async fn apply_terms_change(
    context: &CliContext,
    signer: &Arc<dyn JwsSigner>,
    snapshot: &aster_acme::account::AccountRecord,
    target: bool,
    confirmed: bool,
    preflight: &UpdatePreflight,
    cli: &crate::common::context::CommandContext,
) -> CliResult<crate::commands::account::report::TermsChange> {
    let directory_checked = preflight.terms_directory_checked;
    let advertised_terms = preflight.advertised_terms.clone();
    let accepted = snapshot
        .accepted_terms_url
        .as_ref()
        .map_or_else(|| "(none saved)".to_owned(), |url| output::safe(url));
    let advertised = advertised_terms.as_ref().map_or_else(
        || {
            if directory_checked {
                "not advertised".to_owned()
            } else {
                "not checked".to_owned()
            }
        },
        |url| output::safe(url),
    );
    let details = if target {
        format!(
            "Enable automatic CA terms updates\n  Name: {}\n  CA: {}\n  Current CA terms: {}\n  Previously accepted: {}\n\nThis accepts the CA's current terms and lets unattended account checks accept future terms URL changes without review.\nThe CA account is not modified; the consent is stored locally.",
            output::safe(&context.name),
            output::safe(context.directory.as_str()),
            advertised,
            accepted,
        )
    } else {
        format!(
            "Disable automatic CA terms updates\n  Name: {}\n  CA: {}\n  Accepted terms URL (retained): {}\n\nFuture terms URL changes will block unattended account checks until you review them.",
            output::safe(&context.name),
            output::safe(context.directory.as_str()),
            accepted,
        )
    };
    terminal::confirm_action(
        &details,
        if target {
            "Enable automatic terms updates?"
        } else {
            "Disable automatic terms updates?"
        },
        confirmed,
        &cli.output,
    )?;
    let thumbprint = signer.jwk()?.thumbprint()?;
    let lease = context
        .store
        .lock_account(&context.directory, &thumbprint)
        .await?;
    let mut record = context
        .store
        .load(&context.directory, &thumbprint)
        .await?
        .ok_or(AccountError::AccountDoesNotExist)?;
    if record.directory_url != context.directory
        || record.key_thumbprint != thumbprint
        || record.key_algorithm != signer.algorithm()
    {
        return Err(AccountError::IdentityMismatch.into());
    }
    record
        .action(aster_acme_core::account::AccountOperation::Update)
        .map_err(AccountError::from)?;
    let previous = record.auto_accept_terms_updates;
    if previous != snapshot.auto_accept_terms_updates {
        return Err("Automatic CA terms delegation changed while this update was awaiting confirmation; the concurrently saved delegation was preserved. Rerun account update to review the current authorization.".into());
    }
    record.auto_accept_terms_updates = target;
    if target {
        if record.accepted_terms_url != snapshot.accepted_terms_url
            && advertised_terms
                .as_ref()
                .is_none_or(|url| record.accepted_terms_url.as_ref() != Some(url))
        {
            return Err("Accepted CA terms changed while this update was awaiting confirmation; the concurrently saved value was preserved. Rerun account update to review the current terms.".into());
        }
        if let Some(url) = &advertised_terms {
            record.accepted_terms_url = Some(url.clone());
        }
    }
    AccountStore::save(context.store.as_ref(), &record, &lease)
        .await
        .map_err(|error| crate::common::error::ContextError {
            context: "Could not confirm that the terms delegation was saved; inspect account show before retrying".into(),
            source: Box::new(error),
        })?;
    Ok(crate::commands::account::report::TermsChange {
        previous,
        current: record.auto_accept_terms_updates,
        accepted_terms_url: record.accepted_terms_url,
        advertised_terms_url: advertised_terms,
        directory_checked,
    })
}

/// Draft-ietf-acme-profiles interactive default-profile selection: the
/// advertised names plus an explicit clear, or cancellation without a change.
fn interactive_profile_selection(
    current_default: Option<&str>,
    advertised: Option<&std::collections::BTreeMap<String, String>>,
    cli: &crate::common::context::CommandContext,
) -> CliResult<Option<String>> {
    let Some(advertised) = advertised.filter(|map| !map.is_empty()) else {
        return Err(
            "CA directory does not advertise certificate profiles; nothing to select. Remove the profile preference with --clear-profile.".into(),
        );
    };
    // CA-provided names are untrusted terminal text: escape the display
    // labels, while selection indexes the original names unchanged.
    let names = advertised.keys().cloned().collect::<Vec<_>>();
    let mut choices = names
        .iter()
        .map(|name| output::safe(name))
        .collect::<Vec<_>>();
    choices.push("(no default; the CA default applies)".to_owned());
    // Preselect the account's current default so plain confirmation keeps it.
    let default = names
        .iter()
        .position(|name| Some(name.as_str()) == current_default)
        .unwrap_or(0);
    let selection = terminal::select_index_or_back(
        "Default certificate profile:",
        &choices,
        default,
        &cli.output,
    )?
    .ok_or(crate::common::terminal::Canceled)?;
    Ok(if selection < names.len() {
        Some(names[selection].clone())
    } else {
        None
    })
}

/// Validate a named preference against preflight, or clear it without HTTP.
/// Reload under the lease after confirmation so concurrent metadata is retained.
async fn save_profile_preference(
    context: &CliContext,
    signer: &dyn JwsSigner,
    target: Option<String>,
    advertised: Option<&std::collections::BTreeMap<String, String>>,
    confirmed: bool,
    cli: &crate::common::context::CommandContext,
) -> CliResult<crate::commands::account::report::ProfileChange> {
    if let Some(profile) = &target {
        // The advertisement was validated before the contact mutation ran;
        // reaching here means the CA was reachable and the name checked out.
        validate_profile_advertisement(advertised, profile)?;
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
        confirmed,
        &cli.output,
    )?;
    let thumbprint = signer.jwk()?.thumbprint()?;
    let lease = context
        .store
        .lock_account(&context.directory, &thumbprint)
        .await?;
    let mut record = context
        .store
        .load(&context.directory, &thumbprint)
        .await?
        .ok_or(AccountError::AccountDoesNotExist)?;
    if record.key_algorithm != signer.algorithm() {
        return Err(AccountError::IdentityMismatch.into());
    }
    record
        .action(aster_acme_core::account::AccountOperation::Update)
        .map_err(AccountError::from)?;
    let previous = record.preferred_profile.clone();
    record.preferred_profile.clone_from(&target);
    AccountStore::save(context.store.as_ref(), &record, &lease)
        .await
        .map_err(|error| crate::common::error::ContextError {
            context: "Could not confirm that the profile preference was saved; inspect account show before retrying".into(),
            source: Box::new(error),
        })?;
    Ok(crate::commands::account::report::ProfileChange {
        previous,
        current: target,
    })
}

/// Validate an explicit registration profile against a directory response:
/// `Err` names the requested profile and every advertised alternative.
/// `Ok` on `None` means the CA default applies.
/// Build the Profiles report from an already-discovered client. Split out of
/// the Show arm so the loopback harness can exercise it with an explicit
/// loopback-permitting transport.
pub(super) fn profiles_listing_from_client(
    context: &CliContext,
    client: &aster_acme::transport::AcmeClient,
) -> AccountReport {
    AccountReport::Profiles {
        directory: context.directory.clone(),
        profiles: client.directory().meta.profiles.clone(),
    }
}

pub(crate) fn validate_profile_advertisement(
    advertised: Option<&std::collections::BTreeMap<String, String>>,
    profile: &str,
) -> CliResult<()> {
    match advertised {
        None => Err(format!(
            "CA directory does not advertise certificate profiles; profile {profile:?} cannot be saved. Register without --profile, then set it with account update --profile once the CA advertises profiles (account show --profiles lists the advertisement)."
        )
        .into()),
        Some(advertised) if !advertised.contains_key(profile) => Err(format!(
            "CA directory does not advertise profile {profile:?}; available: {}",
            advertised.keys().cloned().collect::<Vec<_>>().join(", ")
        )
        .into()),
        Some(_) => Ok(()),
    }
}

pub(super) async fn submit_contacts(
    context: &CliContext,
    signer: Arc<dyn aster_acme::crypto::JwsSigner>,
    contacts: Vec<String>,
    transport: aster_acme::transport::TransportOptions,
    cli: &crate::common::context::CommandContext,
) -> CliResult<crate::commands::account::report::ContactsUpdate> {
    let client = Arc::new(
        cli.http
            .discover(context.directory.clone(), transport)
            .await.map_err(|error| crate::common::error::ContextError {
                context: "Contacts were not submitted to the CA; directory discovery failed before any contact mutation".into(),
                source: Box::new(error),
            })?,
    );
    let account = AccountService::new(client, context.store.clone())
        .update_contacts(signer.as_ref(), contacts)
        .await?;
    Ok(crate::commands::account::report::ContactsUpdate { account })
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
    use crate::commands::account::mutation::*;

    use crate::common::args::HttpArgs;
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

    /// Registered loopback account bound to a wiremock directory. `terms`
    /// controls the advertised `meta.termsOfService`.
    struct HarnessHandles {
        _temp: tempfile::TempDir,
    }

    async fn account_fixture(
        server: &MockServer,
    ) -> (
        CliContext,
        Arc<dyn aster_acme::crypto::JwsSigner>,
        aster_acme::transport::TransportOptions,
        HarnessHandles,
    ) {
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
        let transport = aster_acme::transport::TransportOptions {
            allow_loopback_http: true,
            ..aster_acme::transport::TransportOptions::default()
        };
        (context, signer, transport, HarnessHandles { _temp: temp })
    }

    async fn harness() -> (
        MockServer,
        CliContext,
        Arc<dyn aster_acme::crypto::JwsSigner>,
        aster_acme::transport::TransportOptions,
        AcmeUrl,
        HarnessHandles,
    ) {
        harness_with_terms(None).await
    }

    async fn harness_with_terms(
        terms: Option<&str>,
    ) -> (
        MockServer,
        CliContext,
        Arc<dyn aster_acme::crypto::JwsSigner>,
        aster_acme::transport::TransportOptions,
        AcmeUrl,
        HarnessHandles,
    ) {
        let server = MockServer::start().await;
        let (context, signer, transport, handles) = account_fixture(&server).await;
        let mut meta = serde_json::json!({"profiles": {
            "classic": "https://ca.example/classic",
            "shortlived": "https://ca.example/shortlived"
        }});
        if let Some(terms) = terms {
            meta["termsOfService"] = serde_json::json!(terms);
        }
        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "newNonce": format!("{}/nonce", server.uri()),
                "newAccount": format!("{}/new-account", server.uri()),
                "newOrder": format!("{}/orders", server.uri()),
                "meta": meta
            })))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "initial"))
            .mount(&server)
            .await;
        let directory = context.directory.clone();
        (server, context, signer, transport, directory, handles)
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
        let (_server, context, signer, _transport, _directory, _handles) = harness().await;
        save_profile_preference(
            &context,
            signer.as_ref(),
            Some("shortlived".into()),
            Some(&std::collections::BTreeMap::from([
                (
                    "classic".to_owned(),
                    "https://ca.example/classic".to_owned(),
                ),
                (
                    "shortlived".to_owned(),
                    "https://ca.example/shortlived".to_owned(),
                ),
            ])),
            true,
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
        let (_server, context, signer, _transport, _directory, _handles) = harness().await;
        let error = save_profile_preference(
            &context,
            signer.as_ref(),
            Some("premium".into()),
            Some(&std::collections::BTreeMap::from([
                (
                    "classic".to_owned(),
                    "https://ca.example/classic".to_owned(),
                ),
                (
                    "shortlived".to_owned(),
                    "https://ca.example/shortlived".to_owned(),
                ),
            ])),
            true,
            &CommandContext::new(true),
        )
        .await
        .err()
        .unwrap();
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
        let (_server, context, signer, _transport, _directory, _handles) = harness().await;
        save_profile_preference(
            &context,
            signer.as_ref(),
            Some("classic".into()),
            Some(&std::collections::BTreeMap::from([
                (
                    "classic".to_owned(),
                    "https://ca.example/classic".to_owned(),
                ),
                (
                    "shortlived".to_owned(),
                    "https://ca.example/shortlived".to_owned(),
                ),
            ])),
            true,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        save_profile_preference(
            &context,
            signer.as_ref(),
            None,
            Some(&std::collections::BTreeMap::from([
                (
                    "classic".to_owned(),
                    "https://ca.example/classic".to_owned(),
                ),
                (
                    "shortlived".to_owned(),
                    "https://ca.example/shortlived".to_owned(),
                ),
            ])),
            true,
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
        // The hoisted validation in update_with_transport discovers the
        // directory before anything else; with no mount the profile change
        // fails before any contact mutation or persistence.
        let args = crate::commands::account::args::UpdateArgs {
            network: crate::commands::account::args::NetworkArgs {
                identity: crate::commands::account::args::NameArgs {
                    name: Some("work".into()),
                    ..Default::default()
                },
                ca: crate::commands::account::args::CaArgs {
                    ca_directory: Some(directory.as_str().to_owned()),
                    ..Default::default()
                },
                http: HttpArgs::default(),
                local: crate::common::args::LocalArgs {
                    data_dir: Some(temp.path().into()),
                    json: true,
                },
            },
            profile: Some("shortlived".into()),
            yes: true,
            ..Default::default()
        };
        let error = match update_with_transport(
            args,
            &context,
            aster_acme::transport::TransportOptions {
                allow_loopback_http: true,
                ..aster_acme::transport::TransportOptions::default()
            },
            &CommandContext::new(true),
        )
        .await
        {
            Err(error) => error.to_string(),
            Ok(_) => panic!("profile change must fail without advertisement"),
        };
        assert!(error.contains("404"), "{error}");
        assert_eq!(record.preferred_profile, None);
    }

    /// The review regression: contacts submission lands CA-observed contacts
    /// in storage; the profile save must preserve that fresh server state
    /// instead of reverting to the pre-update snapshot.
    #[tokio::test]
    async fn profile_save_preserves_server_contacts_landed_by_contact_update() {
        let (_server, context, signer, _transport, _directory, _handles) = harness().await;
        let stale = stored(&context, &signer).await;
        let mut fresh = stale.clone();
        fresh.server_contacts = Some(vec!["mailto:new@example.com".into()]);
        context.store.save(&fresh).await.unwrap();

        save_profile_preference(
            &context,
            signer.as_ref(),
            Some("shortlived".into()),
            Some(&std::collections::BTreeMap::from([
                (
                    "classic".to_owned(),
                    "https://ca.example/classic".to_owned(),
                ),
                (
                    "shortlived".to_owned(),
                    "https://ca.example/shortlived".to_owned(),
                ),
            ])),
            true,
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

    /// End-to-end `update`: contact replacement (kid-signed POST to the CA)
    /// followed by the profile save must land both — and the profile save
    /// must preserve the CA-observed contacts (the review regression).
    #[tokio::test]
    async fn update_applies_contacts_then_profile_preserving_server_state() {
        let (server, context, signer, transport, _directory, _handles) = harness().await;
        let _thumbprint = signer.jwk().unwrap().thumbprint().unwrap();
        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "initial"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/acct/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "valid",
                // ACME account objects carry the singular `contact` field.
                "contact": ["mailto:new@example.com"]
            })))
            .mount(&server)
            .await;
        let args = crate::commands::account::args::UpdateArgs {
            network: crate::commands::account::args::NetworkArgs {
                identity: crate::commands::account::args::NameArgs {
                    name: Some("work".into()),
                    ..Default::default()
                },
                ca: crate::commands::account::args::CaArgs {
                    ca_directory: Some(context.directory.as_str().to_owned()),
                    ..Default::default()
                },
                http: HttpArgs::default(),
                local: crate::common::args::LocalArgs {
                    data_dir: Some(context.config_path.parent().unwrap().to_path_buf()),
                    json: true,
                },
            },
            contact: vec!["mailto:new@example.com".into()],
            clear_contacts: false,
            profile: Some("shortlived".into()),
            clear_profile: false,
            auto_accept_new_terms: false,
            clear_auto_accept_new_terms: false,
            yes: true,
        };
        // Loopback CA: inject the loopback-permitting transport through the
        // same seam the production path uses for its resolved transport.
        let report = update_with_transport(args, &context, transport, &CommandContext::new(true))
            .await
            .unwrap();
        // The combined invocation reports both scopes: the CA-committed contact
        // evidence and the local profile preference.
        let json = report_json(&report);
        assert_eq!(json["name"], "work");
        assert!(json["contacts"].is_object(), "{json}");
        assert_eq!(
            json["contacts"]["contacts"],
            serde_json::json!(["mailto:new@example.com"])
        );
        assert_eq!(json["profile"]["current"], "shortlived");
        assert_eq!(json["terms"], serde_json::Value::Null);
        assert!(report_text(&report).contains("Updated contacts for"));
        assert!(report_text(&report).contains("default profile"));
        let record = stored(&context, &signer).await;
        assert_eq!(record.preferred_profile.as_deref(), Some("shortlived"));
        // Contacts: the local intent is kept and the CA-observed value stored.
        assert_eq!(record.contacts, ["mailto:new@example.com"]);
        assert_eq!(
            record.server_contacts.as_deref(),
            Some(["mailto:new@example.com".to_owned()].as_slice())
        );
    }

    fn report_json(report: &AccountReport) -> serde_json::Value {
        crate::commands::account::render::tests::json_value(report)
    }

    /// Update args bound to the harness account, JSON mode, no scopes selected.
    fn update_args(context: &CliContext) -> crate::commands::account::args::UpdateArgs {
        crate::commands::account::args::UpdateArgs {
            network: crate::commands::account::args::NetworkArgs {
                identity: crate::commands::account::args::NameArgs {
                    name: Some("work".into()),
                    ..Default::default()
                },
                ca: crate::commands::account::args::CaArgs {
                    ca_directory: Some(context.directory.as_str().to_owned()),
                    ..Default::default()
                },
                http: HttpArgs::default(),
                local: crate::common::args::LocalArgs {
                    data_dir: Some(context.config_path.parent().unwrap().to_path_buf()),
                    json: true,
                },
            },
            ..Default::default()
        }
    }

    #[test]
    fn scope_intent_maps_each_menu_scope_and_cancels_without_one() {
        use crate::commands::account::interaction::UpdateScope;
        assert_eq!(
            scope_intent(Some(UpdateScope::Contacts)).unwrap(),
            (true, false, false)
        );
        assert_eq!(
            scope_intent(Some(UpdateScope::Profile)).unwrap(),
            (false, true, false)
        );
        assert_eq!(
            scope_intent(Some(UpdateScope::TermsDelegation)).unwrap(),
            (false, false, true)
        );
        assert!(
            scope_intent(None)
                .unwrap_err()
                .is::<crate::common::terminal::Canceled>()
        );
    }

    #[tokio::test]
    async fn update_without_an_explicit_scope_lists_every_option() {
        let (_server, context, _signer, transport, _directory, _handles) =
            harness_with_terms(None).await;
        let args = crate::commands::account::args::UpdateArgs {
            network: crate::commands::account::args::NetworkArgs {
                identity: crate::commands::account::args::NameArgs::default(),
                ca: crate::commands::account::args::CaArgs::default(),
                http: HttpArgs::default(),
                local: crate::common::args::LocalArgs {
                    data_dir: None,
                    json: true,
                },
            },
            ..Default::default()
        };
        let error = update_with_transport(args, &context, transport, &CommandContext::new(true))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("--contact/--clear-contacts")
                && error.contains("--profile/--clear-profile")
                && error.contains("--auto-accept-new-terms")
                && error.contains("--clear-auto-accept-new-terms"),
            "{error}"
        );
    }

    fn report_text(report: &AccountReport) -> String {
        crate::commands::account::render::render(
            report,
            crate::common::session::Format::plain(false),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn enabling_terms_delegation_accepts_current_terms_without_a_ca_write() {
        let (server, context, signer, transport, _directory, _handles) =
            harness_with_terms(Some("https://ca.example/terms/v2")).await;
        let before = server.received_requests().await.unwrap().len();
        let args = crate::commands::account::args::UpdateArgs {
            auto_accept_new_terms: true,
            yes: true,
            ..update_args(&context)
        };
        let report = update_with_transport(
            args,
            &context,
            transport.clone(),
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let json = report_json(&report);
        assert_eq!(json["name"], "work");
        assert_eq!(json["contacts"], serde_json::Value::Null);
        assert_eq!(json["terms"]["auto_accept_terms_updates"], true);
        assert_eq!(json["terms"]["previous_auto_accept_terms_updates"], false);
        assert_eq!(
            json["terms"]["accepted_terms_url"],
            "https://ca.example/terms/v2"
        );
        assert_eq!(
            json["terms"]["advertised_terms_url"],
            "https://ca.example/terms/v2"
        );
        assert_eq!(json["terms"]["directory_checked"], true);
        assert_eq!(json["terms"]["ca_account_update_sent"], false);
        let text = report_text(&report);
        assert!(
            text.contains("now accepts")
                && text.contains("the terms delegation itself sent no CA account request"),
            "{text}"
        );
        let record = stored(&context, &signer).await;
        assert!(record.auto_accept_terms_updates);
        assert_eq!(
            record.accepted_terms_url.as_ref().unwrap().as_str(),
            "https://ca.example/terms/v2"
        );
        let requests = server.received_requests().await.unwrap();
        assert!(
            requests[before..]
                .iter()
                .all(|request| request.method == "GET" && request.url.path() == "/directory"),
            "enabling only reads the directory; no CA account request"
        );

        let report = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                auto_accept_new_terms: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let json = report_json(&report);
        assert_eq!(json["terms"]["previous_auto_accept_terms_updates"], true);
        assert_eq!(json["terms"]["auto_accept_terms_updates"], true);
        assert!(report_text(&report).contains("already accepts"));
    }

    #[tokio::test]
    async fn enabling_records_the_updated_terms_url() {
        let (_server, context, signer, transport, _directory, _handles) =
            harness_with_terms(Some("https://ca.example/terms/v2")).await;
        let mut saved = stored(&context, &signer).await;
        saved.accepted_terms_url = Some("https://ca.example/terms/v1".to_owned());
        context.store.save(&saved).await.unwrap();
        let report = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                auto_accept_new_terms: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let record = stored(&context, &signer).await;
        assert_eq!(
            record.accepted_terms_url.as_ref().unwrap().as_str(),
            "https://ca.example/terms/v2"
        );
        assert_eq!(
            report_json(&report)["terms"]["accepted_terms_url"],
            "https://ca.example/terms/v2"
        );
    }

    #[tokio::test]
    async fn enabling_without_advertised_terms_reports_no_url_accepted() {
        let (server, context, signer, transport, _directory, _handles) =
            harness_with_terms(None).await;
        let report = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                auto_accept_new_terms: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let record = stored(&context, &signer).await;
        assert!(record.auto_accept_terms_updates);
        assert_eq!(record.accepted_terms_url, None);
        let json = report_json(&report);
        assert_eq!(
            json["terms"]["advertised_terms_url"],
            serde_json::Value::Null
        );
        assert_eq!(json["terms"]["directory_checked"], true);
        assert_eq!(json["terms"]["auto_accept_terms_updates"], true);
        let text = report_text(&report);
        assert!(text.contains("publishes no terms today"), "{text}");
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method == "GET")
        );
    }

    #[tokio::test]
    async fn enabling_without_terms_retains_the_previously_accepted_url() {
        let (_server, context, signer, transport, _directory, _handles) =
            harness_with_terms(None).await;
        let mut saved = stored(&context, &signer).await;
        saved.accepted_terms_url = Some("https://ca.example/terms/old".to_owned());
        context.store.save(&saved).await.unwrap();
        let report = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                auto_accept_new_terms: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let record = stored(&context, &signer).await;
        assert!(record.auto_accept_terms_updates);
        assert_eq!(
            record.accepted_terms_url.as_ref().unwrap().as_str(),
            "https://ca.example/terms/old"
        );
        let json = report_json(&report);
        assert_eq!(
            json["terms"]["advertised_terms_url"],
            serde_json::Value::Null
        );
        assert_eq!(
            json["terms"]["accepted_terms_url"],
            "https://ca.example/terms/old"
        );
        assert_eq!(json["terms"]["directory_checked"], true);
        let text = report_text(&report);
        assert!(text.contains("any saved URL is retained"), "{text}");
    }

    #[tokio::test]
    async fn enabling_fails_closed_when_the_directory_cannot_confirm_terms() {
        for combined in [false, true] {
            let server = MockServer::start().await;
            let (context, signer, transport, _handles) = account_fixture(&server).await;
            let before = stored(&context, &signer).await;
            let error = update_with_transport(
                crate::commands::account::args::UpdateArgs {
                    clear_contacts: combined,
                    profile: combined.then(|| "shortlived".into()),
                    auto_accept_new_terms: true,
                    yes: true,
                    ..update_args(&context)
                },
                &context,
                transport,
                &CommandContext::new(true),
            )
            .await
            .err()
            .unwrap();
            let (error, _) = crate::common::error::diagnostic(error.as_ref());
            assert!(
                error.contains("could not be read to confirm its current terms"),
                "{error}"
            );
            assert_eq!(stored(&context, &signer).await, before);
            assert!(
                server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .all(|request| request.method == "GET")
            );
        }
    }

    #[tokio::test]
    async fn disabling_terms_delegation_is_local_and_retains_the_accepted_url() {
        let (server, context, signer, transport, _directory, _handles) =
            harness_with_terms(Some("https://ca.example/terms/v1")).await;
        let mut saved = stored(&context, &signer).await;
        saved.auto_accept_terms_updates = true;
        saved.accepted_terms_url = Some("https://ca.example/terms/v1".to_owned());
        context.store.save(&saved).await.unwrap();
        let before = server.received_requests().await.unwrap().len();
        let report = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                clear_auto_accept_new_terms: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport.clone(),
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let record = stored(&context, &signer).await;
        assert!(!record.auto_accept_terms_updates);
        assert_eq!(
            record.accepted_terms_url.as_ref().unwrap().as_str(),
            "https://ca.example/terms/v1"
        );
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            before,
            "disabling never contacts the CA"
        );
        let json = report_json(&report);
        assert_eq!(json["terms"]["auto_accept_terms_updates"], false);
        assert_eq!(json["terms"]["previous_auto_accept_terms_updates"], true);
        assert_eq!(json["terms"]["directory_checked"], false);
        assert_eq!(
            json["terms"]["advertised_terms_url"],
            serde_json::Value::Null
        );
        assert_eq!(json["terms"]["ca_account_update_sent"], false);
        let text = report_text(&report);
        assert!(
            text.contains("no longer accepts") && text.contains("retained"),
            "{text}"
        );

        let report = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                clear_auto_accept_new_terms: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        assert!(report_text(&report).contains("was already set"));
    }

    #[tokio::test]
    async fn terms_delegation_requires_confirmation_in_automation() {
        let (_server, context, signer, transport, _directory, _handles) =
            harness_with_terms(Some("https://ca.example/terms/v1")).await;
        let before = stored(&context, &signer).await;
        let error = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                auto_accept_new_terms: true,
                yes: false,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .err()
        .unwrap();
        let (error, _) = crate::common::error::diagnostic(error.as_ref());
        assert!(
            error.contains("requires confirmation") && error.contains("--yes"),
            "{error}"
        );
        assert_eq!(stored(&context, &signer).await, before);
    }

    #[tokio::test]
    async fn terms_delegation_preserves_metadata_saved_after_its_snapshot() {
        let (_server, context, signer, transport, _directory, _handles) =
            harness_with_terms(Some("https://ca.example/terms/v1")).await;
        let stale = stored(&context, &signer).await;
        let cli = CommandContext::new(true);
        let preflight = update_preflight(&context, transport, false, true, None, &cli)
            .await
            .unwrap();
        let mut fresh = stale.clone();
        fresh.preferred_profile = Some("shortlived".into());
        fresh.server_contacts = Some(vec!["mailto:new@example.com".into()]);
        context.store.save(&fresh).await.unwrap();
        apply_terms_change(&context, &signer, &stale, true, true, &preflight, &cli)
            .await
            .unwrap();
        let record = stored(&context, &signer).await;
        assert!(record.auto_accept_terms_updates);
        assert_eq!(record.preferred_profile.as_deref(), Some("shortlived"));
        assert_eq!(
            record.server_contacts.as_deref(),
            Some(["mailto:new@example.com".to_owned()].as_slice())
        );
    }

    #[tokio::test]
    async fn local_preferences_recheck_account_state_after_preflight() {
        use aster_acme_core::account::DeactivationState;
        for state in [DeactivationState::Pending, DeactivationState::Confirmed] {
            let (_server, context, signer, transport, _directory, _handles) =
                harness_with_terms(Some("https://ca.example/terms/v2")).await;
            let snapshot = stored(&context, &signer).await;
            let cli = CommandContext::new(true);
            let preflight = update_preflight(&context, transport, false, true, None, &cli)
                .await
                .unwrap();
            let mut changed = snapshot.clone();
            changed.deactivation = state;
            context.store.save(&changed).await.unwrap();
            let error =
                apply_terms_change(&context, &signer, &snapshot, true, true, &preflight, &cli)
                    .await
                    .err()
                    .unwrap();
            assert!(matches!(
                error.downcast_ref::<AccountError>(),
                Some(AccountError::DeactivationUncertain | AccountError::AccountNotActive)
            ));
            assert_eq!(stored(&context, &signer).await, changed);
            let error = save_profile_preference(&context, signer.as_ref(), None, None, true, &cli)
                .await
                .err()
                .unwrap();
            assert!(matches!(
                error.downcast_ref::<AccountError>(),
                Some(AccountError::DeactivationUncertain | AccountError::AccountNotActive)
            ));
            assert_eq!(stored(&context, &signer).await, changed);
        }
    }

    #[tokio::test]
    async fn combined_revocation_never_accepts_directory_terms() {
        for advertised in [None, Some("https://ca.example/terms/v2")] {
            for previous in [false, true] {
                for accepted in [None, Some("https://ca.example/terms/v1")] {
                    for clear_profile in [false, true] {
                        for contacts in [false, true] {
                            let (server, context, signer, transport, _directory, _handles) =
                                harness_with_terms(advertised).await;
                            let mut saved = stored(&context, &signer).await;
                            saved.auto_accept_terms_updates = previous;
                            saved.accepted_terms_url = accepted.map(str::to_owned);
                            saved.preferred_profile = Some("classic".into());
                            context.store.save(&saved).await.unwrap();
                            Mock::given(method("POST"))
                                .and(path("/acct/1"))
                                .respond_with(ResponseTemplate::new(200).set_body_json(
                                    serde_json::json!({"status": "valid", "contact": []}),
                                ))
                                .expect(u64::from(contacts))
                                .mount(&server)
                                .await;
                            let report = update_with_transport(
                                crate::commands::account::args::UpdateArgs {
                                    clear_contacts: contacts,
                                    profile: (!clear_profile).then(|| "shortlived".into()),
                                    clear_profile,
                                    clear_auto_accept_new_terms: true,
                                    yes: true,
                                    ..update_args(&context)
                                },
                                &context,
                                transport,
                                &CommandContext::new(true),
                            )
                            .await
                            .unwrap();
                            let after = stored(&context, &signer).await;
                            assert!(!after.auto_accept_terms_updates);
                            assert_eq!(after.accepted_terms_url, saved.accepted_terms_url);
                            assert_eq!(
                                after.preferred_profile.as_deref(),
                                (!clear_profile).then_some("shortlived")
                            );
                            let json = report_json(&report);
                            assert_eq!(json["terms"]["directory_checked"], false);
                            assert_eq!(
                                json["terms"]["advertised_terms_url"],
                                serde_json::Value::Null
                            );
                            assert_eq!(
                                json["terms"]["previous_auto_accept_terms_updates"],
                                previous
                            );
                            assert_eq!(json["contacts"].is_object(), contacts);
                            assert_eq!(
                                json["terms"]["accepted_terms_url"],
                                serde_json::json!(accepted)
                            );
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn profile_save_rejects_a_mismatched_key_algorithm_without_writing() {
        let (_server, context, signer, _transport, _directory, _handles) = harness().await;
        // Simulate metadata replaced after the signer was loaded. Ordinary
        // AccountStore::save rejects algorithm changes, so edit only this fixture.
        let path = context
            .config_path
            .parent()
            .unwrap()
            .join("accounts/work/account.toml");
        let mut document = std::fs::read_to_string(&path)
            .unwrap()
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        document["account"]["key_algorithm"] = toml_edit::value("ecdsa-p384");
        let before = document.to_string();
        std::fs::write(&path, &before).unwrap();
        let error = save_profile_preference(
            &context,
            signer.as_ref(),
            None,
            None,
            true,
            &CommandContext::new(true),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            error.downcast_ref::<AccountError>(),
            Some(AccountError::IdentityMismatch)
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn profile_menu_without_an_advertisement_fails_before_prompting() {
        for advertised in [None, Some(std::collections::BTreeMap::new())] {
            let error = interactive_profile_selection(
                None,
                advertised.as_ref(),
                &CommandContext::new(true),
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("does not advertise certificate profiles")
            );
            assert!(error.to_string().contains("--clear-profile"));
            assert!(!error.is::<crate::common::terminal::Canceled>());
        }
    }

    #[tokio::test]
    async fn contact_discovery_failure_reports_no_submission_and_leaves_record_unchanged() {
        let server = MockServer::start().await;
        let (context, signer, transport, _handles) = account_fixture(&server).await;
        let before = stored(&context, &signer).await;
        let error = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                clear_contacts: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .err()
        .unwrap();
        let (message, _) = crate::common::error::diagnostic(error.as_ref());
        assert!(message.contains("Contacts were not submitted"), "{message}");
        assert_eq!(stored(&context, &signer).await, before);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method != "POST")
        );
    }

    #[tokio::test]
    async fn contact_acceptance_with_failed_local_save_reports_remote_evidence() {
        let (server, context, _signer, transport, _directory, _handles) =
            harness_with_terms(Some("https://ca.example/terms/v2")).await;
        let metadata = context
            .config_path
            .parent()
            .unwrap()
            .join("accounts/work/account.toml");
        let retained = metadata.with_extension("retained.toml");
        let response_metadata = metadata.clone();
        let response_retained = retained.clone();
        Mock::given(method("POST"))
            .and(path("/acct/1"))
            .respond_with(move |_: &wiremock::Request| {
                // The CA received the POST. Make the subsequent real-file save
                // fail without deleting the already persisted contact intent.
                std::fs::rename(&response_metadata, &response_retained).unwrap();
                std::fs::create_dir(&response_metadata).unwrap();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "status":"valid", "contact":["mailto:accepted@example.com"]
                }))
            })
            .expect(1)
            .mount(&server)
            .await;
        let error = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                contact: vec!["accepted@example.com".into()],
                profile: Some("shortlived".into()),
                auto_accept_new_terms: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            error.downcast_ref::<aster_acme::account::ContactUpdateError>(),
            Some(aster_acme::account::ContactUpdateError::Persistence(_))
        ));
        let json: serde_json::Value = serde_json::from_str(
            &crate::common::error::render(
                error.as_ref(),
                crate::common::session::Format::plain(true),
            )
            .unwrap(),
        )
        .unwrap();
        let message = json["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("Contacts were updated at the CA"),
            "{message}"
        );
        assert!(message.contains("local persistence"), "{message}");
        assert!(!message.contains("not changed"), "{message}");
        assert_eq!(
            crate::common::error::exit_status(error.as_ref()),
            crate::common::session::ExitStatus::Failed
        );
        let record: toml::Value =
            toml::from_str(&std::fs::read_to_string(retained).unwrap()).unwrap();
        assert_eq!(
            record["account"]["contacts"].as_array().unwrap()[0].as_str(),
            Some("mailto:accepted@example.com")
        );
        assert!(record["account"].get("preferred_profile").is_none());
        assert_eq!(
            record["account"]["auto_accept_terms_updates"].as_bool(),
            Some(false)
        );
    }

    #[tokio::test]
    async fn rejected_or_uncertain_contact_updates_never_apply_later_scopes() {
        for (status, problem, rejected) in [
            (400, true, true),
            (400, false, false),
            (503, false, false),
            (429, true, false),
        ] {
            let (server, context, signer, transport, _directory, _handles) = harness().await;
            Mock::given(method("POST"))
                .and(path("/acct/1"))
                .respond_with(if problem {
                    ResponseTemplate::new(status)
                        .insert_header("Retry-After", "60")
                        .set_body_json(
                            serde_json::json!({"type":"urn:ietf:params:acme:error:unauthorized"}),
                        )
                } else {
                    ResponseTemplate::new(status)
                })
                .expect(1)
                .mount(&server)
                .await;
            let error = update_with_transport(
                crate::commands::account::args::UpdateArgs {
                    clear_contacts: true,
                    profile: Some("shortlived".into()),
                    clear_auto_accept_new_terms: true,
                    yes: true,
                    ..update_args(&context)
                },
                &context,
                transport,
                &CommandContext::new(true),
            )
            .await
            .err()
            .unwrap();
            let (message, hint) = crate::common::error::diagnostic(error.as_ref());
            assert_eq!(
                message.contains("explicitly rejected"),
                rejected,
                "{message}"
            );
            assert_eq!(
                message.contains("result at the CA is unknown"),
                !rejected,
                "{message}"
            );
            if !rejected {
                assert!(
                    hint.as_ref()
                        .unwrap()
                        .contains("do not automatically replay")
                );
            }
            if status == 429 {
                assert!(hint.unwrap().contains("60 seconds"));
            }
            let saved = stored(&context, &signer).await;
            assert_eq!(saved.preferred_profile, None);
            assert!(!saved.auto_accept_terms_updates);
            assert_eq!(saved.accepted_terms_url, None);
        }
    }

    #[tokio::test]
    async fn terms_preflight_preserves_rate_limit_diagnostics_before_any_mutation() {
        for combined in [false, true] {
            let server = MockServer::start().await;
            let (context, signer, transport, _handles) = account_fixture(&server).await;
            Mock::given(method("GET"))
                .and(path("/directory"))
                .respond_with(
                    ResponseTemplate::new(429)
                        .insert_header("Retry-After", "60")
                        .insert_header("Content-Type", "application/problem+json")
                        .set_body_json(
                            serde_json::json!({"type": "urn:ietf:params:acme:error:rateLimited"}),
                        ),
                )
                .expect(1)
                .mount(&server)
                .await;
            let before = stored(&context, &signer).await;
            let error = update_with_transport(
                crate::commands::account::args::UpdateArgs {
                    clear_contacts: combined,
                    profile: combined.then(|| "shortlived".into()),
                    auto_accept_new_terms: true,
                    yes: true,
                    ..update_args(&context)
                },
                &context,
                transport,
                &CommandContext::new(true),
            )
            .await
            .err()
            .unwrap();
            let (message, hint) = crate::common::error::diagnostic(error.as_ref());
            assert!(
                message.contains("Cannot enable automatic terms updates"),
                "{message}"
            );
            assert!(hint.unwrap().contains("60 seconds"));
            assert_eq!(stored(&context, &signer).await, before);
            assert!(
                server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .all(|r| r.method == "GET")
            );
        }
    }

    #[tokio::test]
    async fn terms_changes_never_overwrite_a_concurrent_delegation_change() {
        for target in [false, true] {
            for snapshot_enabled in [false, true] {
                for saved_enabled in [false, true] {
                    for advertised in [None, Some("terms")] {
                        let (_server, context, signer, transport, _directory, _handles) =
                            harness_with_terms(advertised).await;
                        let mut snapshot = stored(&context, &signer).await;
                        snapshot.auto_accept_terms_updates = snapshot_enabled;
                        snapshot.accepted_terms_url = advertised.map(str::to_owned);
                        context.store.save(&snapshot).await.unwrap();
                        let cli = CommandContext::new(true);
                        let preflight =
                            update_preflight(&context, transport, false, true, None, &cli)
                                .await
                                .unwrap();
                        let mut changed = snapshot.clone();
                        changed.auto_accept_terms_updates = saved_enabled;
                        context.store.save(&changed).await.unwrap();
                        let result = apply_terms_change(
                            &context, &signer, &snapshot, target, true, &preflight, &cli,
                        )
                        .await;
                        if snapshot_enabled == saved_enabled {
                            result.unwrap();
                            assert_eq!(
                                stored(&context, &signer).await.auto_accept_terms_updates,
                                target
                            );
                        } else {
                            let error = result.err().unwrap();
                            assert!(error.to_string().contains("delegation changed"));
                            assert_eq!(stored(&context, &signer).await, changed);
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn clearing_profile_and_revoking_terms_work_offline() {
        let server = MockServer::start().await;
        let (context, signer, transport, _handles) = account_fixture(&server).await;
        let mut before = stored(&context, &signer).await;
        before.preferred_profile = Some("classic".into());
        before.auto_accept_terms_updates = true;
        before.accepted_terms_url = Some("https://ca.example/terms/v1".into());
        context.store.save(&before).await.unwrap();
        let report = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                clear_profile: true,
                clear_auto_accept_new_terms: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let saved = stored(&context, &signer).await;
        assert_eq!(saved.preferred_profile, None);
        assert!(!saved.auto_accept_terms_updates);
        assert_eq!(saved.accepted_terms_url, before.accepted_terms_url);
        assert!(server.received_requests().await.unwrap().is_empty());
        let json = report_json(&report);
        assert_eq!(json["profile"]["previous"], "classic");
        assert_eq!(json["terms"]["directory_checked"], false);
    }

    #[tokio::test]
    async fn terms_change_preserves_conflicting_consent_saved_after_preflight() {
        for (snapshot_url, saved_url, advertised, conflict) in [
            (Some("old"), Some("newer"), Some("advertised"), true),
            (None, Some("newer"), Some("advertised"), true),
            (Some("old"), None, Some("advertised"), true),
            (Some("old"), Some("advertised"), Some("advertised"), false),
            (Some("old"), Some("old"), Some("advertised"), false),
            (Some("old"), Some("newer"), None, true),
            (Some("old"), Some("old"), None, false),
            (None, Some("newer"), None, true),
            (Some("old"), None, None, true),
        ] {
            let (_server, context, signer, transport, _directory, _handles) =
                harness_with_terms(advertised).await;
            let mut snapshot = stored(&context, &signer).await;
            snapshot.accepted_terms_url = snapshot_url.map(str::to_owned);
            context.store.save(&snapshot).await.unwrap();
            let cli = CommandContext::new(true);
            let preflight = update_preflight(&context, transport, false, true, None, &cli)
                .await
                .unwrap();
            let mut fresh = snapshot.clone();
            fresh.accepted_terms_url = saved_url.map(str::to_owned);
            fresh.preferred_profile = Some("classic".into());
            context.store.save(&fresh).await.unwrap();
            let result =
                apply_terms_change(&context, &signer, &snapshot, true, true, &preflight, &cli)
                    .await;
            if conflict {
                let error = result.err().unwrap();
                assert!(error.to_string().contains("Accepted CA terms changed"));
                assert_eq!(stored(&context, &signer).await, fresh);
            } else {
                result.unwrap();
                let saved = stored(&context, &signer).await;
                assert!(saved.auto_accept_terms_updates);
                assert_eq!(
                    saved.accepted_terms_url.as_deref(),
                    advertised.or(saved_url)
                );
                assert_eq!(saved.preferred_profile, fresh.preferred_profile);
            }
        }
    }

    #[tokio::test]
    async fn profile_save_reloads_metadata_after_acquiring_its_lease() {
        let (_server, context, signer, _transport, _directory, _handles) = harness().await;
        let mut fresh = stored(&context, &signer).await;
        fresh.preferred_profile = Some("classic".into());
        fresh.accepted_terms_url = Some("newer consent".into());
        let thumbprint = signer.jwk().unwrap().thumbprint().unwrap();
        let lease = context
            .store
            .lock_account(&context.directory, &thumbprint)
            .await
            .unwrap();
        let cli = CommandContext::new(true);
        let (change, ()) = tokio::join!(
            save_profile_preference(&context, signer.as_ref(), None, None, true, &cli),
            async {
                AccountStore::save(context.store.as_ref(), &fresh, &lease)
                    .await
                    .unwrap();
                drop(lease);
            }
        );
        let change = change.unwrap();
        assert_eq!(change.previous.as_deref(), Some("classic"));
        assert_eq!(change.current, None);
        let saved = stored(&context, &signer).await;
        assert_eq!(saved.preferred_profile, None);
        assert_eq!(saved.accepted_terms_url, fresh.accepted_terms_url);
    }

    #[tokio::test]
    async fn terms_save_failure_preserves_every_preceding_scope() {
        // The directory may advertise arbitrary terms strings. A value larger
        // than the account-file limit deterministically fails the final save.
        let terms = "x".repeat(256 * 1024);
        for contacts in [false, true] {
            for profile in [false, true] {
                let (server, context, signer, transport, _directory, _handles) =
                    harness_with_terms(Some(&terms)).await;
                Mock::given(method("POST"))
                    .and(path("/acct/1"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({"status": "valid", "contact": ["mailto:new@example.com"]}),
                    ))
                    .expect(u64::from(contacts))
                    .mount(&server)
                    .await;
                let error = update_with_transport(
                    crate::commands::account::args::UpdateArgs {
                        contact: if contacts {
                            vec!["new@example.com".into()]
                        } else {
                            vec![]
                        },
                        profile: profile.then(|| "shortlived".into()),
                        auto_accept_new_terms: true,
                        yes: true,
                        ..update_args(&context)
                    },
                    &context,
                    transport,
                    &CommandContext::new(true),
                )
                .await
                .err()
                .unwrap();
                let (message, _) = crate::common::error::diagnostic(error.as_ref());
                assert_eq!(
                    message.contains("Contacts were updated at the CA"),
                    contacts,
                    "{message}"
                );
                assert_eq!(
                    message.contains("the default profile was saved"),
                    profile,
                    "{message}"
                );
                assert!(
                    message.contains("the terms delegation update did not complete"),
                    "{message}"
                );
                assert!(message.contains("size limit"), "{message}");
                assert!(
                    message.contains("Could not confirm that the terms delegation was saved"),
                    "{message}"
                );
                assert!(!message.contains("was not saved"), "{message}");
                assert_eq!(
                    crate::common::error::exit_status(error.as_ref()),
                    crate::common::session::ExitStatus::Failed
                );
                let after = stored(&context, &signer).await;
                assert_eq!(after.contacts.is_empty(), !contacts);
                assert_eq!(
                    after.preferred_profile.as_deref(),
                    profile.then_some("shortlived")
                );
                assert!(!after.auto_accept_terms_updates);
                assert_eq!(after.accepted_terms_url, None);
            }
        }
    }

    #[tokio::test]
    async fn profile_save_failure_keeps_contact_evidence_and_does_not_apply_terms() {
        // Profile names have no protocol length cap. The file limit rejects
        // this advertised name after the contact update has committed.
        let profile = "p".repeat(256 * 1024);
        for contacts in [false, true] {
            let (server, context, signer, transport, _directory, _handles) = harness().await;
            Mock::given(method("GET"))
                .and(path("/directory"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "newNonce": format!("{}/nonce", server.uri()),
                    "newAccount": format!("{}/new-account", server.uri()),
                    "newOrder": format!("{}/orders", server.uri()),
                    "meta": {
                        "profiles": std::collections::BTreeMap::from([(profile.clone(), "description")]),
                        "termsOfService": "https://ca.example/terms/v2"
                    }
                })))
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/acct/1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"status": "valid", "contact": ["mailto:new@example.com"]}),
                ))
                .expect(u64::from(contacts))
                .mount(&server)
                .await;
            let error = update_with_transport(
                crate::commands::account::args::UpdateArgs {
                    contact: if contacts {
                        vec!["new@example.com".into()]
                    } else {
                        vec![]
                    },
                    profile: Some(profile.clone()),
                    auto_accept_new_terms: true,
                    yes: true,
                    ..update_args(&context)
                },
                &context,
                transport,
                &CommandContext::new(true),
            )
            .await
            .err()
            .unwrap();
            let (message, _) = crate::common::error::diagnostic(error.as_ref());
            assert_eq!(
                message.contains("Contacts were updated at the CA"),
                contacts,
                "{message}"
            );
            assert!(
                message.contains("the profile preference update did not complete"),
                "{message}"
            );
            assert!(message.contains("size limit"), "{message}");
            assert!(
                message.contains("Could not confirm that the profile preference was saved"),
                "{message}"
            );
            assert!(!message.contains("was not saved"), "{message}");
            let after = stored(&context, &signer).await;
            assert_eq!(after.contacts.is_empty(), !contacts);
            assert_eq!(after.preferred_profile, None);
            assert!(!after.auto_accept_terms_updates);
            assert_eq!(after.accepted_terms_url, None);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "native PTY account-update fixture"]
    #[expect(
        clippy::too_many_lines,
        reason = "PTY fixture keeps setup, prompts, finish result and durable state assertions together"
    )]
    async fn terminal_update_consent_child() {
        let mode = std::env::var("ASTER_ACCOUNT_TERMS_TEST_MODE").unwrap();
        let (server, context, signer, transport, _directory, _handles) =
            harness_with_terms(Some("https://ca.example/terms/v2")).await;
        let combined = mode.starts_with("update-combined-");
        let menu = mode.starts_with("update-menu-");
        let profile_only = mode == "update-profile-deny";
        let profile_menu = mode == "update-menu-profile";
        let conflict = mode == "update-combined-conflict";
        let revoke = mode.starts_with("update-revoke-");
        let cancelled = mode.ends_with("-deny") || mode.ends_with("-cancel");
        if revoke || conflict {
            let mut saved = stored(&context, &signer).await;
            saved.auto_accept_terms_updates = revoke;
            saved.accepted_terms_url = Some("https://ca.example/terms/v1".into());
            context.store.save(&saved).await.unwrap();
        }
        let before = stored(&context, &signer).await;
        if conflict {
            println!(
                "ACCOUNT_UPDATE_RECORD={}",
                context
                    .config_path
                    .parent()
                    .unwrap()
                    .join("accounts/work/account.toml")
                    .display()
            );
        }
        Mock::given(method("POST"))
            .and(path("/acct/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"status": "valid", "contact": ["mailto:new@example.com"]}),
            ))
            .expect(u64::from(combined))
            .mount(&server)
            .await;
        let mut args = update_args(&context);
        args.network.local.json = false;
        args.auto_accept_new_terms = !menu && !profile_only && !revoke;
        args.clear_auto_accept_new_terms = revoke;
        args.yes = menu || mode == "update-combined-yes";
        if combined {
            args.contact = vec!["new@example.com".into()];
        }
        if combined || profile_only {
            args.profile = Some("shortlived".into());
        }
        let cli = CommandContext::new(false);
        let result = update_with_transport(args, &context, transport, &cli).await;
        let status = match result {
            Err(error) => {
                assert!(cancelled || conflict);
                let (message, _) = crate::common::error::diagnostic(error.as_ref());
                if conflict {
                    assert!(message.contains("Accepted CA terms changed"), "{message}");
                }
                assert_eq!(
                    message.contains("Contacts were updated at the CA"),
                    combined
                );
                assert_eq!(message.contains("the default profile was saved"), combined);
                crate::finish(Err(error), &cli)
            }
            Ok(report) => {
                assert!(!cancelled && !conflict);
                let json = report_json(&report);
                assert_eq!(json["contacts"].is_object(), combined);
                assert_eq!(json["profile"].is_object(), combined || profile_menu);
                if profile_menu {
                    assert!(json["terms"].is_null());
                } else {
                    assert_eq!(
                        json["terms"]["accepted_terms_url"],
                        if revoke {
                            "https://ca.example/terms/v1"
                        } else {
                            "https://ca.example/terms/v2"
                        }
                    );
                }
                crate::finish(
                    Ok(crate::dispatch::CommandReport::Account(Box::new(report))),
                    &cli,
                )
            }
        };
        assert_eq!(
            status,
            if conflict {
                std::process::ExitCode::FAILURE
            } else if cancelled {
                std::process::ExitCode::from(130)
            } else {
                std::process::ExitCode::SUCCESS
            }
        );
        let saved = stored(&context, &signer).await;
        assert_eq!(saved.contacts.is_empty(), !combined);
        assert_eq!(
            saved.preferred_profile.as_deref(),
            (combined || profile_menu).then_some("shortlived")
        );
        assert_eq!(
            saved.auto_accept_terms_updates,
            if revoke {
                cancelled
            } else {
                !cancelled && !conflict && !profile_menu
            }
        );
        assert_eq!(
            saved.accepted_terms_url.as_deref(),
            if conflict {
                Some("https://ca.example/terms/v3")
            } else if revoke {
                Some("https://ca.example/terms/v1")
            } else {
                (!cancelled && !profile_menu).then_some("https://ca.example/terms/v2")
            }
        );
        if cancelled && !combined {
            assert_eq!(saved, before);
        }
        if revoke {
            assert!(server.received_requests().await.unwrap().is_empty());
        }
        if profile_menu {
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].url.path(), "/directory");
        }
        println!("ACCOUNT_UPDATE_DONE {mode}");
    }

    /// Contacts + terms in one invocation: the CA-committed contact evidence
    /// and the local delegation both stay in the report, with exactly one
    /// account POST for the contact update.
    #[tokio::test]
    async fn combined_contacts_and_terms_report_both_outcomes() {
        let (server, context, signer, transport, _directory, _handles) =
            harness_with_terms(Some("https://ca.example/terms/v2")).await;
        Mock::given(method("POST"))
            .and(path("/acct/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "valid",
                "contact": ["mailto:new@example.com"]
            })))
            .mount(&server)
            .await;
        let report = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                contact: vec!["mailto:new@example.com".into()],
                auto_accept_new_terms: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let json = report_json(&report);
        assert!(json["contacts"].is_object(), "{json}");
        assert_eq!(
            json["contacts"]["contacts"],
            serde_json::json!(["mailto:new@example.com"])
        );
        assert_eq!(json["terms"]["auto_accept_terms_updates"], true);
        assert_eq!(
            json["terms"]["accepted_terms_url"],
            "https://ca.example/terms/v2"
        );
        assert_eq!(json["terms"]["ca_account_update_sent"], false);
        let text = report_text(&report);
        assert!(
            text.contains("Updated contacts for") && text.contains("now accepts"),
            "{text}"
        );
        assert!(
            text.contains("the terms delegation itself sent no CA account request"),
            "{text}"
        );
        assert!(!text.contains("no CA account request was sent"), "{text}");
        let record = stored(&context, &signer).await;
        assert_eq!(record.contacts, ["mailto:new@example.com"]);
        assert!(record.auto_accept_terms_updates);
        let posts = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method == "POST")
            .count();
        assert_eq!(posts, 1, "the contact update is the only CA account POST");
    }

    #[tokio::test]
    async fn all_three_scopes_apply_and_report_together() {
        let (server, context, signer, transport, _directory, _handles) =
            harness_with_terms(Some("https://ca.example/terms/v3")).await;
        Mock::given(method("POST"))
            .and(path("/acct/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "valid",
                "contact": ["mailto:new@example.com"]
            })))
            .mount(&server)
            .await;
        let report = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                contact: vec!["mailto:new@example.com".into()],
                profile: Some("shortlived".into()),
                auto_accept_new_terms: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let json = report_json(&report);
        assert!(json["contacts"].is_object(), "{json}");
        assert_eq!(json["profile"]["current"], "shortlived");
        assert_eq!(json["terms"]["auto_accept_terms_updates"], true);
        assert_eq!(
            json["terms"]["accepted_terms_url"],
            "https://ca.example/terms/v3"
        );
        let record = stored(&context, &signer).await;
        assert_eq!(record.contacts, ["mailto:new@example.com"]);
        assert_eq!(record.preferred_profile.as_deref(), Some("shortlived"));
        assert!(record.auto_accept_terms_updates);
        assert_eq!(
            record.accepted_terms_url.as_ref().unwrap().as_str(),
            "https://ca.example/terms/v3"
        );
    }

    /// The directory-backed preflight runs before every mutation: an
    /// unadvertised profile fails the whole invocation, leaving the terms
    /// delegation and the CA account untouched.
    #[tokio::test]
    async fn an_unadvertised_profile_blocks_the_entire_update_before_any_mutation() {
        let (server, context, signer, transport, _directory, _handles) =
            harness_with_terms(Some("https://ca.example/terms/v2")).await;
        let before = stored(&context, &signer).await;
        let error = update_with_transport(
            crate::commands::account::args::UpdateArgs {
                contact: vec!["mailto:new@example.com".into()],
                profile: Some("premium".into()),
                auto_accept_new_terms: true,
                yes: true,
                ..update_args(&context)
            },
            &context,
            transport,
            &CommandContext::new(true),
        )
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("premium"), "{error}");
        assert_eq!(stored(&context, &signer).await, before);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method == "GET"),
            "only directory reads happened; no account POST reached the CA"
        );
    }

    #[tokio::test]
    async fn update_rejects_terms_delegation_for_an_unregistered_account_before_http() {
        let server = MockServer::start().await;
        let (context, signer, transport, _handles) = account_fixture(&server).await;
        let mut saved = stored(&context, &signer).await;
        saved.state = aster_acme_core::account::AccountRecordState::RegistrationPending;
        context.store.save(&saved).await.unwrap();
        let args = crate::commands::account::args::UpdateArgs {
            network: crate::commands::account::args::NetworkArgs {
                identity: crate::commands::account::args::NameArgs::default(),
                ca: crate::commands::account::args::CaArgs::default(),
                http: HttpArgs::default(),
                local: crate::common::args::LocalArgs {
                    data_dir: None,
                    json: true,
                },
            },
            auto_accept_new_terms: true,
            yes: true,
            ..Default::default()
        };
        let error = update_with_transport(args, &context, transport, &CommandContext::new(true))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("no registered account exists"), "{error}");
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "the account gate precedes discovery"
        );
    }
}
