//! Provider operations and host-side effects.
use crate::commands::provider::{
    args::{AddArgs, ProviderCommand, UpdateArgs},
    interaction,
    report::{CleanupView, ProviderReport, view},
    runtime,
};
use crate::common::{context::CliSettings, error::CliResult, output::safe, terminal};
use aster_acme::storage::issuance::IssueStore;
use std::time::Duration;

pub(crate) async fn execute(
    command: ProviderCommand,
    cli: &crate::common::context::CommandContext,
) -> CliResult<ProviderReport> {
    let local = command.local().clone();
    let interactive = terminal::interactive(local.json);
    let settings = CliSettings::load(&local.into()).await?;
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        settings.data_dir.clone(),
        Duration::from_secs(5),
    );
    match command {
        ProviderCommand::Backends(_) => Ok(ProviderReport {
            backends: runtime::registry()?.descriptors(),
            operation: "backends",
            profiles: Vec::new(),
            removed: None,
            cleanup: Vec::new(),
            cancelled: false,
            incomplete: false,
        }),
        ProviderCommand::Add(args) => add_profile(args, &store, interactive, cli).await,
        ProviderCommand::List(_) => {
            let names = store.names().await?;
            let mut profiles = Vec::with_capacity(names.len());
            for name in names {
                profiles.push(view(
                    name.clone(),
                    store.path(&name)?,
                    store.get(name).await?,
                ));
            }
            Ok(ProviderReport {
                backends: Vec::new(),
                operation: "listed",
                profiles,
                removed: None,
                cleanup: Vec::new(),
                cancelled: false,
                incomplete: false,
            })
        }
        ProviderCommand::Show(args) => {
            let name = target(args.name, &store, &cli.output, "show", interactive).await?;
            Ok(ProviderReport {
                backends: Vec::new(),
                operation: "shown",
                profiles: vec![view(
                    name.clone(),
                    store.path(&name)?,
                    store.get(name).await?,
                )],
                removed: None,
                cleanup: Vec::new(),
                cancelled: false,
                incomplete: false,
            })
        }
        ProviderCommand::Update(args) => update_profile(args, &store, interactive, cli).await,
        ProviderCommand::Cleanup(args) => {
            let name = target(args.name, &store, &cli.output, "cleanup", interactive).await?;
            store.get(name.clone()).await?;
            cleanup_profile(&name, &settings.data_dir, &store, cli).await
        }
        ProviderCommand::Remove(args) => {
            let name = target(args.name, &store, &cli.output, "remove", interactive).await?;
            remove_profile(name, args.yes, &store, cli).await
        }
    }
}

async fn add_profile(
    mut args: AddArgs,
    store: &aster_acme_cli_storage::provider::ProviderProfileStore,
    interactive: bool,
    cli: &crate::common::context::CommandContext,
) -> CliResult<ProviderReport> {
    let names = store.names().await?;
    interaction::complete_add(
        &mut args,
        &names,
        interactive,
        &mut interaction::TerminalPrompts(&cli.output),
    )?;
    let name = args.name.ok_or("Specify a DNS provider profile name.")?;
    let backend_id = args
        .backend
        .unwrap_or_else(|| aster_acme_dns::backend::ADPP_BACKEND_ID.into());
    let descriptor = runtime::registry()?.require(&backend_id)?.descriptor();
    let mut profile = if descriptor.executable {
        aster_acme_cli_storage::provider::ProviderProfile::new(
            args.exec.ok_or("Specify --exec <PATH>.")?,
            args.args,
            args.allowed_zones,
        )?
    } else {
        if args.exec.is_some() || !args.args.is_empty() {
            return Err("This backend does not accept --exec or --arg.".into());
        }
        aster_acme_cli_storage::provider::ProviderProfile::builtin(
            backend_id.clone(),
            args.custom,
            args.allowed_zones,
        )?
    };
    if let Some(ttl) = args.ttl_seconds {
        profile.ttl_seconds = ttl;
    }
    profile.backend_id = backend_id;
    profile.backend_config_version = descriptor.config_version;
    if let Some(path) = args.settings_file {
        profile.provider_custom = runtime::read_settings(&path).await?;
    }
    profile.validate()?;
    runtime::registry()?
        .require(&profile.backend_id)?
        .validate(&(&profile).into())?;
    store.add(name.clone(), profile.clone()).await?;
    Ok(ProviderReport {
        backends: Vec::new(),
        operation: "added",
        profiles: vec![view(name.clone(), store.path(&name)?, profile)],
        removed: None,
        cleanup: Vec::new(),
        cancelled: false,
        incomplete: false,
    })
}

async fn update_profile(
    args: UpdateArgs,
    store: &aster_acme_cli_storage::provider::ProviderProfileStore,
    interactive: bool,
    cli: &crate::common::context::CommandContext,
) -> CliResult<ProviderReport> {
    let explicit = args.ttl_seconds.is_some()
        || args.settings_file.is_some()
        || args.exec.is_some()
        || args.args.is_some()
        || args.clear_args
        || args.allowed_zones.is_some()
        || args.clear_zones;
    if !explicit && !interactive {
        return Err("Specify provider update <NAME> with explicit changes; the edit menu is only available on a terminal.".into());
    }
    if let Some(executable) = &args.exec {
        validate_executable(executable)?;
    }
    let name = target(args.name.clone(), store, &cli.output, "update", interactive).await?;
    let custom = match args.settings_file.as_deref() {
        Some(path) => Some(runtime::read_settings(path).await?),
        None => None,
    };
    let registry = runtime::registry()?;
    let profile = if explicit {
        store
            .edit(name.clone(), move |profile| {
                if let Some(ttl) = args.ttl_seconds {
                    profile.ttl_seconds = ttl;
                }
                if let Some(executable) = args.exec {
                    profile.executable = executable;
                }
                if let Some(values) = args.args {
                    profile.args = values;
                } else if args.clear_args {
                    profile.args.clear();
                }
                if let Some(zones) = args.allowed_zones {
                    profile.allowed_zones = zones;
                } else if args.clear_zones {
                    profile.allowed_zones.clear();
                }
                if let Some(custom) = custom {
                    profile.provider_custom = custom;
                }
                profile.validate()?;
                registry
                    .require(&profile.backend_id)
                    .map_err(std::io::Error::other)?
                    .validate(&(&*profile).into())
                    .map_err(std::io::Error::other)
            })
            .await?
    } else {
        let expected = store.get(name.clone()).await?;
        let edited = interaction::update::edit(
            &name,
            &store.path(&name)?,
            &expected,
            &mut interaction::TerminalPrompts(&cli.output),
        )?;
        save_interactive_edit(store, name.clone(), expected, edited).await?
    };
    Ok(ProviderReport {
        backends: Vec::new(),
        operation: "updated",
        profiles: vec![view(name.clone(), store.path(&name)?, profile)],
        removed: None,
        cleanup: Vec::new(),
        cancelled: false,
        incomplete: false,
    })
}

pub(super) async fn save_interactive_edit(
    store: &aster_acme_cli_storage::provider::ProviderProfileStore,
    name: String,
    expected: aster_acme_cli_storage::provider::ProviderProfile,
    edited: aster_acme_cli_storage::provider::ProviderProfile,
) -> CliResult<aster_acme_cli_storage::provider::ProviderProfile> {
    Ok(store.edit(name, move |profile| {
        if profile != &expected {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "Provider profile changed while editing; inspect it and retry instead of overwriting concurrent changes."));
        }
        *profile = edited;
        Ok(())
    }).await?)
}

async fn remove_profile(
    name: String,
    yes: bool,
    store: &aster_acme_cli_storage::provider::ProviderProfileStore,
    cli: &crate::common::context::CommandContext,
) -> CliResult<ProviderReport> {
    let profile = store.get(name.clone()).await?;
    terminal::confirm_action(
        &format!(
            "Remove provider profile '{}' using backend {}? Custom values are sensitive and will be deleted.",
            name,
            safe(&profile.backend_id)
        ),
        "Remove this provider profile?",
        yes,
        &cli.output,
    )?;
    store.remove(name.clone()).await?;
    Ok(ProviderReport {
        backends: Vec::new(),
        operation: "removed",
        profiles: Vec::new(),
        removed: Some(name),
        cleanup: Vec::new(),
        cancelled: false,
        incomplete: false,
    })
}

async fn cleanup_profile(
    name: &str,
    root: &std::path::Path,
    store: &aster_acme_cli_storage::provider::ProviderProfileStore,
    cli: &crate::common::context::CommandContext,
) -> CliResult<ProviderReport> {
    let _lease = store.lease().await?;
    let issues = aster_acme_cli_storage::issuance::CliIssueStore::new(
        root.to_path_buf(),
        Duration::from_secs(5),
    );
    let records = issues
        .query(aster_acme::storage::query::IssueQuery::default())
        .await?;
    let cancellation = tokio_util::sync::CancellationToken::new();
    let _signal = crate::common::signal::InterruptGuard::new(cancellation.clone());
    let execution = aster_acme::solver::ExecutionContext {
        cancellation,
        deadline: std::time::Instant::now() + Duration::from_secs(300),
    };
    let mut cleanup = Vec::new();
    let mut interrupted = false;
    let mut incomplete = false;
    for record in records.into_iter().filter(|record| {
        aster_acme_cli_storage::issuance::ProviderSolverId::from_saved_id(&record.solver_id)
            == aster_acme_cli_storage::issuance::ProviderSolverId::Current
            && record
                .solver_config
                .get("provider_instance_id")
                .and_then(serde_json::Value::as_str)
                == Some(name)
            && record
                .authorizations
                .iter()
                .any(|auth| auth.cleanup_pending)
            && record.publication_cleanup_eligible(time::OffsetDateTime::now_utc())
    }) {
        if execution.check().is_err() {
            interrupted = true;
            incomplete = true;
            break;
        }
        let session = issues
            .open_observation(&record.name, &record.operation_id)
            .await?;
        let result = crate::commands::cert::validation::provider::cleanup_provider(
            root,
            session.as_ref(),
            cli.output.clone(),
            &execution,
            cli.dns_http.clone(),
        )
        .await;
        cleanup.push(CleanupView {
            certificate: record.name.as_str().into(),
            operation: record.operation_id,
            completed: result.as_ref().is_ok_and(|record| {
                record
                    .authorizations
                    .iter()
                    .all(|auth| !auth.cleanup_pending)
            }),
            error: result.err().map(|error| error.to_string()),
        });
    }
    Ok(ProviderReport {
        backends: Vec::new(),
        operation: "cleanup",
        profiles: Vec::new(),
        removed: None,
        cleanup,
        cancelled: interrupted
            || execution.cancellation.is_cancelled()
            || execution.deadline <= std::time::Instant::now(),
        incomplete,
    })
}

/// Supply the same stable profile argument for issuance and offline inspection.
pub(crate) async fn select(
    root: &std::path::Path,
    output: &crate::common::session::OutputSession,
) -> CliResult<String> {
    let names = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        root.to_path_buf(),
        Duration::from_secs(5),
    )
    .names()
    .await?;
    choose(&names, output)
}

async fn target(
    name: Option<String>,
    store: &aster_acme_cli_storage::provider::ProviderProfileStore,
    output: &crate::common::session::OutputSession,
    action: &str,
    interactive: bool,
) -> CliResult<String> {
    if let Some(name) = name {
        return Ok(name);
    }
    if !interactive {
        return Err(format!("Specify a DNS provider profile: provider {action} <NAME>.").into());
    }
    choose(&store.names().await?, output)
}

fn choose(names: &[String], output: &crate::common::session::OutputSession) -> CliResult<String> {
    if names.is_empty() {
        return Err("No DNS provider profiles configured; create one with provider add <NAME> --exec <PATH>.".into());
    }
    let index = terminal::select_index("DNS provider profile:", names, 0, output)?;
    names
        .get(index)
        .cloned()
        .ok_or_else(|| "Invalid DNS provider profile selection.".into())
}

pub(super) fn validate_executable(path: &std::path::Path) -> CliResult<()> {
    if !path.is_absolute() || !path.is_file() {
        return Err("Provider executable must be an existing absolute file path.".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o111 == 0 {
            return Err("Provider executable has no execute permission.".into());
        }
    }
    Ok(())
}
