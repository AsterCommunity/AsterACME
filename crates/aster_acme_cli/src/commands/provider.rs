//! Manage named DNS backend profiles and their private configuration.

use crate::common::output::{MessageKind, Style, field, safe, styled};
use crate::common::{
    args::{LocalArgs, parse_account_name},
    context::CliSettings,
    error::CliResult,
    session::Format,
    terminal,
};
use aster_acme::storage::issuance::IssueStore;
use clap::{Args, Subcommand};
use serde::Serialize;
use std::{path::PathBuf, time::Duration};

mod interaction;
pub(crate) mod runtime;

#[derive(Subcommand)]
pub(crate) enum ProviderCommand {
    /// List backend types available in this build and their configuration fields.
    Backends(LocalArgs),
    /// Register a named DNS provider profile.
    Add(AddArgs),
    /// List configured provider profile names and safe metadata.
    List(LocalArgs),
    /// Show one provider profile with all custom values redacted.
    Show(ShowArgs),
    /// Retry owned DNS cleanup for terminal requests using this provider profile.
    Cleanup(ShowArgs),
    /// Update configuration for a DNS provider profile.
    Update(UpdateArgs),
    /// Remove a provider profile that no retained certificate references.
    Remove(RemoveArgs),
}

impl ProviderCommand {
    pub(crate) fn local(&self) -> &LocalArgs {
        match self {
            Self::Add(args) => &args.local,
            Self::List(local) | Self::Backends(local) => local,
            Self::Show(args) | Self::Cleanup(args) => &args.local,
            Self::Update(args) => &args.local,
            Self::Remove(args) => &args.local,
        }
    }
}

#[derive(Args)]
pub(crate) struct AddArgs {
    /// Stable provider profile name; prompt when omitted on a terminal.
    #[arg(value_parser = parse_account_name)]
    name: Option<String>,
    /// Absolute executable path; no shell is used.
    #[arg(long, value_name = "PATH")]
    exec: Option<PathBuf>,
    /// Backend type ID; defaults to ADPP when --exec is supplied.
    #[arg(long, value_name = "ID")]
    backend: Option<String>,
    #[arg(skip)]
    custom: serde_json::Map<String, serde_json::Value>,
    /// Private TOML file containing backend-owned configuration values.
    #[arg(long, value_name = "PATH")]
    settings_file: Option<PathBuf>,
    /// Exact argument; repeat to build argv. Never put secrets here.
    #[arg(long = "arg", value_name = "VALUE")]
    args: Vec<String>,
    /// Optional allowed DNS zone suffix; repeat to restrict, omit to allow all zones.
    #[arg(long = "allow-zone", value_name = "DOMAIN")]
    allowed_zones: Vec<String>,
    #[command(flatten)]
    local: LocalArgs,
}

#[derive(Args)]
pub(crate) struct ShowArgs {
    /// Stable provider profile name; choose interactively when omitted.
    #[arg(value_parser = parse_account_name)]
    name: Option<String>,
    #[command(flatten)]
    local: LocalArgs,
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("provider_changes").args(["exec", "args", "clear_args", "allowed_zones", "clear_zones", "settings_file"]).multiple(true)))]
pub(crate) struct UpdateArgs {
    /// Stable provider profile name; choose interactively when omitted.
    #[arg(value_parser = parse_account_name)]
    name: Option<String>,
    /// Replace the executable path.
    #[arg(long, value_name = "PATH")]
    exec: Option<PathBuf>,
    /// Replace argv with the supplied exact arguments.
    #[arg(long = "arg", value_name = "VALUE", num_args = 1.., conflicts_with = "clear_args")]
    args: Option<Vec<String>>,
    /// Remove all saved argv values.
    #[arg(long, conflicts_with = "args")]
    clear_args: bool,
    /// Replace the allowed zone suffix set.
    #[arg(long = "allow-zone", value_name = "DOMAIN", num_args = 1.., conflicts_with = "clear_zones")]
    allowed_zones: Option<Vec<String>>,
    /// Clear zone restrictions and allow all valid publication owners.
    #[arg(long, conflicts_with = "allowed_zones")]
    clear_zones: bool,
    /// Replace backend-owned configuration from a private TOML file.
    #[arg(long, value_name = "PATH")]
    settings_file: Option<PathBuf>,
    #[command(flatten)]
    local: LocalArgs,
}

#[derive(Args)]
pub(crate) struct RemoveArgs {
    /// Stable provider profile name; choose interactively when omitted.
    #[arg(value_parser = parse_account_name)]
    name: Option<String>,
    /// Confirm removal without prompting.
    #[arg(short = 'y', long)]
    yes: bool,
    #[command(flatten)]
    local: LocalArgs,
}

#[derive(Debug, Clone, Serialize)]
struct ProfileView {
    backend_id: String,
    backend_config_version: u32,
    name: String,
    profile_path: PathBuf,
    executable: PathBuf,
    args: Vec<String>,
    allowed_zones: Vec<String>,
    profile_version: u32,
    custom_values: String,
}

#[derive(Debug, Clone, Serialize)]
struct CleanupView {
    certificate: String,
    operation: String,
    completed: bool,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProviderReport {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    backends: Vec<aster_acme_dns::backend::BackendDescriptor>,
    operation: &'static str,
    profiles: Vec<ProfileView>,
    removed: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cleanup: Vec<CleanupView>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    cancelled: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    incomplete: bool,
}

impl ProviderReport {
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    pub(crate) fn has_failures(&self) -> bool {
        self.incomplete || self.cleanup.iter().any(|item| !item.completed)
    }
}

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
    let explicit = args.settings_file.is_some()
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

async fn save_interactive_edit(
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
        record.solver_id == "dns_provider"
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
        let result = crate::commands::cert::validation::cleanup_provider(
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

fn validate_executable(path: &std::path::Path) -> CliResult<()> {
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

fn view(
    name: String,
    profile_path: PathBuf,
    profile: aster_acme_cli_storage::provider::ProviderProfile,
) -> ProfileView {
    ProfileView {
        backend_id: profile.backend_id,
        backend_config_version: profile.backend_config_version,
        name,
        profile_path,
        executable: profile.executable,
        args: profile.args,
        allowed_zones: profile.allowed_zones,
        profile_version: profile.provider_profile_version,
        custom_values: format!("<redacted: {} value(s)>", profile.provider_custom.len()),
    }
}

pub(crate) fn render(report: &ProviderReport, format: Format) -> CliResult<String> {
    if format.json {
        return Ok(serde_json::to_string_pretty(report)?);
    }
    if let Some(name) = &report.removed {
        return Ok(format!(
            "{} Removed provider profile {}.",
            MessageKind::Success.badge(format.color),
            safe(name)
        ));
    }
    if report.operation == "cleanup" {
        return Ok(render_cleanup(report, format.color));
    }
    if report.operation == "backends" {
        let mut rows = vec![["BACKEND ID".into(), "NAME".into(), "CONFIGURATION".into()]];
        for backend in &report.backends {
            rows.push([
                backend.id.into(),
                backend.label.into(),
                backend
                    .fields
                    .iter()
                    .map(|field| field.name)
                    .collect::<Vec<_>>()
                    .join(", "),
            ]);
        }
        return Ok(
            crate::common::table::listing(&rows, format.color, |_, _| Style::Plain).join("\n"),
        );
    }
    if report.profiles.is_empty() {
        return Ok("No DNS provider profiles configured.".into());
    }
    if report.operation == "listed" {
        let mut rows = vec![["NAME".into(), "BACKEND".into(), "ALLOWED ZONES".into()]];
        for profile in &report.profiles {
            rows.push([
                profile.name.clone(),
                profile.backend_id.clone(),
                if profile.allowed_zones.is_empty() {
                    "all (unrestricted)".into()
                } else {
                    profile.allowed_zones.join(", ")
                },
            ]);
        }
        return Ok(
            crate::common::table::listing(&rows, format.color, |_, column| {
                if column == 0 {
                    Style::Green
                } else {
                    Style::Plain
                }
            })
            .join("\n"),
        );
    }
    let mut lines = vec![styled(
        &match report.operation {
            "added" => "Added DNS provider profile.".to_owned(),
            "updated" => "Updated DNS provider profile.".to_owned(),
            "shown" => "DNS provider profile:".to_owned(),
            _ => "DNS provider profiles:".to_owned(),
        },
        Style::BoldCyan,
        format.color,
    )];
    for profile in &report.profiles {
        lines.extend(detail_lines(profile, format.color)?);
    }
    Ok(lines.join("\n").trim_end().to_owned())
}

fn detail_lines(profile: &ProfileView, color: bool) -> CliResult<Vec<String>> {
    let mut lines = Vec::new();
    lines.push(field(
        "Name:",
        &styled(&safe(&profile.name), Style::BoldGreen, color),
        color,
    ));
    lines.push(field("Backend:", &safe(&profile.backend_id), color));
    lines.push(field(
        "Backend config version:",
        &profile.backend_config_version.to_string(),
        color,
    ));
    if !profile.executable.as_os_str().is_empty() {
        lines.push(field(
            "Executable:",
            &safe(&profile.executable.to_string_lossy()),
            color,
        ));
    }
    lines.push(field(
        "Profile file:",
        &safe(&profile.profile_path.to_string_lossy()),
        color,
    ));
    lines.push(field(
        "Allowed zones:",
        &if profile.allowed_zones.is_empty() {
            "all (unrestricted)".to_owned()
        } else {
            safe(&profile.allowed_zones.join(", "))
        },
        color,
    ));
    lines.push(field(
        "Profile version:",
        &profile.profile_version.to_string(),
        color,
    ));
    lines.push(field("Custom values:", &profile.custom_values, color));
    if !profile.args.is_empty() {
        lines.push(field(
            "Arguments:",
            &safe(&serde_json::to_string(&profile.args)?),
            color,
        ));
    }
    Ok(lines)
}

fn render_cleanup(report: &ProviderReport, color: bool) -> String {
    if report.cleanup.is_empty() {
        return if report.incomplete {
            "Provider cleanup deadline expired before all matching requests were examined.".into()
        } else {
            "No terminal DNS publication cleanup is pending for this provider.".into()
        };
    }
    let mut lines = report
        .cleanup
        .iter()
        .map(|item| {
            format!(
                "{} {}: {}{}",
                if item.completed {
                    MessageKind::Success
                } else {
                    MessageKind::Warning
                }
                .badge(color),
                safe(&item.certificate),
                if item.completed {
                    "cleanup complete"
                } else {
                    "cleanup pending"
                },
                item.error
                    .as_ref()
                    .map_or(String::new(), |error| format!(": {}", safe(error)))
            )
        })
        .collect::<Vec<_>>();
    if report.incomplete {
        lines.push(format!(
            "{} Provider cleanup did not examine all matching requests before its deadline.",
            MessageKind::Error.badge(color)
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use crate::{
        app::{Args, Command},
        commands::provider::{CleanupView, ProviderReport, execute, render},
        common::{context::CommandContext, session::Format},
    };
    use clap::Parser;
    fn command(words: &[&str]) -> crate::commands::provider::ProviderCommand {
        let args = Args::try_parse_from(
            ["aster-acme", "provider"]
                .into_iter()
                .chain(words.iter().copied()),
        )
        .unwrap();
        let Command::Provider { command } = args.command else {
            panic!("not provider command");
        };
        command
    }

    #[tokio::test]
    async fn show_requires_explicit_targets_in_automation_and_empty_selection_is_actionable() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_str().unwrap();
        for action in ["show", "cleanup", "remove"] {
            let error = execute(
                command(&[action, "--data-dir", root, "--json"]),
                &CommandContext::new(true),
            )
            .await
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("provider {action} <NAME>"))
            );
        }
        let error = execute(
            command(&["remove", "--yes", "--json", "--data-dir", root]),
            &CommandContext::new(true),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("provider remove <NAME>"));
        for words in [
            vec!["add", "--json", "--data-dir", root],
            vec!["add", "new", "--json", "--data-dir", root],
        ] {
            assert!(
                execute(command(&words), &CommandContext::new(true))
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("provider add <NAME> with --backend <ID> or --exec <PATH>")
            );
        }
        for words in [
            vec!["update", "--json", "--data-dir", root],
            vec!["update", "prod", "--json", "--data-dir", root],
            vec!["update", "--clear-args", "--json", "--data-dir", root],
        ] {
            assert!(
                execute(command(&words), &CommandContext::new(true))
                    .await
                    .is_err()
            );
        }
        let error =
            crate::commands::provider::select(temp.path(), &CommandContext::new(false).output)
                .await
                .unwrap_err();
        assert!(error.to_string().contains("provider add"));
        assert!(!temp.path().join("providers").exists());
        assert!(!temp.path().join("certs").exists());
        assert!(
            execute(
                command(&["show", "missing", "--data-dir", root, "--json"]),
                &CommandContext::new(true)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn interactive_update_commits_once_and_refuses_concurrent_profile_changes() {
        let temp = tempfile::tempdir().unwrap();
        let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
            temp.path().into(),
            std::time::Duration::from_secs(1),
        );
        let original = aster_acme_cli_storage::provider::ProviderProfile::new(
            std::env::current_exe().unwrap(),
            vec!["old".into()],
            Vec::new(),
        )
        .unwrap();
        store.add("prod".into(), original.clone()).await.unwrap();
        let mut edited = original.clone();
        edited.args = vec!["edited".into()];
        let saved = crate::commands::provider::save_interactive_edit(
            &store,
            "prod".into(),
            original.clone(),
            edited.clone(),
        )
        .await
        .unwrap();
        assert_eq!(saved, edited);
        let mut concurrent = edited.clone();
        concurrent
            .provider_custom
            .insert("token".into(), serde_json::json!("concurrent-secret"));
        store
            .update("prod".into(), concurrent.clone())
            .await
            .unwrap();
        let error = crate::commands::provider::save_interactive_edit(
            &store,
            "prod".into(),
            edited,
            original,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("changed while editing"));
        assert!(!error.to_string().contains("concurrent-secret"));
        assert_eq!(store.get("prod".into()).await.unwrap(), concurrent);
    }

    #[test]
    fn profile_and_cleanup_reports_escape_untrusted_fields_and_keep_machine_output_pure() {
        let mut report = ProviderReport {
            backends: Vec::new(),
            operation: "shown",
            profiles: vec![crate::commands::provider::ProfileView {
                backend_id: aster_acme_dns::backend::ADPP_BACKEND_ID.into(),
                backend_config_version: 1,
                name: "safe-name".into(),
                profile_path: "path\nfile.toml".into(),
                executable: "bad\x1b[2J".into(),
                args: vec!["line\nnext".into()],
                allowed_zones: vec!["zone\r.example".into()],
                profile_version: 1,
                custom_values: "<redacted>".into(),
            }],
            removed: None,
            cleanup: Vec::new(),
            cancelled: false,
            incomplete: false,
        };
        for operation in ["shown", "listed"] {
            report.operation = operation;
            let text = render(&report, Format::plain(false)).unwrap();
            assert!(!text.contains('\x1b'));
            assert!(!text.contains('\r'));
            if operation == "shown" {
                assert!(text.contains("bad\\u{1b}[2J"));
            }
            assert!(text.contains("zone\\r.example"));
            let json = render(
                &report,
                Format {
                    json: true,
                    color: true,
                },
            )
            .unwrap();
            assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
            assert!(!json.contains('\x1b'));
        }
        report.operation = "cleanup";
        report.cleanup = vec![CleanupView {
            certificate: "web\x1b[2J".into(),
            operation: "op".into(),
            completed: false,
            error: Some("failure\nnext".into()),
        }];
        let text = render(&report, Format::plain(false)).unwrap();
        assert!(!text.contains('\x1b'));
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("cleanup pending"));
        assert!(text.contains("failure\\nnext"));
        assert!(
            render(
                &report,
                Format {
                    json: false,
                    color: true
                }
            )
            .unwrap()
            .starts_with("\x1b[33m[WARN]")
        );
        report.cleanup[0].completed = true;
        report.cleanup[0].error = None;
        let complete = render(&report, Format::plain(false)).unwrap();
        assert!(complete.contains("cleanup complete"));
        assert!(!complete.contains("cleanup pending"));
        report.cleanup.clear();
        assert!(
            render(&report, Format::plain(false))
                .unwrap()
                .contains("No terminal DNS publication cleanup is pending")
        );
        report.incomplete = true;
        assert!(
            render(&report, Format::plain(false))
                .unwrap()
                .contains("deadline expired")
        );
        report.operation = "listed";
        report.profiles.clear();
        assert!(
            render(&report, Format::plain(false))
                .unwrap()
                .contains("No DNS provider profiles configured")
        );
        report.removed = Some("prod\nunsafe".into());
        report.operation = "removed";
        let removed = render(
            &report,
            Format {
                json: false,
                color: true,
            },
        )
        .unwrap();
        assert!(removed.contains("Removed provider profile prod\\nunsafe"));
    }

    #[tokio::test]
    async fn list_is_a_sorted_table_and_show_exposes_the_profile_file_with_shared_styles() {
        let temp = tempfile::tempdir().unwrap();
        let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
            temp.path().into(),
            std::time::Duration::from_secs(1),
        );
        for name in ["long-profile", "a"] {
            let mut profile = aster_acme_cli_storage::provider::ProviderProfile::new(
                std::env::current_exe().unwrap(),
                vec!["arg\\n".into()],
                Vec::new(),
            )
            .unwrap();
            profile
                .provider_custom
                .insert("token".into(), serde_json::json!("secret-sentinel"));
            store.add(name.into(), profile).await.unwrap();
        }
        let root = temp.path().to_str().unwrap();
        let report = execute(
            command(&["list", "--data-dir", root, "--json"]),
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let plain = render(&report, Format::plain(false)).unwrap();
        let lines = plain.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("NAME"));
        assert!(lines[1].starts_with("a "));
        assert!(lines[2].starts_with("long-profile "));
        assert_eq!(
            lines[0].find("EXECUTABLE"),
            lines[1].find(
                &std::env::current_exe()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            )
        );
        assert!(!plain.contains("Arguments:"));
        assert!(!plain.contains('\x1b'));
        assert!(
            render(
                &report,
                Format {
                    json: false,
                    color: true
                }
            )
            .unwrap()
            .contains("\x1b[1;36mNAME")
        );
        let report = execute(
            command(&["show", "a", "--data-dir", root, "--json"]),
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let plain = render(&report, Format::plain(false)).unwrap();
        let expected = store.path("a").unwrap();
        assert!(plain.contains(&expected.to_string_lossy().to_string()));
        assert!(plain.contains("Profile file:"));
        let colored = render(
            &report,
            Format {
                json: false,
                color: true,
            },
        )
        .unwrap();
        assert!(colored.contains("\x1b[36mProfile file:\x1b[0m"));
        assert!(colored.contains("\x1b[36mExecutable:\x1b[0m"));
        assert!(!colored.contains("secret-sentinel"));
        let json = render(
            &report,
            Format {
                json: true,
                color: true,
            },
        )
        .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["profiles"][0]["profile_path"],
            expected.to_string_lossy().as_ref()
        );
        assert!(!json.contains("secret-sentinel"));
        assert!(!json.contains('\x1b'));
        assert!(store.path("../escape").is_err());
    }

    #[test]
    fn incomplete_cleanup_report_is_rendered_and_fails_the_command() {
        let report = ProviderReport {
            backends: Vec::new(),
            operation: "cleanup",
            profiles: Vec::new(),
            removed: None,
            cleanup: vec![CleanupView {
                certificate: "web".into(),
                operation: "operation-id".into(),
                completed: true,
                error: None,
            }],
            cancelled: false,
            incomplete: true,
        };
        assert!(report.has_failures());
        assert_eq!(
            crate::dispatch::CommandReport::Provider(report.clone()).exit_status(),
            crate::common::session::ExitStatus::Failed
        );
        assert!(
            render(&report, Format::plain(false))
                .unwrap()
                .contains("did not examine all matching requests")
        );
        let json: serde_json::Value =
            serde_json::from_str(&render(&report, Format::plain(true)).unwrap()).unwrap();
        assert_eq!(json["incomplete"], true);
    }
    #[tokio::test]
    async fn cleanup_command_is_offline_and_reports_all_terminal_results() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_str().unwrap();
        let executable = std::env::current_exe().unwrap();
        let cli = CommandContext::new(true);
        execute(
            command(&[
                "add",
                "prod",
                "--exec",
                executable.to_str().unwrap(),
                "--allow-zone",
                "validation.net",
                "--data-dir",
                root,
                "--json",
            ]),
            &cli,
        )
        .await
        .unwrap();
        let report = execute(
            command(&["cleanup", "prod", "--data-dir", root, "--json"]),
            &cli,
        )
        .await
        .unwrap();
        assert_eq!(report.operation, "cleanup");
        assert!(report.cleanup.is_empty());
    }

    #[tokio::test]
    async fn provider_crud_outputs_are_redacted_and_no_binary_is_executed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_str().unwrap();
        let executable = std::env::current_exe().unwrap();
        let cli = CommandContext::new(true);
        execute(
            command(&[
                "add",
                "prod",
                "--exec",
                executable.to_str().unwrap(),
                "--allow-zone",
                "example.com",
                "--data-dir",
                root,
                "--json",
            ]),
            &cli,
        )
        .await
        .unwrap();
        let path = temp.path().join("providers/prod.toml");
        let mut document: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        document["provider_custom"] = toml::Value::Table(toml::Table::from_iter([(
            "token".into(),
            toml::Value::String("secret-sentinel".into()),
        )]));
        std::fs::write(&path, toml::to_string(&document).unwrap()).unwrap();
        for operation in ["show", "list"] {
            let words = if operation == "list" {
                vec!["list", "--data-dir", root, "--json"]
            } else {
                vec!["show", "prod", "--data-dir", root, "--json"]
            };
            let report = execute(command(&words), &cli).await.unwrap();
            let json = render(
                &report,
                Format {
                    json: true,
                    color: false,
                },
            )
            .unwrap();
            assert!(!json.contains("secret-sentinel"));
            assert!(json.contains("redacted"));
            assert!(
                !render(
                    &report,
                    Format {
                        json: false,
                        color: false
                    }
                )
                .unwrap()
                .contains("secret-sentinel")
            );
        }
        execute(
            command(&[
                "update",
                "prod",
                "--clear-args",
                "--data-dir",
                root,
                "--json",
            ]),
            &cli,
        )
        .await
        .unwrap();
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("secret-sentinel")
        );
        assert!(
            execute(
                command(&["remove", "prod", "--data-dir", root, "--json"]),
                &cli
            )
            .await
            .is_err()
        );
        execute(
            command(&["remove", "prod", "--yes", "--data-dir", root, "--json"]),
            &cli,
        )
        .await
        .unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn explicit_update_replaces_and_clears_fields_and_duplicate_add_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_str().unwrap();
        let executable = std::env::current_exe().unwrap();
        let cli = CommandContext::new(true);
        execute(
            command(&[
                "add",
                "prod",
                "--exec",
                executable.to_str().unwrap(),
                "--arg=old",
                "--allow-zone",
                "old.example",
                "--data-dir",
                root,
                "--json",
            ]),
            &cli,
        )
        .await
        .unwrap();
        assert!(
            execute(
                command(&[
                    "add",
                    "prod",
                    "--exec",
                    executable.to_str().unwrap(),
                    "--data-dir",
                    root,
                    "--json",
                ]),
                &cli
            )
            .await
            .is_err()
        );
        let updated = execute(
            command(&[
                "update",
                "prod",
                "--exec",
                executable.to_str().unwrap(),
                "--arg=--label=hello world",
                "--allow-zone",
                "updated.example",
                "--data-dir",
                root,
                "--json",
            ]),
            &cli,
        )
        .await
        .unwrap();
        assert_eq!(updated.profiles[0].args, ["--label=hello world"]);
        assert_eq!(updated.profiles[0].allowed_zones, ["updated.example"]);
        assert_eq!(updated.profiles[0].executable, executable);
        let cleared = execute(
            command(&[
                "update",
                "prod",
                "--clear-args",
                "--clear-zones",
                "--data-dir",
                root,
                "--json",
            ]),
            &cli,
        )
        .await
        .unwrap();
        assert_eq!(cleared.profiles[0].args, Vec::<String>::new());
        assert_eq!(cleared.profiles[0].allowed_zones, Vec::<String>::new());
    }
    #[tokio::test]
    async fn zone_restriction_is_optional_and_can_be_added_or_cleared() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_str().unwrap();
        let executable = std::env::current_exe().unwrap();
        let cli = CommandContext::new(true);
        let report = execute(
            command(&[
                "add",
                "prod",
                "--exec",
                executable.to_str().unwrap(),
                "--data-dir",
                root,
                "--json",
            ]),
            &cli,
        )
        .await
        .unwrap();
        let plain = render(
            &report,
            Format {
                json: false,
                color: false,
            },
        )
        .unwrap();
        assert!(plain.contains("all (unrestricted)"));
        let restricted = execute(
            command(&[
                "update",
                "prod",
                "--allow-zone",
                "example.com",
                "--data-dir",
                root,
                "--json",
            ]),
            &cli,
        )
        .await
        .unwrap();
        assert_eq!(restricted.profiles[0].allowed_zones, ["example.com"]);
        let cleared = execute(
            command(&[
                "update",
                "prod",
                "--clear-zones",
                "--data-dir",
                root,
                "--json",
            ]),
            &cli,
        )
        .await
        .unwrap();
        assert_eq!(
            cleared.profiles[0].allowed_zones,
            [] as [std::string::String; 0]
        );
        let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
            temp.path().into(),
            std::time::Duration::from_secs(1),
        );
        assert_eq!(
            store.get("prod".into()).await.unwrap().allowed_zones,
            [] as [std::string::String; 0]
        );
        assert!(
            Args::try_parse_from([
                "aster-acme",
                "provider",
                "update",
                "prod",
                "--clear-zones",
                "--allow-zone",
                "example.com"
            ])
            .is_err()
        );
    }

    #[test]
    fn malformed_provider_and_external_dns_arguments_are_rejected() {
        for words in [
            vec![
                "provider",
                "add",
                "../escape",
                "--exec",
                "/bin/true",
                "--allow-zone",
                "example.com",
            ],
            vec!["provider", "show", "prod", "--yes"],
        ] {
            assert!(Args::try_parse_from(["aster-acme"].into_iter().chain(words)).is_err());
        }
    }
    mod builtin;
}
