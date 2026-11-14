//! Manage per-profile DNS provider executables and custom configuration.

use crate::common::output::safe;
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

#[derive(Subcommand)]
pub(crate) enum ProviderCommand {
    /// Register a named provider executable.
    Add(AddArgs),
    /// List configured provider profile names and safe metadata.
    List(LocalArgs),
    /// Show one provider profile with all custom values redacted.
    Show(ShowArgs),
    /// Retry owned DNS cleanup for terminal requests using this provider profile.
    Cleanup(ShowArgs),
    /// Update executable settings for a provider profile.
    Update(UpdateArgs),
    /// Remove a provider profile that no retained certificate references.
    Remove(RemoveArgs),
}

impl ProviderCommand {
    pub(crate) fn local(&self) -> &LocalArgs {
        match self {
            Self::Add(args) => &args.local,
            Self::List(local) => local,
            Self::Show(args) | Self::Cleanup(args) => &args.local,
            Self::Update(args) => &args.local,
            Self::Remove(args) => &args.local,
        }
    }
}

#[derive(Args)]
pub(crate) struct AddArgs {
    /// Stable provider profile name.
    #[arg(value_parser = parse_account_name)]
    name: String,
    /// Absolute executable path; no shell is used.
    #[arg(long, value_name = "PATH")]
    exec: PathBuf,
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
    /// Stable provider profile name.
    #[arg(value_parser = parse_account_name)]
    name: String,
    #[command(flatten)]
    local: LocalArgs,
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("provider_changes").args(["exec", "args", "clear_args", "allowed_zones", "clear_zones"]).multiple(true).required(true)))]
pub(crate) struct UpdateArgs {
    /// Stable provider profile name.
    #[arg(value_parser = parse_account_name)]
    name: String,
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
    #[command(flatten)]
    local: LocalArgs,
}

#[derive(Args)]
pub(crate) struct RemoveArgs {
    /// Stable provider profile name.
    #[arg(value_parser = parse_account_name)]
    name: String,
    /// Confirm removal without prompting.
    #[arg(short = 'y', long)]
    yes: bool,
    #[command(flatten)]
    local: LocalArgs,
}

#[derive(Debug, Clone, Serialize)]
struct ProfileView {
    name: String,
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
    operation: &'static str,
    profiles: Vec<ProfileView>,
    removed: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cleanup: Vec<CleanupView>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    cancelled: bool,
}

impl ProviderReport {
    pub(crate) fn has_failures(&self) -> bool {
        self.cleanup.iter().any(|item| !item.completed)
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

pub(crate) async fn execute(
    command: ProviderCommand,
    cli: &crate::common::context::CommandContext,
) -> CliResult<ProviderReport> {
    let local = command.local().clone();
    let settings = CliSettings::load(&local.into()).await?;
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        settings.data_dir.clone(),
        Duration::from_secs(5),
    );
    match command {
        ProviderCommand::Add(args) => {
            validate_executable(&args.exec)?;
            let profile = aster_acme_cli_storage::provider::ProviderProfile::new(
                args.exec,
                args.args,
                args.allowed_zones,
            )?;
            store.add(args.name.clone(), profile.clone()).await?;
            Ok(ProviderReport {
                operation: "added",
                profiles: vec![view(args.name, profile)],
                removed: None,
                cleanup: Vec::new(),
                cancelled: false,
            })
        }
        ProviderCommand::List(_) => {
            let names = store.names().await?;
            let mut profiles = Vec::with_capacity(names.len());
            for name in names {
                profiles.push(view(name.clone(), store.get(name).await?));
            }
            Ok(ProviderReport {
                operation: "listed",
                profiles,
                removed: None,
                cleanup: Vec::new(),
                cancelled: false,
            })
        }
        ProviderCommand::Show(args) => Ok(ProviderReport {
            operation: "shown",
            profiles: vec![view(args.name.clone(), store.get(args.name).await?)],
            removed: None,
            cleanup: Vec::new(),
            cancelled: false,
        }),
        ProviderCommand::Update(args) => {
            if let Some(executable) = &args.exec {
                validate_executable(executable)?;
            }
            let profile = store
                .edit(args.name.clone(), move |profile| {
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
                    profile.validate()
                })
                .await?;
            Ok(ProviderReport {
                operation: "updated",
                profiles: vec![view(args.name, profile)],
                removed: None,
                cleanup: Vec::new(),
                cancelled: false,
            })
        }
        ProviderCommand::Cleanup(args) => {
            cleanup_profile(args, &settings.data_dir, &store, cli).await
        }
        ProviderCommand::Remove(args) => remove_profile(args, &store, cli).await,
    }
}

async fn remove_profile(
    args: RemoveArgs,
    store: &aster_acme_cli_storage::provider::ProviderProfileStore,
    cli: &crate::common::context::CommandContext,
) -> CliResult<ProviderReport> {
    let profile = store.get(args.name.clone()).await?;
    terminal::confirm_action(
        &format!(
            "Remove provider profile '{}' for executable {}? Custom values are sensitive and will be deleted.",
            args.name,
            safe(&profile.executable.to_string_lossy())
        ),
        "Remove this provider profile?",
        args.yes,
        &cli.output,
    )?;
    store.remove(args.name.clone()).await?;
    Ok(ProviderReport {
        operation: "removed",
        profiles: Vec::new(),
        removed: Some(args.name),
        cleanup: Vec::new(),
        cancelled: false,
    })
}

async fn cleanup_profile(
    args: ShowArgs,
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
    for record in records.into_iter().filter(|record| {
        record.solver_id == "dns_external"
            && record
                .solver_config
                .get("provider_instance_id")
                .and_then(serde_json::Value::as_str)
                == Some(&args.name)
            && record
                .authorizations
                .iter()
                .any(|auth| auth.cleanup_pending)
            && record.publication_cleanup_eligible(time::OffsetDateTime::now_utc())
    }) {
        if execution.check().is_err() {
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
        operation: "cleanup",
        profiles: Vec::new(),
        removed: None,
        cleanup,
        cancelled: execution.cancellation.is_cancelled(),
    })
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

fn view(name: String, profile: aster_acme_cli_storage::provider::ProviderProfile) -> ProfileView {
    ProfileView {
        name,
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
        return Ok(format!("Removed provider profile {name}."));
    }
    if report.operation == "cleanup" {
        if report.cleanup.is_empty() {
            return Ok("No terminal DNS publication cleanup is pending for this provider.".into());
        }
        return Ok(report
            .cleanup
            .iter()
            .map(|item| {
                format!(
                    "{}: {}{}",
                    item.certificate,
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
            .collect::<Vec<_>>()
            .join("\n"));
    }
    if report.profiles.is_empty() {
        return Ok("No DNS provider profiles configured.".into());
    }
    let mut lines = vec![match report.operation {
        "added" => "Added DNS provider profile.".to_owned(),
        "updated" => "Updated DNS provider profile.".to_owned(),
        "shown" => "DNS provider profile:".to_owned(),
        _ => "DNS provider profiles:".to_owned(),
    }];
    for profile in &report.profiles {
        lines.push(format!("Name:             {}", profile.name));
        lines.push(format!(
            "Executable:       {}",
            safe(&profile.executable.to_string_lossy())
        ));
        lines.push(format!(
            "Allowed zones:    {}",
            if profile.allowed_zones.is_empty() {
                "all (unrestricted)".to_owned()
            } else {
                safe(&profile.allowed_zones.join(", "))
            }
        ));
        lines.push(format!("Profile version:  {}", profile.profile_version));
        lines.push(format!("Custom values:    {}", profile.custom_values));
        if !profile.args.is_empty() {
            lines.push(format!(
                "Arguments:        {}",
                safe(&serde_json::to_string(&profile.args).unwrap_or_default())
            ));
        }
        if report.operation != "listed" {
            break;
        }
        lines.push(String::new());
    }
    Ok(lines.join("\n").trim_end().to_owned())
}

#[cfg(test)]
mod tests {
    use crate::{
        app::{Args, Command},
        commands::provider::{execute, render},
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
            vec!["provider", "update", "prod"],
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
}
