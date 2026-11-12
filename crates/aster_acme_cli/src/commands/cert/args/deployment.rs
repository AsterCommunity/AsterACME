//! Deployment operations keep configuration flags scoped to add and update.
use crate::commands::cert::args::parse_certificate_name;
use crate::common::args::LocalArgs;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct DeployArgs {
    #[command(subcommand)]
    pub(crate) command: DeployCommand,
}

#[derive(Subcommand)]
pub(crate) enum DeployCommand {
    /// Publish the current certificate and reload all or one deployment; also retries failures.
    #[command(mut_arg("id", |arg| arg.help("Deployment name; omit to run all configured bindings.")))]
    Run(DeployTargetArgs),
    /// Save a named binding and immediately deploy the current certificate.
    Add(DeployAddArgs),
    /// List saved bindings without publishing files or running reload commands.
    List(DeployListArgs),
    /// Inspect one saved deployment's configuration and execution status without running it.
    Show(DeployShowArgs),
    /// Change saved configuration without publishing files or running reload.
    #[command(mut_arg("id", |arg| arg.help("Deployment name; omit to select interactively.")))]
    Update(DeployUpdateArgs),
    /// Remove a binding; already published files remain untouched.
    #[command(mut_arg("id", |arg| arg.help("Deployment name; omit to select interactively.")))]
    Remove(DeployTargetArgs),
}

#[derive(Args)]
pub(crate) struct DeployTargetArgs {
    /// Managed certificate name; omit to select interactively.
    #[arg(value_name = "CERT_NAME", value_parser = parse_certificate_name)]
    pub(crate) name: Option<String>,
    /// Deployment name; its omission policy is defined by the owning operation.
    #[arg(short = 'n', long = "name", value_name = "DEPLOY_NAME", value_parser = parse_deployment_id)]
    pub(crate) id: Option<String>,
    #[command(flatten)]
    pub(crate) local: LocalArgs,
}

#[derive(Args)]
pub(crate) struct DeployListArgs {
    /// Managed certificate name; omit to select interactively.
    #[arg(value_name = "CERT_NAME", value_parser = parse_certificate_name)]
    pub(crate) name: Option<String>,
    #[command(flatten)]
    pub(crate) local: LocalArgs,
}

#[derive(Args)]
pub(crate) struct DeployShowArgs {
    /// Managed certificate name; omit to select interactively.
    #[arg(value_name = "CERT_NAME", value_parser = parse_certificate_name)]
    pub(crate) name: Option<String>,
    /// Deployment name; omit to select interactively.
    #[arg(value_name = "DEPLOY_NAME", value_parser = parse_deployment_id)]
    pub(crate) deployment: Option<String>,
    #[command(flatten)]
    pub(crate) local: LocalArgs,
}

#[derive(Args)]
pub(crate) struct DeployAddArgs {
    /// Managed certificate name; omit to select interactively.
    #[arg(value_name = "CERT_NAME", value_parser = parse_certificate_name)]
    pub(crate) name: Option<String>,
    /// Deployment name; omitted prompts with a default on terminals, auto-generates in scripts.
    #[arg(short = 'n', long = "name", value_name = "DEPLOY_NAME", value_parser = parse_deployment_id)]
    pub(crate) id: Option<String>,
    /// Existing directory receiving the four standard PEM files.
    #[arg(long, value_name = "DIR", conflicts_with_all = ["cert_path", "key_path", "fullchain_path", "ca_path"])]
    pub(crate) target: Option<PathBuf>,
    /// Publish the leaf certificate to this exact path.
    #[arg(long, value_name = "PATH", conflicts_with = "target")]
    pub(crate) cert_path: Option<PathBuf>,
    /// Publish the full certificate chain to this exact path.
    #[arg(long, value_name = "PATH", conflicts_with = "target")]
    pub(crate) fullchain_path: Option<PathBuf>,
    /// Publish the CA chain to this exact path.
    #[arg(long, value_name = "PATH", conflicts_with = "target")]
    pub(crate) ca_path: Option<PathBuf>,
    /// Publish the private key to this exact path.
    #[arg(long, value_name = "PATH", conflicts_with = "target")]
    pub(crate) key_path: Option<PathBuf>,
    /// Optional reload program and arguments; omit for file publication only.
    #[arg(long, value_name = "COMMAND")]
    pub(crate) reload_cmd: Option<String>,
    /// Unix certificate/CA/fullchain permissions in octal, default 0600.
    #[arg(long, value_name = "MODE", value_parser = parse_mode)]
    pub(crate) file_mode: Option<u32>,
    /// Unix private-key permissions in octal, default 0600.
    #[arg(long, value_name = "MODE", value_parser = parse_mode)]
    pub(crate) key_mode: Option<u32>,
    /// Timeout per reload attempt in seconds (1-3600), default 30.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub(crate) reload_timeout: Option<u64>,
    /// Additional reload attempts after failure (0-10), default 3.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=10))]
    pub(crate) max_retries: Option<u8>,
    #[command(flatten)]
    pub(crate) local: LocalArgs,
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("changes").args(["target", "cert_path", "fullchain_path", "ca_path", "key_path", "reload_cmd", "clear_reload", "reload_timeout", "max_retries", "file_mode", "key_mode"]).multiple(true).required(true)))]
pub(crate) struct DeployUpdateArgs {
    #[command(flatten)]
    pub(crate) identity: DeployTargetArgs,
    /// Replace the target with a standard PEM directory.
    #[arg(long, value_name = "DIR", conflicts_with_all = ["cert_path", "fullchain_path", "ca_path", "key_path"])]
    pub(crate) target: Option<PathBuf>,
    /// Replace destinations with exactly the supplied file paths (unspecified files are omitted).
    #[arg(long, value_name = "PATH", conflicts_with = "target")]
    pub(crate) cert_path: Option<PathBuf>,
    /// Publish the full chain at this path in the replacement destination set.
    #[arg(long, value_name = "PATH", conflicts_with = "target")]
    pub(crate) fullchain_path: Option<PathBuf>,
    /// Publish the CA chain at this path in the replacement destination set.
    #[arg(long, value_name = "PATH", conflicts_with = "target")]
    pub(crate) ca_path: Option<PathBuf>,
    /// Publish the private key at this path in the replacement destination set.
    #[arg(long, value_name = "PATH", conflicts_with = "target")]
    pub(crate) key_path: Option<PathBuf>,
    /// Replace the reload executable and arguments.
    #[arg(long, value_name = "COMMAND", conflicts_with = "clear_reload")]
    pub(crate) reload_cmd: Option<String>,
    /// Disable reload, retaining file publication.
    #[arg(long)]
    pub(crate) clear_reload: bool,
    /// Replace the timeout per reload attempt in seconds (1-3600).
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub(crate) reload_timeout: Option<u64>,
    /// Replace the number of additional reload attempts (0-10).
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=10))]
    pub(crate) max_retries: Option<u8>,
    /// Replace Unix certificate/CA/fullchain permissions with this octal mode.
    #[arg(long, value_name = "MODE", value_parser = parse_mode)]
    pub(crate) file_mode: Option<u32>,
    /// Replace Unix private-key permissions with this octal mode.
    #[arg(long, value_name = "MODE", value_parser = parse_mode)]
    pub(crate) key_mode: Option<u32>,
}

fn parse_mode(value: &str) -> Result<u32, String> {
    if !(3..=4).contains(&value.len()) || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err("Use an octal Unix permission mode such as 0644 or 0640.".into());
    }
    let mode = u32::from_str_radix(value, 8).map_err(|_| "Invalid octal mode.".to_owned())?;
    if mode > 0o777 {
        return Err("Only ordinary permission bits 000-777 are accepted.".into());
    }
    Ok(mode)
}

impl DeployArgs {
    pub(crate) fn local(&self) -> &LocalArgs {
        match &self.command {
            DeployCommand::Run(args) | DeployCommand::Remove(args) => &args.local,
            DeployCommand::Add(args) => &args.local,
            DeployCommand::List(args) => &args.local,
            DeployCommand::Show(args) => &args.local,
            DeployCommand::Update(args) => &args.identity.local,
        }
    }

    pub(crate) fn name(&self) -> Option<&str> {
        match &self.command {
            DeployCommand::Run(args) | DeployCommand::Remove(args) => args.name.as_deref(),
            DeployCommand::Add(args) => args.name.as_deref(),
            DeployCommand::List(args) => args.name.as_deref(),
            DeployCommand::Show(args) => args.name.as_deref(),
            DeployCommand::Update(args) => args.identity.name.as_deref(),
        }
    }
}

pub(crate) fn parse_deployment_id(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(
            "Use 1-64 ASCII letters, digits, hyphens or underscores for deployment name.".into(),
        );
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests;
