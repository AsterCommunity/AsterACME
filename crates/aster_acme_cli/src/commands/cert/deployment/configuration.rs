//! Deployment configuration stage.

use crate::commands::cert::args::deployment::DeployAddArgs;
use crate::commands::cert::deployment::interaction;
use crate::commands::cert::deployment::{DEFAULT_RETRIES, DEFAULT_TIMEOUT_SECONDS};
use crate::common::error::CliResult;
use aster_acme::issuance::CertificateName;
use aster_acme::storage::issuance::IssueStore as _;
use aster_acme::storage::query::{IssueQuery, IssueView};
use aster_acme_cli_storage::issuance::{
    CliIssueStore, DeploymentBinding, DeploymentDefinition, DeploymentPatch, DeploymentPermissions,
    DeploymentTarget,
};
use std::path::{Path, PathBuf};

pub(super) async fn complete_add(
    store: &CliIssueStore,
    name: &CertificateName,
    args: &mut DeployAddArgs,
    output: &crate::common::session::OutputSession,
) -> CliResult<()> {
    let definitions = store.deployments(name).await?;
    interaction::complete(
        args,
        &definitions,
        crate::common::terminal::interactive(output.is_json()),
        &mut interaction::TerminalPrompts { output },
    )
}

pub(super) async fn update(
    store: &CliIssueStore,
    name: &CertificateName,
    args: crate::commands::cert::args::deployment::DeployUpdateArgs,
    output: &crate::common::session::OutputSession,
) -> CliResult<DeploymentBinding> {
    let id = if let Some(id) = args.identity.id {
        id
    } else {
        let definitions = store.deployments(name).await?;
        binding_id(&definitions, "update", output)?
    };
    let target = if args.target.is_some()
        || args.cert_path.is_some()
        || args.fullchain_path.is_some()
        || args.ca_path.is_some()
        || args.key_path.is_some()
    {
        Some(destination(
            args.target,
            args.cert_path,
            args.fullchain_path,
            args.ca_path,
            args.key_path,
        )?)
    } else {
        None
    };
    let patch = DeploymentPatch {
        target,
        reload_command: if args.clear_reload {
            Some(Vec::new())
        } else {
            args.reload_cmd.as_deref().map(parse_command).transpose()?
        },
        timeout_seconds: args.reload_timeout,
        max_retries: args.max_retries,
        permissions: DeploymentPermissions {
            file_mode: args.file_mode,
            key_mode: args.key_mode,
        },
    };
    let binding = store.update_deployment(name, &id, patch).await?;
    Ok(binding)
}

pub(super) fn definition(args: DeployAddArgs) -> CliResult<DeploymentDefinition> {
    Ok(DeploymentDefinition {
        permissions: DeploymentPermissions {
            file_mode: args.file_mode,
            key_mode: args.key_mode,
        },
        name: args.id,
        target: destination(
            args.target,
            args.cert_path,
            args.fullchain_path,
            args.ca_path,
            args.key_path,
        )?,
        reload_command: args
            .reload_cmd
            .as_deref()
            .map(parse_command)
            .transpose()?
            .unwrap_or_default(),
        timeout_seconds: args.reload_timeout.unwrap_or(DEFAULT_TIMEOUT_SECONDS),
        max_retries: args.max_retries.unwrap_or(DEFAULT_RETRIES),
    })
}

pub(super) fn binding_id(
    definitions: &[DeploymentBinding],
    operation: &str,
    output: &crate::common::session::OutputSession,
) -> CliResult<String> {
    if !crate::common::terminal::interactive(output.is_json()) {
        let hint = if operation == "inspect" {
            "cert deploy show CERT_NAME DEPLOY_NAME"
        } else {
            "cert deploy update CERT_NAME -n DEPLOY_NAME"
        };
        return Err(format!("Specify a deployment name: {hint}.").into());
    }
    if definitions.is_empty() {
        return Err(
            "No deployment bindings to inspect. Use cert deploy add to configure one.".into(),
        );
    }
    let labels = definitions
        .iter()
        .map(|binding| binding.id.clone())
        .collect::<Vec<_>>();
    let index = crate::common::terminal::select_index(
        &format!("Choose a deployment to {operation}:"),
        &labels,
        0,
        output,
    )?;
    labels
        .into_iter()
        .nth(index)
        .ok_or_else(|| "Invalid deployment selection.".into())
}

pub(super) fn remove_id(
    explicit: Option<String>,
    definitions: &[DeploymentBinding],
    output: &crate::common::session::OutputSession,
) -> CliResult<String> {
    if let Some(id) = explicit {
        return Ok(id);
    }
    if definitions.is_empty() {
        return Err("No deployment bindings to remove.".into());
    }
    if !crate::common::terminal::interactive(output.is_json()) {
        return Err(
            "Specify a deployment name: cert deploy remove CERT_NAME -n DEPLOY_NAME.".into(),
        );
    }
    let labels = definitions
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let index = crate::common::terminal::select_index(
        "Choose a deployment to remove:",
        &labels,
        0,
        output,
    )?;
    labels
        .into_iter()
        .nth(index)
        .ok_or_else(|| "Invalid deployment selection.".into())
}

/// Inspecting/removing bindings uses retained inventory; publishing requires an eligible current version.
pub(super) async fn select_certificate(
    store: &CliIssueStore,
    explicit: Option<&str>,
    managing: bool,
    output: &crate::common::session::OutputSession,
) -> CliResult<CertificateName> {
    let candidates = store
        .query(IssueQuery {
            name: explicit.map(CertificateName::new).transpose()?,
            view: if managing {
                IssueView::Managed
            } else {
                IssueView::All
            },
            in_use: if managing { None } else { Some(true) },
            unfinished: if managing { None } else { Some(false) },
            revocation: if managing {
                None
            } else {
                Some(aster_acme_core::revocation::RevocationState::NotRequested)
            },
            ..IssueQuery::default()
        })
        .await?;
    if managing {
        crate::commands::cert::selection::certificate_name(
            &candidates,
            explicit,
            None,
            crate::commands::cert::selection::CertificateLabel::Deployment,
            output,
        )
    } else {
        crate::commands::cert::selection::deployment_certificate_name(&candidates, explicit, output)
    }
}

/// Called after a completed issuance/renewal. A deployment error never changes
/// the saved CA certificate result; each target retains its own retry checkpoint.
pub(super) fn destination(
    target: Option<PathBuf>,
    certificate: Option<PathBuf>,
    fullchain: Option<PathBuf>,
    ca_chain: Option<PathBuf>,
    key: Option<PathBuf>,
) -> CliResult<DeploymentTarget> {
    match (target, certificate, fullchain, ca_chain, key) {
        (Some(path), None, None, None, None) => {
            Ok(DeploymentTarget::Directory { path: directory(&path)? })
        }
        (None, certificate, fullchain, ca_chain, private_key)
            if certificate.is_some() || fullchain.is_some() || ca_chain.is_some() || private_key.is_some() => Ok(DeploymentTarget::Files {
                certificate: certificate.as_deref().map(canonical_file_path).transpose()?,
                fullchain: fullchain.as_deref().map(canonical_file_path).transpose()?,
                ca_chain: ca_chain.as_deref().map(canonical_file_path).transpose()?,
                private_key: private_key.as_deref().map(canonical_file_path).transpose()?,
            }),
        _ => Err("Use --target DIR or at least one of --cert-path, --key-path, --ca-path, --fullchain-path; these forms are mutually exclusive.".into()),
    }
}

pub(super) fn directory(path: &Path) -> CliResult<PathBuf> {
    let path = path
        .canonicalize()
        .map_err(|_| "--target must be an existing directory")?;
    if !path.is_dir() {
        return Err("--target must be an existing directory".into());
    }
    Ok(path)
}

pub(super) fn canonical_file_path(path: &Path) -> CliResult<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let name = path
        .file_name()
        .ok_or("deployment file path must name a file")?;
    if name.to_string_lossy().contains(['/', '\\', ':']) {
        return Err("invalid deployment filename".into());
    }
    Ok(parent.join(name))
}

pub(super) fn parse_command(command: &str) -> CliResult<Vec<String>> {
    let words = shlex::split(command).ok_or("--reload-cmd has unbalanced quoting")?;
    if words.is_empty()
        || words.len() > 64
        || words
            .iter()
            .any(|word| word.contains('\0') || word.len() > 4096)
    {
        return Err("--reload-cmd must contain a bounded executable and argv".into());
    }
    Ok(words)
}

pub(super) fn select_targets(
    definitions: Vec<DeploymentBinding>,
    requested: Option<&str>,
) -> CliResult<Vec<DeploymentBinding>> {
    if let Some(id) = requested {
        return definitions
            .into_iter()
            .find(|item| item.id == id)
            .map(|item| vec![item])
            .ok_or_else(|| format!("No deployment named '{id}' is configured.").into());
    }
    Ok(definitions)
}
