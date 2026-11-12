//! Complete missing add inputs before any binding or file is written.
use crate::commands::cert::{
    args::deployment::{DeployAddArgs, parse_deployment_id},
    deployment::{directory, parse_command},
};
use crate::common::{error::CliResult, session::OutputSession, terminal};
use aster_acme_cli_storage::issuance::DeploymentBinding;
use std::path::Path;

pub(super) trait Prompts {
    fn text(&mut self, message: &str, default: Option<&str>) -> CliResult<String>;
    fn invalid(&mut self, message: &str);
}

pub(super) struct TerminalPrompts<'a> {
    pub(super) output: &'a OutputSession,
}

impl Prompts for TerminalPrompts<'_> {
    fn text(&mut self, message: &str, default: Option<&str>) -> CliResult<String> {
        self.output.interaction_started();
        let prompt = inquire::Text::new(message).with_render_config(terminal::prompt_style(
            self.output.diagnostic_format().color,
            false,
        ));
        let prompt = if let Some(default) = default {
            prompt.with_default(default)
        } else {
            prompt
        };
        terminal::prompt_result(prompt.prompt())
    }

    fn invalid(&mut self, message: &str) {
        self.output.context(&crate::common::output::safe(message));
    }
}

pub(super) fn complete(
    args: &mut DeployAddArgs,
    definitions: &[DeploymentBinding],
    interactive: bool,
    prompts: &mut impl Prompts,
) -> CliResult<()> {
    if let Some(id) = &args.id {
        validate_name(id, definitions)?;
    } else if interactive {
        let suggestion = (0..=definitions.len())
            .map(|index| {
                if index == 0 {
                    "default".to_owned()
                } else {
                    format!("deploy-{index}")
                }
            })
            .find(|name| !definitions.iter().any(|entry| entry.id == *name))
            .ok_or("No available deployment name suggestion.")?;
        args.id = Some(loop {
            let name = prompts.text("Deployment name:", Some(&suggestion))?;
            match validate_name(&name, definitions) {
                Ok(()) => break name,
                Err(error) => prompts.invalid(&error.to_string()),
            }
        });
    }
    if args.target.is_none()
        && args.cert_path.is_none()
        && args.key_path.is_none()
        && args.fullchain_path.is_none()
        && args.ca_path.is_none()
    {
        if !interactive {
            return Err(
                "Specify --target DIR or at least one exact file destination (--cert-path, --key-path, --ca-path, --fullchain-path).".into(),
            );
        }
        args.target = Some(loop {
            let path = prompts.text("Target directory (existing):", None)?;
            if path.is_empty() {
                prompts.invalid("Enter an existing target directory.");
                continue;
            }
            match directory(Path::new(&path)) {
                Ok(path) => break path,
                Err(error) => prompts.invalid(&error.to_string()),
            }
        });
    }
    if interactive && args.reload_cmd.is_none() {
        args.reload_cmd = loop {
            let command = prompts.text("Reload command (optional; Enter to skip):", None)?;
            if command.trim().is_empty() {
                break None;
            }
            match parse_command(&command) {
                Ok(_) => break Some(command),
                Err(error) => prompts.invalid(&error.to_string()),
            }
        };
    }
    Ok(())
}

fn validate_name(id: &str, definitions: &[DeploymentBinding]) -> CliResult<()> {
    parse_deployment_id(id)?;
    if definitions.iter().any(|definition| definition.id == id) {
        return Err("That deployment name already exists for this certificate.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
