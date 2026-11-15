//! Edit a private draft; only the caller may commit it after a complete snapshot check.
use crate::commands::provider::{
    interaction::{Back, Prompts},
    validate_executable,
};
use crate::common::{error::CliResult, output::safe, terminal::Canceled};
use aster_acme_cli_storage::provider::ProviderProfile;
use std::path::{Path, PathBuf};

pub(in crate::commands::provider) fn edit(
    name: &str,
    path: &Path,
    original: &ProviderProfile,
    prompts: &mut dyn Prompts,
) -> CliResult<ProviderProfile> {
    let mut draft = original.clone();
    let choices = [
        "Executable path",
        "Arguments",
        "Allowed zones",
        "Save changes",
        "Cancel",
    ]
    .map(str::to_owned);
    loop {
        prompts.review(name, path, &draft)?;
        let action = prompts
            .select("Edit provider profile:", &choices)
            .map_err(|error| {
                if error.is::<Back>() {
                    Box::new(Canceled) as Box<dyn std::error::Error>
                } else {
                    error
                }
            })?;
        match action {
            0 => {
                let executable = match prompts.text("Provider executable path:", true) {
                    Ok(value) => PathBuf::from(value),
                    Err(error) if error.is::<Back>() => continue,
                    Err(error) => return Err(error),
                };
                match validate_executable(&executable) {
                    Ok(()) => draft.executable = executable,
                    Err(error) => prompts.invalid(&error.to_string()),
                }
            }
            1 => edit_list(&mut draft.args, ListKind::Arguments, prompts)?,
            2 => edit_list(&mut draft.allowed_zones, ListKind::Zones, prompts)?,
            3 => {
                draft.validate()?;
                validate_executable(&draft.executable)?;
                return Ok(draft);
            }
            4 => return Err(Box::new(Canceled)),
            _ => return Err("Invalid provider edit selection.".into()),
        }
    }
}

#[derive(Clone, Copy)]
enum ListKind {
    Arguments,
    Zones,
}

fn edit_list(values: &mut Vec<String>, kind: ListKind, prompts: &mut dyn Prompts) -> CliResult<()> {
    let (message, add, clear) = match kind {
        ListKind::Arguments => (
            "Edit arguments:",
            "Argument value (passed exactly, without shell parsing):",
            "Clear arguments",
        ),
        ListKind::Zones => (
            "Edit allowed zones:",
            "Allowed zone:",
            "Clear restrictions (allow all zones)",
        ),
    };
    loop {
        let choices = vec![
            "Add value".into(),
            "Remove value".into(),
            clear.into(),
            "Back to profile".into(),
        ];
        let action = match prompts.select(message, &choices) {
            Ok(index) => index,
            Err(error) if error.is::<Back>() => return Ok(()),
            Err(error) => return Err(error),
        };
        match action {
            0 => {
                let value = match prompts.text(add, true) {
                    Ok(value) => value,
                    Err(error) if error.is::<Back>() => continue,
                    Err(error) => return Err(error),
                };
                let valid = match kind {
                    ListKind::Arguments => !value.contains('\0'),
                    ListKind::Zones => {
                        aster_acme_dns::routing::absolute_name(&value).is_ok_and(|name| {
                            !values.iter().any(|old| {
                                aster_acme_dns::routing::absolute_name(old)
                                    .is_ok_and(|old| old == name)
                            })
                        })
                    }
                };
                if valid {
                    values.push(value);
                } else {
                    prompts.invalid("Enter a valid value; zones must be distinct DNS names and arguments cannot contain NUL.");
                }
            }
            1 => {
                if values.is_empty() {
                    prompts.invalid("There are no values to remove.");
                    continue;
                }
                let mut labels = values
                    .iter()
                    .enumerate()
                    .map(|(index, value)| format!("{}: {}", index + 1, safe(value)))
                    .collect::<Vec<_>>();
                labels.push("Back".into());
                let index = match prompts.select("Remove which value?", &labels) {
                    Ok(index) => index,
                    Err(error) if error.is::<Back>() => continue,
                    Err(error) => return Err(error),
                };
                if index == values.len() {
                    continue;
                }
                if index > values.len() {
                    return Err("Invalid provider value selection.".into());
                }
                values.remove(index);
            }
            2 => values.clear(),
            3 => return Ok(()),
            _ => return Err("Invalid provider list edit selection.".into()),
        }
    }
}

#[cfg(test)]
mod tests;
