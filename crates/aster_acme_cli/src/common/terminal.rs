//! Terminal capabilities and escaping of untrusted display text.

use crate::common::error::CliResult;
use std::{
    fmt,
    io::{self, IsTerminal},
};

/// A declined prompt or Ctrl-C is a user cancellation, distinct from an operation failure.
#[derive(Debug)]
pub(crate) struct Canceled;

impl fmt::Display for Canceled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Canceled; the requested operation was not submitted.")
    }
}

impl std::error::Error for Canceled {}

/// Machine output and redirected input must never trigger interactive questions.
pub(crate) fn interactive(json: bool) -> bool {
    !json && io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// Normalize terminal interruption without hiding genuine terminal I/O failures.
pub(crate) fn prompt_result<T>(result: Result<T, inquire::InquireError>) -> CliResult<T> {
    match result {
        Ok(value) => Ok(value),
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => Err(Box::new(Canceled)),
        Err(error) => Err(Box::new(error)),
    }
}

/// Shared prompt palette; terminal controls stay disabled under `NO_COLOR` or redirects.
pub(crate) fn prompt_style(danger: bool) -> inquire::ui::RenderConfig<'static> {
    use inquire::ui::{Color, RenderConfig, StyleSheet};
    if !super::output::colors(io::stderr().is_terminal()) {
        return RenderConfig::empty();
    }
    RenderConfig {
        prompt: StyleSheet::new().with_fg(if danger {
            Color::LightRed
        } else {
            Color::LightCyan
        }),
        answer: StyleSheet::new().with_fg(Color::LightGreen),
        ..RenderConfig::default()
    }
}

/// Resolve terminal selection to a stable caller-owned index and normalize cancellation.
pub(crate) fn select_index(message: &str, choices: &[String], default: usize) -> CliResult<usize> {
    let items = choices
        .iter()
        .enumerate()
        .map(|(index, label)| SelectionItem {
            index,
            label: label.clone(),
        })
        .collect();
    let chosen = prompt_result(
        inquire::Select::new(message, items)
            .with_starting_cursor(default)
            .with_render_config(prompt_style(false))
            .prompt(),
    )?;
    Ok(chosen.index)
}

// Keep UI identity separate from labels: two requests may display the same domain,
// minute and status without selecting the first matching string by mistake.
struct SelectionItem {
    index: usize,
    label: String,
}
impl fmt::Display for SelectionItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.label)
    }
}

/// Follow the Drive confirmation policy: default no, explicit opt-in for automation.
/// JSON mode never prompts, even when attached to a terminal.
pub(crate) fn confirm_write(message: &str, yes: bool, json: bool) -> CliResult<()> {
    confirm_with(
        message,
        yes,
        json,
        io::stdin().is_terminal() && io::stderr().is_terminal(),
        |message| {
            prompt_result(
                inquire::Confirm::new(message)
                    .with_default(false)
                    .with_render_config(prompt_style(false))
                    .prompt(),
            )
        },
    )
}

/// Render reviewable context above a short confirmation, keeping input prompts readable.
/// Automation receives the same context as an error and never prints human text into JSON.
pub(crate) fn confirm_action(
    details: &str,
    question: &str,
    yes: bool,
    json: bool,
) -> CliResult<()> {
    if yes {
        return Ok(());
    }
    if !interactive(json) {
        return Err(format!(
            "{details}\nThis operation requires confirmation; use --yes in automation."
        )
        .into());
    }
    let color = super::output::colors(io::stderr().is_terminal());
    eprintln!("{}\n", super::output::confirmation(details, color));
    let accepted = prompt_result(
        inquire::Confirm::new(question)
            .with_default(false)
            .with_render_config(prompt_style(true))
            .prompt(),
    )?;
    if accepted {
        Ok(())
    } else {
        Err(Box::new(Canceled))
    }
}

fn confirm_with(
    message: &str,
    yes: bool,
    json: bool,
    terminal: bool,
    prompt: impl FnOnce(&str) -> CliResult<bool>,
) -> CliResult<()> {
    if yes {
        return Ok(());
    }
    if json || !terminal {
        return Err(format!(
            "{message} This operation requires confirmation; use --yes in automation."
        )
        .into());
    }
    if prompt(message)? {
        Ok(())
    } else {
        Err(Box::new(Canceled))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_defaults_to_no_and_never_prompts_automation() {
        for (json, terminal) in [(true, true), (true, false), (false, false)] {
            assert!(
                confirm_with("Existing account.", false, json, terminal, |_| panic!(
                    "must not prompt"
                ))
                .unwrap_err()
                .to_string()
                .contains("--yes")
            );
            assert!(
                confirm_with("Existing account.", true, json, terminal, |_| panic!(
                    "must not prompt"
                ))
                .is_ok()
            );
        }
        assert!(confirm_with("Existing account.", false, false, true, |_| Ok(true)).is_ok());
        assert!(
            confirm_with("Existing account.", false, false, true, |_| Ok(false))
                .unwrap_err()
                .is::<Canceled>()
        );
        assert!(
            confirm_with("Existing account.", false, false, true, |_| Err(Box::new(
                Canceled
            )))
            .unwrap_err()
            .is::<Canceled>()
        );
    }
}
