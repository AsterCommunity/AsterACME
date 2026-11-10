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
        formatter.write_str("Canceled; the requested account operation was not submitted.")
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

/// Follow the Drive confirmation policy: default no, explicit opt-in for automation.
/// JSON mode never prompts, even when attached to a terminal.
pub(crate) fn confirm_write(message: &str, yes: bool, json: bool) -> CliResult<()> {
    confirm_with(
        message,
        yes,
        json,
        io::stdin().is_terminal() && io::stderr().is_terminal(),
        |message| prompt_result(inquire::Confirm::new(message).with_default(false).prompt()),
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
    eprintln!("{details}\n");
    confirm_write(question, false, false)
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

pub(crate) fn colors(terminal: bool) -> bool {
    terminal
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}

pub(crate) fn styled(text: &str, code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// CA details and configured names are untrusted terminal text, including on errors.
pub(crate) fn safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
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
