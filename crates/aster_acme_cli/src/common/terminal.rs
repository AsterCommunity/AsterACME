//! Terminal capabilities and escaping of untrusted display text.

use crate::common::error::CliResult;
use std::{
    fmt,
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};

struct RawModeGuard(bool);

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.0 {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

impl RawModeGuard {
    fn restore(&mut self) -> io::Result<()> {
        if self.0 {
            crossterm::terminal::disable_raw_mode()?;
            self.0 = false;
        }
        Ok(())
    }
}

fn wrap_terminal_text(value: &str, max_width: usize) -> Vec<String> {
    use unicode_width::UnicodeWidthChar as _;

    let mut lines = Vec::new();
    let mut line = String::new();
    let mut width = 0usize;
    for character in value.chars() {
        let character_width = character.width().unwrap_or(0);
        if width > 0 && width + character_width > max_width {
            lines.push(std::mem::take(&mut line));
            width = 0;
        }
        line.push(character);
        width += character_width;
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// A declined prompt or Ctrl-C is a user cancellation, distinct from an operation failure.
#[derive(Debug)]
pub(crate) struct Canceled;

impl fmt::Display for Canceled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Canceled; inspect saved state before retrying or resuming.")
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
pub(crate) fn prompt_style(color: bool, danger: bool) -> inquire::ui::RenderConfig<'static> {
    use inquire::ui::{Color, RenderConfig, StyleSheet};
    if !color {
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
pub(crate) fn select_index(
    message: &str,
    choices: &[String],
    default: usize,
    output: &crate::common::session::OutputSession,
) -> CliResult<usize> {
    select_index_or_back(message, choices, default, output)?
        .ok_or_else(|| Box::new(Canceled) as Box<dyn std::error::Error>)
}

/// Editor navigation distinguishes Esc (back) from Ctrl-C (cancel the operation).
pub(crate) fn select_index_or_back(
    message: &str,
    choices: &[String],
    default: usize,
    output: &crate::common::session::OutputSession,
) -> CliResult<Option<usize>> {
    output.interaction_started();
    let items = choices
        .iter()
        .enumerate()
        .map(|(index, label)| SelectionItem {
            index,
            label: label.clone(),
        })
        .collect();
    match inquire::Select::new(message, items)
        .with_starting_cursor(default)
        .with_render_config(prompt_style(output.diagnostic_format().color, false))
        .prompt()
    {
        Err(inquire::InquireError::OperationCanceled) => Ok(None),
        Err(inquire::InquireError::OperationInterrupted) => Err(Box::new(Canceled)),
        Err(error) => Err(Box::new(error)),
        Ok(chosen) => Ok(Some(chosen.index)),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "bounded prompt owns rendering, input, and terminal restoration"
)]
pub(crate) fn select_index_or_back_bounded(
    message: &str,
    choices: &[String],
    default: usize,
    output: &crate::common::session::OutputSession,
    execution: &aster_acme::solver::ExecutionContext,
) -> Result<Option<usize>, aster_acme::issuance::IssueError> {
    use aster_acme::issuance::IssueError;
    use crossterm::{
        cursor::{MoveToColumn, MoveUp},
        event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
        terminal::{self, Clear, ClearType},
    };

    if choices.is_empty() || default >= choices.len() {
        return Err(IssueError::InvalidInput("invalid terminal choices"));
    }
    execution.check().map_err(IssueError::from)?;
    output.interaction_started();
    let terminal_issue = |error: io::Error| {
        IssueError::Publication(format!("chain selection terminal failed: {error}"))
    };
    let restore_raw = !terminal::is_raw_mode_enabled().map_err(&terminal_issue)?;
    if restore_raw {
        terminal::enable_raw_mode().map_err(&terminal_issue)?;
    }
    let mut raw_mode = RawModeGuard(restore_raw);
    let mut writer = io::stderr().lock();
    let mut selected = default;
    let mut rendered_lines = 0usize;
    let result = (|| {
        loop {
            execution.check().map_err(IssueError::from)?;
            if rendered_lines > 0 {
                let lines = u16::try_from(rendered_lines)
                    .map_err(|_| IssueError::InvalidInput("too many terminal choices"))?;
                crossterm::queue!(
                    writer,
                    MoveUp(lines),
                    MoveToColumn(0),
                    Clear(ClearType::FromCursorDown)
                )
                .map_err(terminal_issue)?;
            }
            let width = terminal::size().map_err(&terminal_issue)?.0.max(1) as usize;
            let wrap_width = width.saturating_sub(2).max(1);
            let header_chunks = wrap_terminal_text(message, width);
            for chunk in &header_chunks {
                write!(writer, "{chunk}\r\n").map_err(terminal_issue)?;
            }
            let mut rendered_option_lines = 0usize;
            for (index, choice) in choices.iter().enumerate() {
                let marker = if index == selected { "> " } else { "  " };
                let chunks = wrap_terminal_text(choice, wrap_width);
                rendered_option_lines += chunks.len();
                let marker = crate::common::output::styled(
                    marker,
                    crate::common::output::Style::BoldCyan,
                    output.diagnostic_format().color,
                );
                if let Some((first, rest)) = chunks.split_first() {
                    write!(writer, "{marker}{first}\r\n").map_err(terminal_issue)?;
                    for chunk in rest {
                        write!(writer, "  {chunk}\r\n").map_err(terminal_issue)?;
                    }
                }
            }
            let hint_chunks = wrap_terminal_text("  ↑↓ move · Enter select · Esc cancel", width);
            for chunk in &hint_chunks {
                let hint = crate::common::output::styled(
                    chunk,
                    crate::common::output::Style::Cyan,
                    output.diagnostic_format().color,
                );
                write!(writer, "{hint}\r\n").map_err(terminal_issue)?;
            }
            writer.flush().map_err(terminal_issue)?;
            rendered_lines = header_chunks.len() + rendered_option_lines + hint_chunks.len();

            while !event::poll(
                Duration::from_millis(50)
                    .min(execution.deadline.saturating_duration_since(Instant::now())),
            )
            .map_err(terminal_issue)?
            {
                execution.check().map_err(IssueError::from)?;
            }
            execution.check().map_err(IssueError::from)?;
            let Event::Key(key) = event::read().map_err(terminal_issue)? else {
                continue;
            };
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match key.code {
                KeyCode::Esc => return Ok(None),
                KeyCode::Char('c' | 'C') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Err(IssueError::Cancelled);
                }
                KeyCode::Enter => return Ok(Some(selected)),
                KeyCode::Up => selected = selected.checked_sub(1).unwrap_or(choices.len() - 1),
                KeyCode::Down => selected = (selected + 1) % choices.len(),
                KeyCode::Char(digit @ '1'..='9') => {
                    let index = digit
                        .to_digit(10)
                        .map_or(choices.len(), |value| value as usize - 1);
                    if index < choices.len() {
                        selected = index;
                    }
                }
                _ => {}
            }
        }
    })();
    let newline = write!(writer, "\r\n").and_then(|()| writer.flush());
    let restored = raw_mode.restore();
    drop(raw_mode);
    match result {
        Err(error) => Err(error),
        Ok(selection) => {
            newline.map_err(terminal_issue)?;
            restored.map_err(terminal_issue)?;
            Ok(selection)
        }
    }
}

pub(crate) fn confirm_bounded(
    message: &str,
    default: bool,
    output: &crate::common::session::OutputSession,
    execution: &aster_acme::solver::ExecutionContext,
) -> Result<bool, aster_acme::issuance::IssueError> {
    let choices = if default {
        vec!["Yes (default)".to_owned(), "No".to_owned()]
    } else {
        vec!["Yes".to_owned(), "No (default)".to_owned()]
    };
    let starting_cursor = usize::from(!default);
    match select_index_or_back_bounded(message, &choices, starting_cursor, output, execution)? {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        Some(_) | None => Err(aster_acme::issuance::IssueError::Cancelled),
    }
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

/// Prompt for a secret without echo. The value stays in `Zeroizing` memory and
/// is used for this run only; it is never persisted or logged.
///
/// # Errors
/// Reports prompt failures; Ctrl-C is a user cancellation.
pub(crate) fn password_prompt(
    message: &str,
    output: &crate::common::session::OutputSession,
) -> CliResult<zeroize::Zeroizing<String>> {
    output.interaction_started();
    let password = inquire::Password::new(message)
        .with_render_config(prompt_style(output.diagnostic_format().color, false));
    prompt_result(password.prompt()).map(zeroize::Zeroizing::new)
}

/// Follow the Drive confirmation policy: default no, explicit opt-in for automation.
/// JSON mode never prompts, even when attached to a terminal.
pub(crate) fn confirm_write(
    message: &str,
    yes: bool,
    output: &crate::common::session::OutputSession,
) -> CliResult<()> {
    confirm_with(
        message,
        yes,
        output.is_json(),
        io::stdin().is_terminal() && io::stderr().is_terminal(),
        |message| {
            output.interaction_started();
            prompt_result(
                inquire::Confirm::new(message)
                    .with_default(false)
                    .with_render_config(prompt_style(output.diagnostic_format().color, false))
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
    output: &crate::common::session::OutputSession,
) -> CliResult<()> {
    if yes {
        return Ok(());
    }
    if !interactive(output.is_json()) {
        return Err(format!(
            "{details}\nThis operation requires confirmation; use --yes in automation."
        )
        .into());
    }
    output.context(&crate::common::output::confirmation(
        details,
        output.diagnostic_format().color,
    ));
    let accepted = prompt_result(
        inquire::Confirm::new(question)
            .with_default(false)
            .with_render_config(prompt_style(output.diagnostic_format().color, true))
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
    use crate::common::terminal::*;

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
