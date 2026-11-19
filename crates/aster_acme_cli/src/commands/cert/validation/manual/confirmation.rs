//! A scoped terminal reader owns raw mode and polls interruption while idle.
use aster_acme::{issuance::IssueError, solver::ExecutionContext};
use crossterm::{
    cursor::{MoveLeft, MoveToColumn},
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
    terminal::{self, Clear, ClearType},
};
use std::{
    io::{self, Write},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const POLL_INTERVAL: Duration = Duration::from_millis(50);

struct Terminal {
    restore_raw: bool,
    bracketed_paste: bool,
}
impl Terminal {
    fn open() -> io::Result<Self> {
        let restore_raw = !terminal::is_raw_mode_enabled()?;
        if restore_raw {
            terminal::enable_raw_mode()?;
        }
        let mut terminal = Self {
            restore_raw,
            bracketed_paste: true,
        };
        if let Err(error) = crossterm::execute!(io::stderr(), EnableBracketedPaste) {
            let _ = terminal.restore();
            return Err(error);
        }
        Ok(terminal)
    }

    fn restore(&mut self) -> io::Result<()> {
        let paste = if self.bracketed_paste {
            crossterm::execute!(io::stderr(), DisableBracketedPaste)
                .inspect(|()| self.bracketed_paste = false)
        } else {
            Ok(())
        };
        if self.restore_raw {
            terminal::disable_raw_mode()?;
            self.restore_raw = false;
        }
        paste
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn check(execution: &ExecutionContext, stop: &CancellationToken) -> Result<(), IssueError> {
    execution.check().map_err(IssueError::from)?;
    if stop.is_cancelled() {
        return Err(IssueError::Cancelled);
    }
    Ok(())
}

fn terminal_error(error: &io::Error) -> IssueError {
    IssueError::Publication(format!("confirmation terminal failed: {error}"))
}

pub(super) fn confirm(
    question: &str,
    execution: &ExecutionContext,
    stop: &CancellationToken,
) -> Result<bool, IssueError> {
    check(execution, stop)?;
    let mut terminal = Terminal::open().map_err(|error| terminal_error(&error))?;
    let mut output = io::stderr();
    let result = read_answer(question, execution, stop, &mut output);
    // End the active prompt even when cancellation or I/O interrupts it. The
    // same reader thread restores terminal mode before the worker is joined.
    let newline = write!(output, "\r\n").and_then(|()| output.flush());
    terminal.restore().map_err(|error| terminal_error(&error))?;
    match result {
        Ok(answer) => {
            newline.map_err(|error| terminal_error(&error))?;
            Ok(answer)
        }
        Err(error) => Err(error),
    }
}

fn read_answer(
    question: &str,
    execution: &ExecutionContext,
    stop: &CancellationToken,
    output: &mut impl Write,
) -> Result<bool, IssueError> {
    let mut input = AnswerInput::default();
    loop {
        check(execution, stop)?;
        crossterm::queue!(output, MoveToColumn(0), Clear(ClearType::UntilNewLine))
            .map_err(|error| terminal_error(&error))?;
        write!(output, "> {question} (y/N) {}", input.text)
            .map_err(|error| terminal_error(&error))?;
        let trailing = u16::try_from(input.text.len() - input.cursor)
            .map_err(|_| IssueError::InvalidInput("confirmation input is too long"))?;
        if trailing > 0 {
            crossterm::queue!(output, MoveLeft(trailing))
                .map_err(|error| terminal_error(&error))?;
        }
        output.flush().map_err(|error| terminal_error(&error))?;
        // poll/read are paired on this one thread, with a bounded poll even
        // when the terminal has no input. No other task reads terminal events.
        while !event::poll(
            POLL_INTERVAL.min(
                execution
                    .deadline
                    .saturating_duration_since(std::time::Instant::now()),
            ),
        )
        .map_err(|error| terminal_error(&error))?
        {
            check(execution, stop)?;
        }
        check(execution, stop)?;
        let key = match event::read().map_err(|error| terminal_error(&error))? {
            Event::Key(key) => key,
            Event::Paste(text) => {
                input.paste(&text);
                continue;
            }
            _ => continue,
        };
        match input.key(key) {
            AnswerAction::Cancel => {
                execution.cancellation.cancel();
                return Err(IssueError::Cancelled);
            }
            AnswerAction::Accepted(answer) => {
                check(execution, stop)?;
                crossterm::queue!(output, MoveToColumn(0), Clear(ClearType::UntilNewLine))
                    .map_err(|error| terminal_error(&error))?;
                write!(output, "> {question} {}", if answer { "Yes" } else { "No" })
                    .map_err(|error| terminal_error(&error))?;
                return Ok(answer);
            }
            AnswerAction::Continue => {}
        }
    }
}

#[derive(Default)]
struct AnswerInput {
    text: String,
    cursor: usize,
}
#[derive(Debug, PartialEq, Eq)]
enum AnswerAction {
    Accepted(bool),
    Cancel,
    Continue,
}
impl AnswerInput {
    fn paste(&mut self, text: &str) {
        for character in text.chars() {
            // Pasted line endings are input, never synthetic Enter events.
            let _ = self.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
    }

    fn key(&mut self, key: KeyEvent) -> AnswerAction {
        if key.kind == KeyEventKind::Release {
            return AnswerAction::Continue;
        }
        if key.code == KeyCode::Esc
            || (matches!(key.code, KeyCode::Char('c' | 'C'))
                && key.modifiers.contains(KeyModifiers::CONTROL))
        {
            return AnswerAction::Cancel;
        }
        match key.code {
            KeyCode::Enter => {
                let answer = if self.text.is_empty() {
                    Ok(false)
                } else {
                    inquire::parser::DEFAULT_BOOL_PARSER(&self.text)
                };
                if let Ok(answer) = answer {
                    return AnswerAction::Accepted(answer);
                }
            }
            KeyCode::Backspace if self.cursor > 0 => {
                self.cursor -= 1;
                self.text.remove(self.cursor);
            }
            KeyCode::Delete if self.cursor < self.text.len() => {
                self.text.remove(self.cursor);
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.text.len()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.text.len(),
            KeyCode::Char(character)
                if (character.is_ascii_graphic() || character == ' ')
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                    && self.text.len() < 8 =>
            {
                self.text.insert(self.cursor, character);
                self.cursor += 1;
            }
            _ => {}
        }
        AnswerAction::Continue
    }
}

#[cfg(test)]
mod tests;
