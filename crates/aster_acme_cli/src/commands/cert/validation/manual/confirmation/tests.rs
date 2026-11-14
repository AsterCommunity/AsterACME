//! Input boundaries are checked without a terminal; PTY tests own real I/O.
use crate::commands::cert::validation::manual::confirmation::{
    AnswerAction, AnswerInput, check, confirm, read_answer,
};
use aster_acme::{issuance::IssueError, solver::ExecutionContext};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

fn press(input: &mut AnswerInput, code: KeyCode) -> AnswerAction {
    input.key(KeyEvent::new(code, KeyModifiers::NONE))
}
fn type_text(input: &mut AnswerInput, text: &str) {
    for character in text.chars() {
        assert_eq!(
            press(input, KeyCode::Char(character)),
            AnswerAction::Continue
        );
    }
}

#[test]
fn default_no_and_case_insensitive_answers_match_confirmation_policy() {
    for (text, expected) in [
        ("", false),
        ("y", true),
        ("YES", true),
        ("YeS", true),
        ("n", false),
        ("NO", false),
    ] {
        let mut input = AnswerInput::default();
        type_text(&mut input, text);
        assert_eq!(
            press(&mut input, KeyCode::Enter),
            AnswerAction::Accepted(expected)
        );
    }
    for invalid in [
        "ye", "maybe", "yess", "false", "true", "1", " y", "y ", "y1",
    ] {
        let mut input = AnswerInput::default();
        type_text(&mut input, invalid);
        assert_eq!(press(&mut input, KeyCode::Enter), AnswerAction::Continue);
    }
}

#[test]
fn editing_obeys_cursor_and_input_size_boundaries() {
    let mut input = AnswerInput::default();
    for code in [
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::Backspace,
        KeyCode::Delete,
    ] {
        press(&mut input, code);
        assert_eq!(input.cursor, 0);
        assert_eq!(input.text, "");
    }
    type_text(&mut input, "ys");
    press(&mut input, KeyCode::Left);
    type_text(&mut input, "e");
    assert_eq!(input.text, "yes");
    press(&mut input, KeyCode::Home);
    press(&mut input, KeyCode::Delete);
    assert_eq!(input.text, "es");
    press(&mut input, KeyCode::End);
    press(&mut input, KeyCode::Backspace);
    assert_eq!(input.text, "e");
    type_text(&mut input, "abcdefghijk");
    assert_eq!(input.text.len(), 8);
    assert_eq!(input.cursor, 8);
    press(&mut input, KeyCode::Right);
    assert_eq!(input.cursor, 8);
    press(&mut input, KeyCode::Backspace);
    type_text(&mut input, "z");
    assert!(input.text.ends_with('z'));
}

#[test]
fn terminal_shortcuts_release_events_and_non_ascii_do_not_become_answers() {
    let mut input = AnswerInput::default();
    for key in [
        KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL),
        KeyEvent::new(KeyCode::Char('y'), KeyModifiers::ALT),
        KeyEvent::new(KeyCode::Char('中'), KeyModifiers::NONE),
        KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
        KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release),
        KeyEvent::new_with_kind(KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Release),
    ] {
        assert_eq!(input.key(key), AnswerAction::Continue);
        assert_eq!(input.text, "");
    }
    for key in [
        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        KeyEvent::new(
            KeyCode::Char('C'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ),
    ] {
        assert_eq!(input.key(key), AnswerAction::Cancel);
    }
}

#[test]
fn pasted_newlines_never_submit_and_pasted_text_stays_bounded() {
    let mut input = AnswerInput::default();
    input.paste("yes\r\n");
    assert_eq!(input.text, "yes");
    assert_eq!(
        press(&mut input, KeyCode::Enter),
        AnswerAction::Accepted(true)
    );
    input.paste(&"x".repeat(1_024));
    assert_eq!(input.text.len(), 8);
    assert_eq!(press(&mut input, KeyCode::Enter), AnswerAction::Continue);
}

fn execution() -> ExecutionContext {
    ExecutionContext {
        cancellation: CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(5),
    }
}
#[test]
fn exact_deadline_cancellation_and_stop_reject_before_terminal_access() {
    for mode in ["deadline", "cancel", "stop"] {
        let mut execution = execution();
        let stop = CancellationToken::new();
        match mode {
            "deadline" => execution.deadline = Instant::now(),
            "cancel" => execution.cancellation.cancel(),
            _ => stop.cancel(),
        }
        assert!(matches!(
            check(&execution, &stop),
            Err(IssueError::Interrupted)
        ));
        assert!(matches!(
            confirm("test", &execution, &stop),
            Err(IssueError::Interrupted)
        ));
        assert!(matches!(
            read_answer("test", &execution, &stop, &mut io::sink()),
            Err(IssueError::Interrupted)
        ));
        assert_eq!(execution.cancellation.is_cancelled(), mode == "cancel");
    }
}

struct FailingOutput {
    flush_only: bool,
}
impl Write for FailingOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.flush_only {
            Ok(bytes.len())
        } else {
            Err(io::Error::other("injected write error"))
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("injected flush error"))
    }
}
#[test]
fn output_write_and_flush_failures_are_publication_errors() {
    for flush_only in [false, true] {
        let error = read_answer(
            "test",
            &execution(),
            &CancellationToken::new(),
            &mut FailingOutput { flush_only },
        )
        .unwrap_err();
        assert!(matches!(error, IssueError::Publication(_)));
    }
}
