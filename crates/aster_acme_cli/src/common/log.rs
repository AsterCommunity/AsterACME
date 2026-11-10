//! Shared human CLI logging: fixed UTC timestamps, aligned levels and detail rows.
//! Structured command results belong to command renderers; JSON disables this sink.
use super::output;
use crate::common::output::Style;
use std::io::{self, IsTerminal};

#[derive(Clone, Copy)]
pub(crate) enum Level {
    Info,
    Wait,
    Success,
    Warning,
}

pub(crate) struct Log {
    pub(crate) enabled: bool,
    color: bool,
}
impl Log {
    pub(crate) fn new(json: bool) -> Self {
        Self {
            enabled: !json,
            color: output::colors(io::stderr().is_terminal()),
        }
    }

    pub(crate) fn line(&self, level: Level, message: &str) {
        self.details(level, message, &[]);
    }

    pub(crate) fn details(&self, level: Level, message: &str, details: &[String]) {
        if self.enabled {
            eprintln!(
                "{}",
                render(
                    level,
                    message,
                    details,
                    time::OffsetDateTime::now_utc(),
                    self.color
                )
            );
        }
    }
}

// Pad the plain prefix before styling. Time, labels and continuation rows share one
// visible column even when the terminal uses ANSI colors or timestamps had subseconds.
fn render(
    level: Level,
    message: &str,
    details: &[String],
    at: time::OffsetDateTime,
    color: bool,
) -> String {
    let (label, style) = match level {
        Level::Info => ("[INFO]", Style::Cyan),
        Level::Wait => ("[WAIT]", Style::Yellow),
        Level::Success => ("[OK]", Style::BoldGreen),
        Level::Warning => ("[WARN]", Style::Yellow),
    };
    let timestamp = crate::common::time::timestamp(Some(at));
    let padding = " ".repeat(6 - label.len());
    let prefix = format!(
        "[{timestamp}] {}{padding} ",
        output::styled(label, style, color)
    );
    let indent = " ".repeat(timestamp.len() + 10);
    let mut output = format!("{prefix}{}", output::safe(message));
    for detail in details {
        output.push('\n');
        output.push_str(&indent);
        output.push_str(&output::safe(detail));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn time_label_and_continuation_columns_are_fixed_and_terminal_controls_escaped() {
        let at = time::OffsetDateTime::from_unix_timestamp(0)
            .unwrap()
            .replace_nanosecond(123_456_000)
            .unwrap();
        for level in [Level::Info, Level::Success, Level::Wait, Level::Warning] {
            let text = render(level, "message", &["detail".into()], at, false);
            let mut lines = text.lines();
            let first = lines.next().unwrap();
            let detail = lines.next().unwrap();
            assert!(first.starts_with("[1970-01-01 00:00:00 UTC] "));
            assert_eq!(first.find("message"), Some(33));
            assert_eq!(detail.find("detail"), Some(33));
            assert!(!text.contains('\x1b'));
            let colored = render(level, "message", &[], at, true);
            assert!(colored.contains('\x1b'));
            assert_eq!(
                colored
                    .replace("\x1b[36m", "")
                    .replace("\x1b[33m", "")
                    .replace("\x1b[1;32m", "")
                    .replace("\x1b[0m", ""),
                first
            );
        }
        let text = render(
            Level::Warning,
            "bad\x1b[2J",
            &["line\nnext".into()],
            at,
            false,
        );
        assert!(!text.contains('\x1b'));
        assert!(text.contains("\\n"));
    }
}
