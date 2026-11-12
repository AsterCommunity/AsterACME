//! Shared human CLI logging: fixed UTC timestamps, aligned levels and detail rows.
//! Structured command results belong to command renderers; JSON disables this sink.
use crate::common::output;
use crate::common::output::MessageKind;

// Pad the plain prefix before styling. Time, labels and continuation rows share one
// visible column even when the terminal uses ANSI colors or timestamps had subseconds.
pub(crate) fn render(
    level: MessageKind,
    message: &str,
    details: &[String],
    at: time::OffsetDateTime,
    color: bool,
) -> String {
    let label = level.label();
    let timestamp = crate::common::time::timestamp(Some(at));
    let padding = " ".repeat(7 - label.len());
    let prefix = format!("[{timestamp}] {}{padding} ", level.badge(color));
    let indent = " ".repeat(timestamp.len() + 11);
    let mut output = format!("{prefix}{}", output::safe(message));
    for detail in details {
        output.push('\n');
        output.push_str(&indent);
        output.push_str(&output::safe(detail));
    }
    output
}

/// Tracing diagnostics use the same palette, UTC timestamp and escaping as progress.
/// The --debug filter enables only product targets; no HTTP bodies or credentials
/// are recorded by the instrumentation. JSON suppression belongs to `OutputSession`.
pub(crate) struct DiagnosticFormat {
    pub(crate) color: bool,
}
impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for DiagnosticFormat
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _context: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let mut fields = DiagnosticFields::default();
        event.record(&mut fields);
        let kind = match *event.metadata().level() {
            tracing::Level::TRACE | tracing::Level::DEBUG => MessageKind::Debug,
            tracing::Level::INFO => MessageKind::Info,
            tracing::Level::WARN => MessageKind::Warning,
            tracing::Level::ERROR => MessageKind::Error,
        };
        let message = format!("{}: {}", event.metadata().target(), fields.values.join(" "));
        writeln!(
            writer,
            "{}",
            render(
                kind,
                &message,
                &[],
                time::OffsetDateTime::now_utc(),
                self.color
            )
        )
    }
}
#[derive(Default)]
struct DiagnosticFields {
    values: Vec<String>,
}
impl tracing::field::Visit for DiagnosticFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.values.push(format!("{value:?}"));
        } else {
            self.values.push(format!("{}={value:?}", field.name()));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::log::*;
    #[test]
    fn time_label_and_continuation_columns_are_fixed_and_terminal_controls_escaped() {
        let at = time::OffsetDateTime::from_unix_timestamp(0)
            .unwrap()
            .replace_nanosecond(123_456_000)
            .unwrap();
        for level in [
            MessageKind::Debug,
            MessageKind::Error,
            MessageKind::Done,
            MessageKind::Info,
            MessageKind::Success,
            MessageKind::Wait,
            MessageKind::Warning,
        ] {
            let text = render(level, "message", &["detail".into()], at, false);
            let mut lines = text.lines();
            let first = lines.next().unwrap();
            let detail = lines.next().unwrap();
            assert!(first.starts_with("[1970-01-01 00:00:00 UTC] "));
            assert_eq!(first.find("message"), Some(34));
            assert_eq!(detail.find("detail"), Some(34));
            assert!(!text.contains('\x1b'));
            let colored = render(level, "message", &[], at, true);
            assert!(colored.contains('\x1b'));
            assert_eq!(
                colored
                    .replace("\x1b[34m", "")
                    .replace("\x1b[1;31m", "")
                    .replace("\x1b[36m", "")
                    .replace("\x1b[33m", "")
                    .replace("\x1b[1;32m", "")
                    .replace("\x1b[0m", ""),
                first
            );
        }
        let text = render(
            MessageKind::Warning,
            "bad\x1b[2J",
            &["line\nnext".into()],
            at,
            false,
        );
        assert!(!text.contains('\x1b'));
        assert!(text.contains("\\n"));
    }
}
