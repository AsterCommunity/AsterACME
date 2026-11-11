//! Output lifecycle tests with isolated sinks: no globals or real terminal writes.
use super::*;

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);
impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Buffer {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn session(json: bool) -> (OutputSession, Buffer, Buffer) {
    let stdout = Buffer::default();
    let stderr = Buffer::default();
    (
        OutputSession::with_writers(
            Box::new(stdout.clone()),
            Box::new(stderr.clone()),
            Format::plain(json),
            Format::plain(json),
        ),
        stdout,
        stderr,
    )
}

#[test]
fn no_progress_has_no_separator_but_shared_progress_gets_exactly_one_blank_line() {
    let (output, stdout, stderr) = session(false);
    output.finish("report", FinalChannel::Result).unwrap();
    assert_eq!(stdout.text(), "report\n");
    assert_eq!(stderr.text(), "");
    assert!(output.finish("duplicate", FinalChannel::Result).is_err());
    let (output, stdout, stderr) = session(false);
    output.clone().progress(MessageKind::Info, "checking");
    output.progress(MessageKind::Warning, "pending");
    output.finish("report", FinalChannel::Result).unwrap();
    assert_eq!(stdout.text(), "report\n");
    assert!(stderr.text().ends_with("pending\n\n"));
    output.progress(MessageKind::Info, "too late");
    assert!(!stderr.text().contains("too late"));
}

#[test]
fn json_suppresses_progress_and_context_and_error_is_one_structured_document() {
    let (output, stdout, stderr) = session(true);
    output.progress(MessageKind::Info, "hidden");
    output.context("hidden confirmation");
    output
        .finish("{\"status\":\"partial_failure\"}", FinalChannel::Result)
        .unwrap();
    assert_eq!(stdout.text(), "{\"status\":\"partial_failure\"}\n");
    assert_eq!(stderr.text(), "");
    let (output, stdout, stderr) = session(true);
    output
        .finish(
            "{\"error\":{\"message\":\"cancelled\"}}",
            FinalChannel::Diagnostic,
        )
        .unwrap();
    assert_eq!(stdout.text(), "");
    assert!(serde_json::from_str::<serde_json::Value>(&stderr.text()).is_ok());
    assert!(
        output
            .finish("duplicate", FinalChannel::Diagnostic)
            .is_err()
    );
}

struct Failing;
impl Write for Failing {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn output_failures_are_returned_without_a_second_attempt_or_panic() {
    let output = OutputSession::with_writers(
        Box::new(Failing),
        Box::new(io::sink()),
        Format::plain(false),
        Format::plain(false),
    );
    assert!(output.finish("report", FinalChannel::Result).is_err());
    assert!(output.finish("error", FinalChannel::Diagnostic).is_err());
    let output = OutputSession::with_writers(
        Box::new(io::sink()),
        Box::new(Failing),
        Format::plain(false),
        Format::plain(false),
    );
    output.progress(MessageKind::Info, "will fail");
    assert!(output.finish("report", FinalChannel::Result).is_err());
}

#[test]
fn result_and_diagnostic_formats_are_independent_and_prompts_count_as_output() {
    let stdout = Buffer::default();
    let stderr = Buffer::default();
    let output = OutputSession::with_writers(
        Box::new(stdout.clone()),
        Box::new(stderr.clone()),
        Format::plain(false),
        Format {
            json: false,
            color: true,
        },
    );
    output.progress(MessageKind::Warning, "review");
    output
        .finish(
            &MessageKind::Done.badge(output.format().color),
            FinalChannel::Result,
        )
        .unwrap();
    assert!(stderr.text().contains("\x1b["));
    assert_eq!(stdout.text(), "[DONE]\n");
    let (output, _, stderr) = session(false);
    output.interaction_started();
    output
        .finish("cancelled", FinalChannel::Diagnostic)
        .unwrap();
    assert_eq!(stderr.text(), "\ncancelled\n");
}

#[test]
fn tracing_respects_json_and_finalization_and_concurrent_progress_is_not_interleaved() {
    use tracing_subscriber::fmt::MakeWriter;
    for json in [false, true] {
        let (output, stdout, stderr) = session(json);
        let mut writer = output.make_writer();
        writer.write_all(b"diagnostic\n").unwrap();
        let threads = (0..8)
            .map(|index| {
                let output = output.clone();
                std::thread::spawn(move || {
                    output.progress(MessageKind::Info, &format!("worker-{index}"));
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        output.finish("{}", FinalChannel::Result).unwrap();
        writer.write_all(b"late\n").unwrap();
        assert_eq!(stdout.text(), "{}\n");
        if json {
            assert_eq!(stderr.text(), "");
        } else {
            let text = stderr.text();
            assert!(text.starts_with("diagnostic\n"));
            assert!(text.ends_with("\n\n"));
            assert!(!text.contains("late"));
            for index in 0..8 {
                assert_eq!(
                    text.matches(&format!("[INFO]  worker-{index}\n")).count(),
                    1
                );
            }
        }
    }
}

#[test]
fn partially_failed_account_report_is_one_json_document_with_failure_disposition() {
    use crate::{
        commands::account::report::{AccountReport, AccountVerification},
        dispatch::CommandReport,
    };
    let report = CommandReport::Account(Box::new(AccountReport::List {
        accounts: vec![],
        default: "default".into(),
        verification: Some(vec![AccountVerification {
            name: "offline".into(),
            status: None,
            error: Some("CA unavailable".into()),
        }]),
    }));
    let (output, stdout, stderr) = session(true);
    assert_eq!(report.exit_status(), ExitStatus::Failed);
    output
        .finish(
            &report.render(output.format()).unwrap(),
            FinalChannel::Result,
        )
        .unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&stdout.text()).is_ok());
    assert_eq!(stderr.text(), "");
}

#[test]
fn panic_delivery_never_waits_for_a_held_lock_and_can_finish_a_poisoned_session() {
    let (output, stdout, stderr) = session(true);
    let guard = output.state.lock().unwrap();
    assert_eq!(
        output.panic_notice("safe hint").unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(guard);
    let cloned = output.clone();
    let _ = std::panic::catch_unwind(move || {
        let _guard = cloned.state.lock().unwrap();
        panic!("test-only poisoned writer");
    });
    output.panic_notice("safe hint").unwrap();
    output.panic_notice("duplicate").unwrap();
    let json: serde_json::Value = serde_json::from_str(&stderr.text()).unwrap();
    assert_eq!(json["error"]["hint"], "safe hint");
    assert_eq!(stdout.text(), "");
    assert!(output.finish("duplicate", FinalChannel::Result).is_err());
}

#[test]
fn debug_events_share_progress_format_and_remain_suppressed_in_json() {
    for json in [false, true] {
        let (output, stdout, stderr) = session(json);
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .event_format(super::super::log::DiagnosticFormat { color: false })
            .with_writer(output.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(
                request_kind = "signed_post",
                status = 201_u16,
                has_location = true,
                "Response checkpoint"
            );
        });
        output.finish("{}", FinalChannel::Result).unwrap();
        assert_eq!(stdout.text(), "{}\n");
        let diagnostics = stderr.text();
        if json {
            assert_eq!(diagnostics, "");
        } else {
            assert!(diagnostics.contains("UTC] [DEBUG]"));
            assert!(
                diagnostics.contains("status=201") && diagnostics.contains("has_location=true")
            );
            assert!(!diagnostics.contains('\x1b'));
        }
    }
}
