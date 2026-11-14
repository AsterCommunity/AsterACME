//! Bounded concurrent output capture and process-tree ownership for reload commands.
use crate::commands::cert::{
    deployment::record_event, progress::Progress, report::DeploymentEvent,
};
use crate::common::output::MessageKind;
use std::fmt::Write as _;
use std::{
    io,
    process::ExitStatus,
    sync::{Arc, Mutex},
    time::Duration,
};

const MAX_OUTPUT: usize = 64 * 1024;

pub(super) struct ReloadResult {
    pub(super) status: io::Result<ExitStatus>,
    pub(super) timed_out: bool,
    pub(super) started: bool,
}

pub(super) async fn run(
    command: &[String],
    timeout: Duration,
    id: &str,
    attempt: u8,
    events: &mut Vec<DeploymentEvent>,
    progress: Option<&Progress>,
    execution: Option<&crate::commands::cert::deployment::execution::Execution>,
) -> ReloadResult {
    if execution.is_some_and(|execution| execution.check().is_err()) {
        return ReloadResult {
            status: Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "reload cancelled before process startup",
            )),
            timed_out: false,
            started: false,
        };
    }
    let mut spec = aster_acme_process::ProcessSpec::new(&command[0], timeout);
    spec.args = command[1..].iter().cloned().map(Into::into).collect();
    spec.stdout_limit = MAX_OUTPUT;
    spec.stderr_limit = MAX_OUTPUT;
    if let Some(deadline) = execution.and_then(|execution| execution.deadline) {
        spec.timeout = spec
            .timeout
            .min(deadline.saturating_duration_since(std::time::Instant::now()));
    }
    let stdout_text = Arc::new(Mutex::new(StreamText::default()));
    let stderr_text = Arc::new(Mutex::new(StreamText::default()));
    let stdout_callback = stdout_text.clone();
    let stderr_callback = stderr_text.clone();
    let cancellation = execution
        .map_or_else(tokio_util::sync::CancellationToken::new, |execution| {
            execution.cancellation.clone()
        });
    let outcome = aster_acme_process::run(spec, &cancellation, |stream, bytes| {
        let (text, name) = match stream {
            aster_acme_process::ProcessStream::Stdout => (&stdout_callback, "stdout"),
            aster_acme_process::ProcessStream::Stderr => (&stderr_callback, "stderr"),
        };
        if let Ok(mut text) = text.lock() {
            stream_output(&text.push(bytes, false), id, attempt, name, progress);
        }
    })
    .await;
    for (text, name) in [(&stdout_text, "stdout"), (&stderr_text, "stderr")] {
        if let Ok(mut text) = text.lock() {
            stream_output(&text.push(&[], true), id, attempt, name, progress);
        }
    }
    let (status, timed_out) = classify(outcome.status);
    for (stream, captured) in [("stdout", outcome.stdout), ("stderr", outcome.stderr)] {
        if captured.truncated
            && let Some(progress) = progress
        {
            progress.output.progress(
                MessageKind::Warning,
                &format!("Deployment '{id}' reload {stream} output truncated at 64 KiB"),
            );
        }
        let mut text = String::from_utf8_lossy(&captured.bytes).into_owned();
        if captured.truncated {
            text.push_str("\n[output truncated at 64 KiB]");
        }
        if let Some(error) = captured.read_error {
            let _ = write!(text, "\n[output read failed: {error}]");
        }
        if !text.is_empty() {
            // The explicit command streamed these bytes already; automatic deployment
            // renders the same bounded capture after the issuance summary.
            record_event(
                events,
                MessageKind::Info,
                &format!("Deployment '{id}' reload attempt {attempt} {stream}:\n{text}"),
                None,
            );
        }
    }
    ReloadResult {
        status,
        timed_out,
        started: outcome.started,
    }
}

fn classify(
    status: Result<ExitStatus, aster_acme_process::ProcessFailure>,
) -> (io::Result<ExitStatus>, bool) {
    match status {
        Ok(status) => (Ok(status), false),
        Err(
            aster_acme_process::ProcessFailure::Spawn(error)
            | aster_acme_process::ProcessFailure::Wait(error),
        ) => (Err(error), false),
        Err(aster_acme_process::ProcessFailure::CancelledBeforeStart) => (
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "reload cancelled before process startup",
            )),
            false,
        ),
        Err(aster_acme_process::ProcessFailure::Cancelled) => (
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "reload cancelled after process startup",
            )),
            true,
        ),
        Err(aster_acme_process::ProcessFailure::TimedOut) => (
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "reload deadline exceeded",
            )),
            true,
        ),
    }
}

/// Keep an incomplete UTF-8 suffix across reads; only invalid sequences are
/// replaced. A valid multibyte character split by the pipe stays intact.
#[derive(Default)]
struct StreamText(Vec<u8>);
impl StreamText {
    fn push(&mut self, bytes: &[u8], eof: bool) -> String {
        self.0.extend_from_slice(bytes);
        let mut text = String::new();
        let mut consumed = 0;
        while consumed < self.0.len() {
            match std::str::from_utf8(&self.0[consumed..]) {
                Ok(valid) => {
                    text.push_str(valid);
                    consumed = self.0.len();
                }
                Err(error) => {
                    let end = consumed + error.valid_up_to();
                    text.push_str(&String::from_utf8_lossy(&self.0[consumed..end]));
                    consumed = end;
                    match error.error_len() {
                        Some(length) => {
                            text.push('\u{fffd}');
                            consumed += length;
                        }
                        None if eof => {
                            text.push('\u{fffd}');
                            consumed = self.0.len();
                        }
                        None => break,
                    }
                }
            }
        }
        self.0.drain(..consumed);
        text
    }
}

fn stream_output(text: &str, id: &str, attempt: u8, stream: &str, progress: Option<&Progress>) {
    if !text.is_empty()
        && let Some(progress) = progress
    {
        progress.output.details(
            MessageKind::Info,
            &format!("Deployment '{id}' reload attempt {attempt} {stream}:"),
            &text.lines().map(str::to_owned).collect::<Vec<_>>(),
        );
    }
}

#[cfg(test)]
mod tests;
