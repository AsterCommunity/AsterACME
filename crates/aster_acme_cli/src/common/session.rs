//! Command-scoped output lifecycle. Clones share progress, errors and exactly one final report.
use super::{log, output, output::MessageKind};
use std::{
    io::{self, IsTerminal, Write},
    sync::{Arc, Mutex},
};

/// Presentation is explicit at the rendering boundary; no renderer probes terminals.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Format {
    pub(crate) json: bool,
    pub(crate) color: bool,
}
impl Format {
    pub(crate) const fn plain(json: bool) -> Self {
        Self { json, color: false }
    }
}

#[derive(Clone)]
pub(crate) struct OutputSession {
    state: Arc<Mutex<State>>,
    result_format: Format,
    diagnostic_format: Format,
}
struct State {
    stdout: Box<dyn Write + Send>,
    stderr: Box<dyn Write + Send>,
    progress: bool,
    finished: bool,
    error: Option<io::Error>,
}

impl OutputSession {
    pub(crate) fn new(json: bool) -> Self {
        Self::with_writers(
            Box::new(io::stdout()),
            Box::new(io::stderr()),
            Format {
                color: !json && output::colors(io::stdout().is_terminal()),
                ..Format::plain(json)
            },
            Format {
                json,
                color: !json && output::colors(io::stderr().is_terminal()),
            },
        )
    }

    fn with_writers(
        stdout: Box<dyn Write + Send>,
        stderr: Box<dyn Write + Send>,
        result_format: Format,
        diagnostic_format: Format,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                stdout,
                stderr,
                progress: false,
                finished: false,
                error: None,
            })),
            result_format,
            diagnostic_format,
        }
    }

    pub(crate) const fn format(&self) -> Format {
        self.result_format
    }
    pub(crate) const fn diagnostic_format(&self) -> Format {
        self.diagnostic_format
    }
    pub(crate) const fn is_json(&self) -> bool {
        self.result_format.json
    }

    pub(crate) fn progress(&self, level: MessageKind, message: &str) {
        self.details(level, message, &[]);
    }

    pub(crate) fn details(&self, level: MessageKind, message: &str, details: &[String]) {
        if self.is_json() {
            return;
        }
        let text = log::render(
            level,
            message,
            details,
            time::OffsetDateTime::now_utc(),
            self.diagnostic_format.color,
        );
        self.context(&text);
    }

    pub(crate) fn interaction_started(&self) {
        if self.is_json() {
            return;
        }
        if let Ok(mut state) = self.state.lock()
            && !state.finished
        {
            state.progress = true;
        }
    }

    /// Prompts and validation notices share stderr ownership with progress. Text is
    /// already rendered by trusted presentation helpers; untrusted fields are escaped there.
    pub(crate) fn context(&self, text: &str) {
        if self.is_json() {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            if state.finished {
                return;
            }
            let result = writeln!(state.stderr, "{text}").and_then(|()| state.stderr.flush());
            match result {
                Ok(()) => state.progress = true,
                Err(error) => state.error = Some(error),
            }
        }
    }

    /// A hook may run while this very thread owns the output lock. Never wait
    /// for it or expose raw panic data; main still observes the atomic panic flag.
    pub(crate) fn panic_notice(&self, hint: &str) -> io::Result<()> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "output busy"));
            }
        };
        if state.finished {
            return Ok(());
        }
        state.finished = true;
        let message = "Unexpected internal error; the operation may be incomplete.";
        if self.is_json() {
            let text = serde_json::to_string(&super::error::ErrorOutput {
                error: super::error::Diagnostic {
                    message,
                    hint: Some(hint),
                },
            })?;
            writeln!(state.stderr, "{text}")?;
        } else {
            if state.progress {
                writeln!(state.stderr)?;
            }
            writeln!(
                state.stderr,
                "{} {}\n{}",
                MessageKind::Error.badge(self.diagnostic_format.color),
                message,
                output::tips(hint, self.diagnostic_format.color)
            )?;
        }
        state.stderr.flush()
    }

    /// The root command owns finalization. A failed report write is not followed by
    /// another JSON document, and errors from detached progress writers remain observable.
    pub(crate) fn finish(&self, text: &str, channel: FinalChannel) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("output session lock poisoned"))?;
        if state.finished {
            return Err(io::Error::other("output session already finalized"));
        }
        state.finished = true;
        if let Some(error) = state.error.take() {
            return Err(error);
        }
        if state.progress && !self.is_json() {
            writeln!(state.stderr)?;
        }
        match channel {
            FinalChannel::Result => {
                writeln!(state.stdout, "{text}").and_then(|()| state.stdout.flush())
            }
            FinalChannel::Diagnostic => {
                writeln!(state.stderr, "{text}").and_then(|()| state.stderr.flush())
            }
        }
    }
}

/// Route tracing diagnostics through the same lifetime and channel policy. A writer
/// holds only the shared handle, so subscriber internals cannot finalize a command.
pub(crate) struct DiagnosticWriter(OutputSession);
impl Write for DiagnosticWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.is_json() {
            return Ok(bytes.len());
        }
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("output session lock poisoned"))?;
        if state.finished {
            return Ok(bytes.len());
        }
        match state.stderr.write(bytes) {
            Ok(written) => {
                state.progress |= written > 0;
                Ok(written)
            }
            Err(error) => {
                state.error = Some(io::Error::new(error.kind(), "diagnostic output failed"));
                Err(error)
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| io::Error::other("output session lock poisoned"))?;
        state.stderr.flush()
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for OutputSession {
    type Writer = DiagnosticWriter;
    fn make_writer(&'a self) -> Self::Writer {
        DiagnosticWriter(self.clone())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FinalChannel {
    Result,
    Diagnostic,
}

/// Process disposition belongs to the typed report, not an error used as an output signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitStatus {
    Success,
    Failed,
    Cancelled,
}
impl ExitStatus {
    pub(crate) fn code(self) -> std::process::ExitCode {
        match self {
            Self::Success => std::process::ExitCode::SUCCESS,
            Self::Failed => std::process::ExitCode::FAILURE,
            Self::Cancelled => std::process::ExitCode::from(130),
        }
    }
}

#[cfg(test)]
mod tests;
