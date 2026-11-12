//! Bounded concurrent output capture and process-tree ownership for reload commands.
use crate::commands::cert::{
    deployment::record_event, progress::Progress, report::DeploymentEvent,
};
use crate::common::output::MessageKind;
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use std::fmt::Write as _;
use std::{
    io,
    process::{ExitStatus, Stdio},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt as _};

const MAX_OUTPUT: usize = 64 * 1024;

pub(super) struct ReloadResult {
    pub(super) status: io::Result<ExitStatus>,
    pub(super) timed_out: bool,
}

struct ProcessTree(Box<dyn ChildWrapper>);
impl Drop for ProcessTree {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

pub(super) async fn run(
    command: &[String],
    timeout: Duration,
    id: &str,
    attempt: u8,
    events: &mut Vec<DeploymentEvent>,
    progress: Option<&Progress>,
) -> ReloadResult {
    let mut wrapped = CommandWrap::with_new(&command[0], |process| {
        process
            .args(&command[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    });
    wrapped.wrap(KillOnDrop);
    #[cfg(unix)]
    wrapped.wrap(process_wrap::tokio::ProcessGroup::leader());
    #[cfg(windows)]
    wrapped.wrap(process_wrap::tokio::JobObject);
    let child = match wrapped.spawn() {
        Ok(child) => child,
        Err(error) => {
            return ReloadResult {
                status: Err(error),
                timed_out: false,
            };
        }
    };
    let mut child = ProcessTree(child);
    let stdout = child.0.stdout().take();
    let stderr = child.0.stderr().take();
    let mut out = Captured::default();
    let mut err = Captured::default();
    let waited = tokio::time::timeout(timeout, async {
        let (status, (), ()) = tokio::join!(
            child.0.wait(),
            capture(stdout, &mut out, id, attempt, "stdout", progress),
            capture(stderr, &mut err, id, attempt, "stderr", progress)
        );
        status
    })
    .await;
    // Kill any remaining descendants even when the immediate process exited successfully.
    let _ = child.0.start_kill();
    let (status, timed_out) = if let Ok(status) = waited {
        (status, false)
    } else {
        let _ = tokio::time::timeout(Duration::from_secs(2), child.0.wait()).await;
        (
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "reload deadline exceeded",
            )),
            true,
        )
    };
    for (stream, captured) in [("stdout", out), ("stderr", err)] {
        if captured.truncated
            && let Some(progress) = progress
        {
            progress.output.progress(
                MessageKind::Warning,
                &format!("Deployment '{id}' reload {stream} output truncated at 64 KiB"),
            );
        }
        let text = captured.text();
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
    ReloadResult { status, timed_out }
}

#[derive(Default)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
    error: Option<String>,
}
impl Captured {
    fn text(self) -> String {
        let mut text = String::from_utf8_lossy(&self.bytes).into_owned();
        if self.truncated {
            text.push_str("\n[output truncated at 64 KiB]");
        }
        if let Some(error) = self.error {
            let _ = write!(text, "\n[output read failed: {error}]");
        }
        text
    }
}

async fn capture(
    stream: Option<impl AsyncRead + Unpin>,
    saved: &mut Captured,
    id: &str,
    attempt: u8,
    stream_name: &str,
    progress: Option<&Progress>,
) {
    let Some(mut stream) = stream else {
        return;
    };
    let mut buffer = [0_u8; 4096];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(size) => {
                let keep = size.min(MAX_OUTPUT.saturating_sub(saved.bytes.len()));
                saved.bytes.extend_from_slice(&buffer[..keep]);
                if keep > 0
                    && let Some(progress) = progress
                {
                    let text = String::from_utf8_lossy(&buffer[..keep]);
                    progress.output.details(
                        MessageKind::Info,
                        &format!("Deployment '{id}' reload attempt {attempt} {stream_name}:"),
                        &text.lines().map(str::to_owned).collect::<Vec<_>>(),
                    );
                }
                saved.truncated |= keep < size;
            }
            Err(error) => {
                saved.error = Some(error.to_string());
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests;
