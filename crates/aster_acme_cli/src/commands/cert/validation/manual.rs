//! Manual implementations share confirmation semantics but keep method-specific instructions.
use crate::commands::cert::validation::{
    Arc, ChallengeKind, ChallengeSolver, IssueError, Progress,
};
use crate::common::output::MessageKind;
use aster_acme::{issuance::ValidationRequirement, solver::ExecutionContext};
use async_trait::async_trait;

pub(super) struct Manual {
    pub(super) method: ChallengeKind,
    pub(super) saved: bool,
    pub(super) interactive: bool,
    pub(super) yes: bool,
    pub(super) progress: Arc<Progress>,
    pub(super) prompt: std::sync::Mutex<Option<PromptTask>>,
}

pub(super) struct PromptTask {
    stop: tokio_util::sync::CancellationToken,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for PromptTask {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
#[async_trait]
impl ChallengeSolver for Manual {
    async fn shutdown(&self) {
        let task = self.prompt.lock().ok().and_then(|mut task| task.take());
        if let Some(task) = task {
            let _ = tokio::task::spawn_blocking(move || drop(task)).await;
        }
    }

    fn kind(&self) -> ChallengeKind {
        self.method
    }
    async fn ready(
        &self,
        requirements: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        if requirements
            .iter()
            .any(|requirement| requirement.kind() != self.method)
        {
            return Err(IssueError::InvalidInput(
                "manual solver received another method's material",
            ));
        }
        // Fresh scripted material must first be exposed to the caller. --yes only
        // confirms an operation; it does not mean newly issued files/TXT already exist.
        match (self.saved, self.interactive, self.yes) {
            (false, _, true) | (_, false, false) => return Ok(false),
            _ => {}
        }
        if self.interactive && !self.yes {
            let progress = self.progress.clone();
            let details = super::super::render::requirement_lines(requirements);
            let message = match self.method {
                ChallengeKind::Dns01 => {
                    "Action required: add all TXT values; keep unrelated values"
                }
                ChallengeKind::Http01 => {
                    "Action required: serve every HTTP file exactly as shown, reachable on public port 80"
                }
                ChallengeKind::TlsAlpn01 => {
                    return Err(IssueError::InvalidInput(
                        "manual TLS-ALPN is not implemented",
                    ));
                }
            };
            let question = match self.method {
                ChallengeKind::Dns01 => "Have you published these TXT values?",
                ChallengeKind::Http01 => "Are these HTTP challenge files publicly available?",
                ChallengeKind::TlsAlpn01 => {
                    return Err(IssueError::InvalidInput(
                        "manual TLS-ALPN is not implemented",
                    ));
                }
            };
            let (sender, receiver) = tokio::sync::oneshot::channel();
            let execution = execution.clone();
            let stop = tokio_util::sync::CancellationToken::new();
            let worker_stop = stop.clone();
            let handle = std::thread::Builder::new()
                .name("validation-confirmation".into())
                .spawn(move || {
                    progress
                        .output
                        .details(MessageKind::Warning, message, &details);
                    let answer = confirm(question, &execution, &worker_stop, &progress);
                    let _ = sender.send(answer);
                })
                .map_err(|_| IssueError::Publication("cannot start confirmation reader".into()))?;
            *self
                .prompt
                .lock()
                .map_err(|_| IssueError::Publication("confirmation state poisoned".into()))? =
                Some(PromptTask {
                    stop,
                    handle: Some(handle),
                });
            let confirmed = receiver
                .await
                .map_err(|_| IssueError::Publication("confirmation reader stopped".into()))??;
            self.shutdown().await;
            if !confirmed {
                return Ok(false);
            }
        }
        match self.method {
            ChallengeKind::Dns01 => {
                dns_precheck(
                    aster_acme_validation::dns01::visibility::DnsVisibility
                        .ready(requirements, execution),
                    execution,
                    &self.progress,
                )
                .await?;
                Ok(true)
            }
            ChallengeKind::Http01 => {
                self.progress.output.progress(MessageKind::Info, "HTTP publication confirmed by caller; the CA will verify public access on port 80");
                Ok(true)
            }
            ChallengeKind::TlsAlpn01 => Err(IssueError::InvalidInput(
                "manual TLS-ALPN is not implemented",
            )),
        }
    }
}

// Every blocking read is preceded by a short bounded poll; shutdown can always
// join this worker. The raw-mode guard restores the terminal before sending an answer.
fn confirm(
    question: &str,
    execution: &ExecutionContext,
    stop: &tokio_util::sync::CancellationToken,
    progress: &Progress,
) -> Result<bool, IssueError> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    struct RawMode;
    impl Drop for RawMode {
        fn drop(&mut self) {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
    crossterm::terminal::enable_raw_mode()
        .map_err(|_| IssueError::Publication("cannot initialize confirmation terminal".into()))?;
    let _raw = RawMode;
    progress.output.interaction_started();
    progress.output.context(&format!("> {question} [y/N]"));
    let mut answer = false;
    loop {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        if stop.is_cancelled() {
            return Err(IssueError::Interrupted);
        }
        if !event::poll(std::time::Duration::from_millis(25))
            .map_err(|_| IssueError::Publication("cannot poll confirmation terminal".into()))?
        {
            continue;
        }
        let Event::Key(key) = event::read()
            .map_err(|_| IssueError::Publication("cannot read confirmation terminal".into()))?
        else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        match key.code {
            KeyCode::Esc => {
                execution.cancellation.cancel();
                return Err(IssueError::Interrupted);
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                execution.cancellation.cancel();
                return Err(IssueError::Interrupted);
            }
            KeyCode::Char('y' | 'Y') => answer = true,
            KeyCode::Char('n' | 'N') | KeyCode::Backspace => answer = false,
            KeyCode::Enter => return Ok(answer),
            _ => {}
        }
    }
}

/// Local resolver observations are advisory, bounded independently of the ACME
/// request budget. A broken resolver must not reject domain control on behalf of a CA.
/// User cancellation/overall expiry still stops the operation.
pub(super) async fn dns_precheck(
    check: impl std::future::Future<Output = Result<bool, IssueError>>,
    execution: &ExecutionContext,
    progress: &Progress,
) -> Result<(), IssueError> {
    execution.check().map_err(|_| IssueError::Interrupted)?;
    progress.output.progress(
        MessageKind::Info,
        "Checking local DNS visibility (advisory, up to 2 seconds)",
    );
    let result = tokio::select! {
        biased;
        () = execution.cancellation.cancelled() => return Err(IssueError::Interrupted),
        result = tokio::time::timeout_at(tokio::time::Instant::from_std(execution.deadline.min(std::time::Instant::now() + std::time::Duration::from_secs(2))), check) => result,
    };
    execution.check().map_err(|_| IssueError::Interrupted)?;
    match result {
        Ok(Ok(true)) => progress.output.progress(
            MessageKind::Success,
            "Required TXT values are visible through the local DNS resolver",
        ),
        Ok(Ok(false)) => progress.output.progress(
            MessageKind::Warning,
            "TXT values are not visible locally yet; continuing to CA validation",
        ),
        Ok(Err(_)) => progress.output.progress(
            MessageKind::Warning,
            "Local DNS resolver is unavailable; continuing to CA validation",
        ),
        Err(_) => progress.output.progress(
            MessageKind::Warning,
            "Local DNS precheck timed out; continuing to CA validation",
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::commands::cert::validation::manual::*;

    #[tokio::test]
    #[ignore = "PTY fixture for confirmation cancellation/deadline and raw-mode restoration"]
    async fn terminal_confirmation_child() {
        let mode = std::env::var("ASTER_CONFIRM_TEST_MODE").unwrap_or_else(|_| "timeout".into());
        let cancellation = tokio_util::sync::CancellationToken::new();
        let execution = ExecutionContext {
            cancellation: cancellation.clone(),
            deadline: std::time::Instant::now()
                + std::time::Duration::from_millis(if mode == "timeout" { 400 } else { 10_000 }),
        };
        let solver = Manual {
            method: ChallengeKind::Http01,
            saved: true,
            interactive: true,
            yes: false,
            progress: Arc::new(Progress::new(crate::common::session::OutputSession::new(
                false,
            ))),
            prompt: std::sync::Mutex::new(None),
        };
        let requirements = [ValidationRequirement::Http01 {
            url: "http://example.com/.well-known/acme-challenge/token".into(),
            path: "/.well-known/acme-challenge/token".into(),
            content: "token.thumbprint".into(),
        }];
        let result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(execution.deadline),
            solver.ready(&requirements, &execution),
        )
        .await;
        solver.shutdown().await;
        assert!(!crossterm::terminal::is_raw_mode_enabled().unwrap());
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(cancellation.is_cancelled(), mode == "escape");
        println!(
            "CONFIRM_RESTORED mode={mode} cancelled={}",
            cancellation.is_cancelled()
        );
    }
}
