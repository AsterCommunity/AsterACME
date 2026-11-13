//! Manual implementations share confirmation semantics but keep method-specific instructions.
use crate::commands::cert::validation::{
    Arc, ChallengeKind, ChallengeSolver, IssueError, Progress,
};
use crate::common::output::MessageKind;
use aster_acme::{issuance::ValidationRequirement, solver::ExecutionContext};
use async_trait::async_trait;

pub(super) struct Manual {
    pub(super) reusable: Vec<ValidationRequirement>,
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
        let reused = !requirements.is_empty()
            && requirements.iter().all(|requirement| {
                requirement.kind().publication_lifetime()
                    == aster_acme::challenge::PublicationLifetime::Persistent
                    && self.reusable.contains(requirement)
            });
        match (reused, self.saved, self.interactive, self.yes) {
            (false, false, _, true) | (false, _, false, false) => return Ok(false),
            _ => {}
        }
        if !reused && self.interactive && !self.yes {
            let progress = self.progress.clone();
            let details = super::super::render::requirement_lines(requirements);
            let message = match self.method {
                ChallengeKind::Dns01 => {
                    "Action required: add all TXT values; keep unrelated values"
                }
                ChallengeKind::DnsPersist01 => {
                    "Action required: add these persistent TXT records; retain them for renewal. They authorize this account until removed"
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
                ChallengeKind::Dns01 | ChallengeKind::DnsPersist01 => {
                    "Have you published these TXT values?"
                }
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
            ChallengeKind::Dns01 | ChallengeKind::DnsPersist01 | ChallengeKind::Http01 => Ok(true),
            ChallengeKind::TlsAlpn01 => Err(IssueError::InvalidInput(
                "manual TLS-ALPN is not implemented",
            )),
        }
    }
}

// Use the same native inquire widget as other CLI confirmations. Its public
// API is blocking and has no external cancellation hook: never detach a live
// prompt or force-disable its raw mode from a different thread. Shutdown joins
// it, then the saved execution scope is checked before any CA operation.
fn confirm(
    question: &str,
    execution: &ExecutionContext,
    stop: &tokio_util::sync::CancellationToken,
    progress: &Progress,
) -> Result<bool, IssueError> {
    execution.check().map_err(|_| IssueError::Interrupted)?;
    if stop.is_cancelled() {
        return Err(IssueError::Interrupted);
    }
    progress.output.interaction_started();
    let answer = inquire::Confirm::new(question)
        .with_default(false)
        .with_render_config(crate::common::terminal::prompt_style(
            progress.output.diagnostic_format().color,
            false,
        ))
        .prompt();
    let answer = match answer {
        Ok(answer) => answer,
        Err(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted,
        ) => {
            execution.cancellation.cancel();
            return Err(IssueError::Interrupted);
        }
        Err(error) => {
            return Err(IssueError::Publication(format!(
                "confirmation terminal failed: {error}"
            )));
        }
    };
    execution.check().map_err(|_| IssueError::Interrupted)?;
    if stop.is_cancelled() {
        return Err(IssueError::Interrupted);
    }
    Ok(answer)
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
            reusable: Vec::new(),
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
        match mode.as_str() {
            "yes" | "yes-word" | "replace" => assert!(result.unwrap().unwrap()),
            "no" | "no-word" | "default" | "erase" => assert!(!result.unwrap().unwrap()),
            _ => assert!(result.is_err() || result.unwrap().is_err()),
        }
        assert_eq!(
            cancellation.is_cancelled(),
            matches!(mode.as_str(), "escape" | "ctrl-c")
        );
        println!(
            "CONFIRM_RESTORED mode={mode} cancelled={}",
            cancellation.is_cancelled()
        );
    }
}
