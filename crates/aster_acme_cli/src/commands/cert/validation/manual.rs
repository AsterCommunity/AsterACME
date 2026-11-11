//! Manual implementations share confirmation semantics but keep method-specific instructions.
use super::{Arc, ChallengeKind, ChallengeSolver, IssueError, Progress};
use crate::common::output::MessageKind;
use aster_acme::{issuance::ValidationRequirement, solver::ExecutionContext};
use async_trait::async_trait;

pub(super) struct Manual {
    pub(super) method: ChallengeKind,
    pub(super) saved: bool,
    pub(super) interactive: bool,
    pub(super) yes: bool,
    pub(super) progress: Arc<Progress>,
}
#[async_trait]
impl ChallengeSolver for Manual {
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
            // No storage lease is moved into the potentially blocked terminal read.
            std::thread::Builder::new()
                .name("validation-confirmation".into())
                .spawn(move || {
                    progress
                        .output
                        .details(MessageKind::Warning, message, &details);
                    progress.output.interaction_started();
                    let answer = inquire::Confirm::new(question)
                        .with_default(false)
                        .with_render_config(crate::common::terminal::prompt_style(
                            progress.output.diagnostic_format().color,
                            false,
                        ))
                        .prompt();
                    let _ = sender.send(answer);
                })
                .map_err(|_| IssueError::Interrupted)?;
            let confirmed = receiver
                .await
                .map_err(|_| IssueError::Interrupted)?
                .map_err(|_| IssueError::Interrupted)?;
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
