//! Bounded advisory observation of public HTTP-01 files after publication.
use crate::commands::cert::validation::{
    Arc, ChallengeKind, ChallengeSolver, IssueError, Progress,
};
use crate::common::output::MessageKind;
use aster_acme::{issuance::ValidationRequirement, solver::ExecutionContext, transport::HttpPool};
use async_trait::async_trait;
use std::time::{Duration, Instant};

pub(super) struct Checked {
    pub(super) inner: Box<dyn ChallengeSolver>,
    pub(super) pool: HttpPool,
    pub(super) progress: Arc<Progress>,
}
#[async_trait]
impl ChallengeSolver for Checked {
    fn kind(&self) -> ChallengeKind {
        self.inner.kind()
    }
    async fn restore(
        &self,
        requirements: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<(), IssueError> {
        self.inner.restore(requirements, execution).await
    }
    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
    async fn ready(
        &self,
        requirements: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        if !self.inner.ready(requirements, execution).await? {
            return Ok(false);
        }
        execution.check().map_err(|_| IssueError::Interrupted)?;
        self.progress.output.progress(
            MessageKind::Info,
            "Checking public HTTP challenge files (advisory, up to 2 seconds)",
        );
        let deadline = execution
            .deadline
            .min(Instant::now() + Duration::from_secs(2));
        let check = async {
            for requirement in requirements {
                let ValidationRequirement::Http01 { url, content, .. } = requirement else {
                    return Ok(false);
                };
                if !self
                    .pool
                    .check_http_challenge(url, content.as_bytes(), Duration::from_secs(2))
                    .await?
                {
                    return Ok(false);
                }
            }
            Ok::<_, aster_acme::transport::TransportError>(true)
        };
        let result = tokio::select! {
            biased;
            () = execution.cancellation.cancelled() => return Err(IssueError::Interrupted),
            result = tokio::time::timeout_at(deadline.into(), check) => result,
        };
        execution.check().map_err(|_| IssueError::Interrupted)?;
        match result {
            Ok(Ok(true)) => self.progress.output.progress(MessageKind::Success, "HTTP files match locally; the CA will independently verify public access"),
            _ => self.progress.output.progress(MessageKind::Warning, "HTTP files could not be confirmed locally (content, network or redirect); continuing to CA validation"),
        }
        Ok(true)
    }
    async fn cleanup(
        &self,
        requirements: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        self.inner.cleanup(requirements, execution).await
    }
}
