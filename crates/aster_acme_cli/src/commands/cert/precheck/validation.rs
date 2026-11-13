//! Bounded advisory DNS/HTTP observations after the publication solver is ready.
use crate::commands::cert::progress::Progress;
use crate::common::output::MessageKind;
use aster_acme::precheck::{Runner, http::Http};
use aster_acme::{challenge::ChallengeKind, issuance::IssueError, solver::ChallengeSolver};
use aster_acme::{issuance::ValidationRequirement, solver::ExecutionContext, transport::HttpPool};
use async_trait::async_trait;
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

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
        match self.kind() {
            ChallengeKind::Dns01 | ChallengeKind::DnsPersist01 => {
                crate::commands::cert::precheck::dns::run(requirements, execution, &self.progress)
                    .await?;
                return Ok(true);
            }
            ChallengeKind::TlsAlpn01 => return Ok(true),
            ChallengeKind::Http01 => {}
        }
        self.progress.output.progress(
            MessageKind::Info,
            &format!(
                "Checking public HTTP challenge files (advisory, up to {} seconds)",
                Runner::default().timeout().as_secs()
            ),
        );
        let report = Runner::default()
            .run(&Http::new(&self.pool), requirements, execution)
            .await
            .map_err(|_| IssueError::Interrupted)?;
        let matches = report
            .observations
            .iter()
            .all(|observation| matches!(observation.result, Ok(true)));
        if matches {
            self.progress.output.progress(
                MessageKind::Success,
                "HTTP files match locally; the CA will independently verify public access",
            );
        } else {
            self.progress.output.progress(MessageKind::Warning, "HTTP files could not be confirmed locally (content, network or redirect); continuing to CA validation");
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

#[cfg(test)]
mod tests {
    use crate::commands::cert::precheck::validation::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    struct Ready;
    #[async_trait]
    impl ChallengeSolver for Ready {
        fn kind(&self) -> ChallengeKind {
            ChallengeKind::Http01
        }
        async fn ready(
            &self,
            _: &[ValidationRequirement],
            _: &ExecutionContext,
        ) -> Result<bool, IssueError> {
            Ok(true)
        }
        async fn cleanup(
            &self,
            _: &[ValidationRequirement],
            _: &ExecutionContext,
        ) -> Result<bool, IssueError> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn five_second_precheck_accepts_response_after_old_two_second_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/challenge"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(2200))
                    .set_body_string("token.thumb"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let (output, _, diagnostics) = crate::common::session::tests::session(false);
        let checked = Checked {
            inner: Box::new(Ready),
            pool: HttpPool::default(),
            progress: Arc::new(Progress::new(output)),
        };
        let context = ExecutionContext {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let requirements = [ValidationRequirement::Http01 {
            url: format!("{}/challenge", server.uri()),
            path: "/challenge".into(),
            content: "token.thumb".into(),
        }];
        assert!(checked.ready(&requirements, &context).await.unwrap());
        assert_eq!(Runner::default().timeout(), Duration::from_secs(5));
        assert!(diagnostics.text().contains("up to 5 seconds"));
        assert!(diagnostics.text().contains("HTTP files match locally"));
        assert!(!diagnostics.text().contains("could not be confirmed"));
    }

    #[tokio::test]
    async fn operation_deadline_and_cancellation_still_override_precheck_budget() {
        let checked = Checked {
            inner: Box::new(Ready),
            pool: HttpPool::default(),
            progress: Arc::new(Progress::new(crate::common::session::OutputSession::new(
                true,
            ))),
        };
        for cancelled in [false, true] {
            let context = ExecutionContext {
                cancellation: tokio_util::sync::CancellationToken::new(),
                deadline: Instant::now()
                    + if cancelled {
                        Duration::from_secs(10)
                    } else {
                        Duration::ZERO
                    },
            };
            if cancelled {
                context.cancellation.cancel();
            }
            assert!(matches!(
                checked.ready(&[], &context).await,
                Err(IssueError::Interrupted)
            ));
        }
    }

    #[tokio::test]
    async fn fixed_five_second_limit_warns_but_shorter_operation_deadline_interrupts() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(10))
                    .set_body_string("token.thumb"),
            )
            .mount(&server)
            .await;
        let requirements = [ValidationRequirement::Http01 {
            url: server.uri(),
            path: "/".into(),
            content: "token.thumb".into(),
        }];
        for operation_budget in [Duration::from_secs(15), Duration::from_millis(100)] {
            let (output, _, diagnostics) = crate::common::session::tests::session(false);
            let progress = Arc::new(Progress::new(output));
            let checked = Checked {
                inner: Box::new(Ready),
                pool: HttpPool::default(),
                progress,
            };
            let context = ExecutionContext {
                cancellation: tokio_util::sync::CancellationToken::new(),
                deadline: Instant::now() + operation_budget,
            };
            let started = Instant::now();
            let result = checked.ready(&requirements, &context).await;
            if operation_budget > Runner::default().timeout() {
                assert!(result.unwrap());
                assert!(started.elapsed() >= Runner::default().timeout());
                assert!(started.elapsed() < Duration::from_secs(8));
                assert!(diagnostics.text().contains("could not be confirmed"));
            } else {
                assert!(matches!(result, Err(IssueError::Interrupted)));
                assert!(started.elapsed() < Duration::from_secs(2));
            }
        }
    }
}
