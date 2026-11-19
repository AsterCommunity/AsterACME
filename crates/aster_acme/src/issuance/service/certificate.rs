//! Issuance certificate stage.

use crate::issuance::progress::IssueEvent;
use crate::issuance::service::{IssueService, execution::bounded};
use crate::issuance::{IssueError, IssueExecution, IssueRecord};
use crate::storage::issuance::IssueSession;
use aster_acme_core::workflow::IssuancePhase;
use aster_acme_protocol::url::AcmeUrl;

impl IssueService {
    // Download, validate and promote as one workflow stage, then enrich its saved
    // fallback with ARI. No renewal query occurs before certificate commitment.
    pub(super) async fn download(
        &self,
        session: &mut dyn IssueSession,
        record: &mut IssueRecord,
        url: &AcmeUrl,
        execution: &IssueExecution,
    ) -> Result<IssueRecord, IssueError> {
        self.observe(&IssueEvent::Downloading);
        record.phase = IssuancePhase::Downloading;
        session.save(record).await?;
        let response = bounded(execution, self.post(url, b"")).await?;
        if response.status != reqwest::StatusCode::OK
            || response
                .headers
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| {
                    !value.split(';').next().is_some_and(|essence| {
                        essence
                            .trim()
                            .eq_ignore_ascii_case("application/pem-certificate-chain")
                    })
                })
        {
            return Err(IssueError::InvalidInput(
                "CA returned an invalid certificate media type or status",
            ));
        }
        record.phase = IssuancePhase::Completed;
        session.complete(record, &response.body).await?;
        self.observe(&IssueEvent::CertificateSaved {
            name: record.name.clone(),
        });
        self.plan_renewal(session, &execution.context).await
    }

    // A cancelled ARI lookup must not turn an already committed issuance into failure.
    // Its six-hour query deadline is saved before GET; expose the latest durable plan.
    pub(super) async fn plan_renewal(
        &self,
        session: &mut dyn IssueSession,
        execution: &crate::solver::ExecutionContext,
    ) -> Result<IssueRecord, IssueError> {
        match crate::renewal::RenewalService::new(self.client.clone())
            .refresh(session, execution)
            .await
        {
            Err(IssueError::Cancelled | IssueError::TimedOut) => session.record().await,
            result => result,
        }
    }
}
