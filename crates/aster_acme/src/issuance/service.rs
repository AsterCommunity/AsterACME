//! RFC 8555 issuance orchestration. All mutations follow durable checkpoints.

use crate::issuance::progress::{IssueEvent, IssueObserver};
use crate::issuance::service::{
    execution::{bounded, check},
    response::{parse_order, schedule},
};
use crate::issuance::{IssueError, IssueExecution, IssueIdentity, IssueOutcome, IssueRecord};
use crate::solver::ChallengeSolver;
use crate::storage::issuance::IssueSession;
use crate::transport::{AcmeClient, AcmeResponse};
use aster_acme_core::{
    machine::{OrderAction, order_action},
    protocol::OrderStatus,
    workflow::IssuancePhase,
};
use aster_acme_protocol::url::AcmeUrl;
use std::{sync::Arc, time::Duration};

/// Embeddable issuance service. Caller owns lifetime, account lease and publication adapter.
pub struct IssueService {
    client: Arc<AcmeClient>,
    identity: IssueIdentity,
    observer: Option<Arc<dyn IssueObserver>>,
}

mod authorization;
mod certificate;
mod execution;
mod order;
mod publication;
mod response;

impl IssueService {
    /// Bind discovered transport to an already registered account; no implicit registration.
    ///
    /// # Errors
    /// Rejects inactive, mismatched or incomplete account identities.
    pub fn new(client: Arc<AcmeClient>, identity: IssueIdentity) -> Result<Self, IssueError> {
        if !identity.account.is_usable()
            || identity.account.directory_url != *client.directory_url()
            || identity.signer.jwk()?.thumbprint()? != identity.account.key_thumbprint
            || identity.signer.algorithm() != identity.account.key_algorithm
        {
            return Err(IssueError::InvalidInput(
                "issuance requires an active matching account",
            ));
        }
        Ok(Self {
            client,
            identity,
            observer: None,
        })
    }

    /// Attach a product-owned progress observer; signed requests and secrets are excluded.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn IssueObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    fn observe(&self, event: &IssueEvent) {
        if let Some(observer) = &self.observer {
            observer.observe(event);
        }
    }

    /// Refresh existing order/authorization resources and due ARI; no challenge acknowledgement/finalize.
    ///
    /// # Errors
    /// Reports binding, HTTP and malformed-resource failures.
    pub async fn inspect(&self, session: &mut dyn IssueSession) -> Result<IssueRecord, IssueError> {
        let mut record = session.record().await?;
        self.check_identity(&record)?;
        let url = record
            .order_url
            .clone()
            .ok_or(IssueError::CreationUncertain)?;
        let response = self.post(&url, b"").await?;
        if response.status != reqwest::StatusCode::OK {
            return Err(IssueError::InvalidInput("order query must return HTTP 200"));
        }
        record.order = Some(parse_order(&response, &record)?);
        let urls = record
            .order
            .as_ref()
            .ok_or(IssueError::InvalidInput("missing order"))?
            .authorizations
            .clone();
        for url in urls {
            self.authorization(&mut record, &url).await?;
        }
        session.save(&record).await?;
        let execution = crate::solver::ExecutionContext {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: std::time::Instant::now() + Duration::from_secs(30),
        };
        self.plan_renewal(session, &execution).await
    }

    /// Drive one saved issuance using explicit core actions and bounded cancellation-aware I/O.
    /// Await solver shutdown on every return; hosts abandoning this future must
    /// explicitly shut down or drop their solver to release temporary publication.
    ///
    /// # Errors
    /// Never automatically recreates an uncertain order or resubmits an uncertain finalize.
    pub async fn run(
        &self,
        session: &mut dyn IssueSession,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) -> Result<IssueOutcome, IssueError> {
        let result = self.run_active(session, solver, execution).await;
        // Shutdown has its own bounded local lifecycle: the operation may already
        // be cancelled/expired, but its listener must not survive this invocation.
        solver.shutdown().await;
        result
    }

    pub(crate) async fn run_active(
        &self,
        session: &mut dyn IssueSession,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) -> Result<IssueOutcome, IssueError> {
        let mut record = session.record().await?;
        tracing::debug!(operation_id = %record.operation_id, phase = ?record.phase, new_order_intent_saved = record.new_order_intent_saved, has_order_url = record.order_url.is_some(), finalize = ?record.finalize_submitted, method = record.challenge.name(), "Loaded issuance checkpoint");

        self.check_execution(&record, solver, execution)?;
        self.restore_publication(session, &mut record, solver, execution)
            .await?;
        let mut last_order_status = None;
        let mut polls = 0_u32;
        if matches!(record.phase, IssuancePhase::Completed) {
            let record = self.plan_renewal(session, &execution.context).await?;
            return self.completed(session, record, solver, execution).await;
        }
        if record.order_url.is_none() {
            self.create(session, &mut record, execution).await?;
        }
        loop {
            check(execution)?;
            if record.expired(time::OffsetDateTime::now_utc()) {
                return Err(IssueError::Expired);
            }
            if polls == execution.max_polls {
                return Err(IssueError::PollLimit {
                    completed: polls,
                    limit: execution.max_polls,
                });
            }
            self.wait(&record, execution, polls + 1).await?;
            polls += 1;
            self.observe(&IssueEvent::Polling {
                attempt: polls,
                limit: execution.max_polls,
            });
            let url = record
                .order_url
                .clone()
                .ok_or(IssueError::CreationUncertain)?;
            let response = bounded(execution, self.post(&url, b"")).await?;
            if response.status != reqwest::StatusCode::OK {
                return Err(IssueError::InvalidInput("order query must return HTTP 200"));
            }
            record.order = Some(parse_order(&response, &record)?);
            let order = record
                .order
                .clone()
                .ok_or(IssueError::InvalidInput("missing order"))?;
            schedule(&mut record, &response, execution.poll_interval);
            session.save(&record).await?;
            if last_order_status.as_ref() != Some(&order.status) {
                self.observe(&IssueEvent::OrderObserved {
                    status: order.status.clone(),
                });
                last_order_status = Some(order.status.clone());
            }
            if record.expired(time::OffsetDateTime::now_utc()) {
                return Err(IssueError::Expired);
            }
            if matches!(order.status, OrderStatus::Invalid) {
                return Err(self
                    .invalid_order(session, &mut record, solver, execution)
                    .await?);
            }
            let statuses = record
                .authorizations
                .iter()
                .map(|auth| auth.resource.status.clone())
                .collect::<Vec<_>>();
            let observations = match &order.status {
                OrderStatus::Pending => None,
                OrderStatus::Ready
                | OrderStatus::Processing
                | OrderStatus::Valid
                | OrderStatus::Invalid
                | OrderStatus::Unknown(_) => Some(statuses.as_slice()),
            };
            let action = order_action(&order.status, observations, record.finalize_submitted)?;
            match action {
                OrderAction::ResolveAuthorizations => {
                    if let Some(records) = self
                        .authorize(session, &mut record, solver, execution)
                        .await?
                    {
                        return Ok(IssueOutcome::ActionRequired {
                            record: Box::new(record),
                            records,
                        });
                    }
                }
                OrderAction::Finalize => self.finalize(session, &mut record, execution).await?,
                OrderAction::PollOrder | OrderAction::RefreshOrder => {}
                OrderAction::DownloadCertificate => {
                    let url = order.certificate.as_ref().ok_or(IssueError::InvalidInput(
                        "valid order omitted certificate URL",
                    ))?;
                    record = self.download(session, &mut record, url, execution).await?;
                    return self.completed(session, record, solver, execution).await;
                }
            }
        }
    }

    // One library-owned guard for new issuance, recovery and renewal. Product
    // adapters cannot reinterpret the saved method or bypass protocol eligibility.
    pub(crate) fn check_execution(
        &self,
        record: &IssueRecord,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) -> Result<(), IssueError> {
        if execution.max_polls == 0 || execution.max_polls > 1000 {
            return Err(IssueError::InvalidInput("max_polls must be in 1..=1000"));
        }
        if execution.poll_interval.is_zero() {
            return Err(IssueError::InvalidInput("poll interval must be nonzero"));
        }
        self.check_identity(record)?;
        if !record.challenge.supports_wildcards()
            && record
                .identifiers
                .iter()
                .any(crate::identifier::DnsIdentifier::is_wildcard)
        {
            return Err(crate::challenge::ChallengeError::WildcardMethod.into());
        }
        if solver.kind() != record.challenge {
            return Err(IssueError::InvalidInput(
                "publication adapter does not implement the saved challenge method",
            ));
        }
        record.check_recovery(time::OffsetDateTime::now_utc())?;
        if !record.new_order_intent_saved && record.order_url.is_none() {
            record
                .challenge
                .validate_directory(&self.client.directory().meta)?;
        }
        if !matches!(
            record.revocation.state,
            aster_acme_core::revocation::RevocationState::NotRequested
        ) {
            return Err(IssueError::InvalidInput(
                "cannot resume an issuance whose certificate revocation is pending or confirmed",
            ));
        }
        Ok(())
    }

    pub(crate) fn check_identity(&self, record: &IssueRecord) -> Result<(), IssueError> {
        if record.account_id != self.identity.account.account_id
            || record.directory != *self.client.directory_url()
            || record.account_url
                != self
                    .identity
                    .account
                    .account_url
                    .clone()
                    .ok_or(IssueError::InvalidInput("missing account URL"))?
        {
            return Err(IssueError::InvalidInput(
                "saved issuance account binding changed; retain original identity",
            ));
        }
        Ok(())
    }

    async fn post(&self, url: &AcmeUrl, payload: &[u8]) -> Result<AcmeResponse, IssueError> {
        Ok(self
            .client
            .signed(
                url,
                self.identity.signer.as_ref(),
                self.identity.account.account_url.as_ref(),
                payload,
            )
            .await?)
    }

    async fn wait(
        &self,
        record: &IssueRecord,
        execution: &IssueExecution,
        attempt: u32,
    ) -> Result<(), IssueError> {
        if let Some(at) = record.next_poll_at {
            let delay = (at - time::OffsetDateTime::now_utc())
                .try_into()
                .unwrap_or(Duration::ZERO);
            if !delay.is_zero() {
                self.observe(&IssueEvent::Waiting {
                    delay,
                    attempt,
                    limit: execution.max_polls,
                    source: record
                        .poll_wait_source
                        .unwrap_or(crate::issuance::PollWaitSource::LocalInterval),
                });
            }
            bounded(execution, async {
                tokio::time::sleep(delay).await;
                Ok(())
            })
            .await?;
        }
        Ok(())
    }
}
