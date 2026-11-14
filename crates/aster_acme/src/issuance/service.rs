//! RFC 8555 issuance orchestration. All mutations follow durable checkpoints.
use crate::issuance::progress::{IssueEvent, IssueObserver};
use crate::issuance::publication::{
    checkpoint, cleanup_saved, outstanding_publications, publication,
};
use crate::issuance::{
    AuthorizationRecord, IssueError, IssueExecution, IssueIdentity, IssueOutcome, IssueRecord,
    ValidationRequirement,
};
use crate::solver::ChallengeSolver;
use crate::storage::issuance::IssueSession;
use crate::{
    challenge::{PublicationAccountProof, PublicationLifetime},
    identifier::{Identifier, authorization_identifier},
    transport::{AcmeClient, AcmeResponse, json_payload},
};
use aster_acme_core::{
    machine::{ChallengeAction, OrderAction, challenge_action, order_action},
    protocol::{AuthorizationStatus, OrderStatus},
    workflow::{IssuancePhase, SubmissionState},
};
use aster_acme_protocol::{
    account::AccountObject,
    order::{
        AcknowledgeRequest, AuthorizationObject, ChallengeObject, FinalizeRequest, NewOrderRequest,
        OrderObject, WireIdentifier,
    },
    problem::ProblemKind,
    url::AcmeUrl,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{sync::Arc, time::Duration};

/// Embeddable issuance service. Caller owns lifetime, account lease and publication adapter.
pub struct IssueService {
    client: Arc<AcmeClient>,
    identity: IssueIdentity,
    observer: Option<Arc<dyn IssueObserver>>,
}

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

    /// Restart ephemeral publication before the first resumed poll. Ready/valid
    /// orders no longer need a listener, and acknowledged challenges are not acked again.
    async fn restore_publication(
        &self,
        session: &dyn IssueSession,
        record: &mut IssueRecord,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) -> Result<(), IssueError> {
        if !record
            .order
            .as_ref()
            .is_some_and(|order| order.status == OrderStatus::Pending)
        {
            return Ok(());
        }
        crate::issuance::publication::prepare(session, record, solver, &execution.context).await?;
        let pending = record
            .authorizations
            .iter()
            .filter(|auth| matches!(auth.resource.status, AuthorizationStatus::Pending))
            .filter(|auth| {
                auth.validation_requirement
                    .as_ref()
                    .is_some_and(|requirement| {
                        requirement.kind().publication_lifetime() == PublicationLifetime::Temporary
                    })
            })
            .map(publication)
            .collect::<Result<Vec<_>, _>>()?;
        if !pending.is_empty()
            && record
                .order
                .as_ref()
                .is_some_and(|order| matches!(order.status, OrderStatus::Pending))
        {
            let result = solver.restore(&pending, &execution.context).await?;
            if checkpoint(record, &result.receipts, result.retry_at)? {
                session.save(record).await?;
            }
            if let Some(error) = result.failure {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Enrich a terminal resource without executing publication or mutations.
    /// The invalid order was already saved; failed detail queries cannot revive it.
    async fn invalid_order(
        &self,
        session: &dyn IssueSession,
        record: &mut IssueRecord,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) -> Result<IssueError, IssueError> {
        let order = record
            .order
            .clone()
            .ok_or(IssueError::InvalidInput("missing invalid order"))?;
        if order.error.is_none() {
            for url in &order.authorizations {
                if let Err(error) = bounded(execution, self.authorization(record, url)).await {
                    tracing::debug!("Could not enrich invalid order authorization details");
                    if matches!(error, IssueError::Interrupted) {
                        break;
                    }
                }
            }
            session.save(record).await?;
        }
        // The saved invalid order is terminal: no later validation/finalization
        // can succeed, so owned publication can now be withdrawn. Cancellation
        // or cleanup failure must never replace the original CA problem.
        self.cleanup_publication(session, record, solver, execution)
            .await;
        Ok(IssueError::InvalidOrder {
            problem: record.failure_problem().cloned().map(Box::new),
        })
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

    async fn completed(
        &self,
        session: &dyn IssueSession,
        mut record: IssueRecord,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) -> Result<IssueOutcome, IssueError> {
        self.cleanup_publication(session, &mut record, solver, execution)
            .await;
        Ok(completed(record))
    }

    /// Shared success/terminal-failure cleanup. Uncertain failures never call this
    /// boundary. Clear pending state only after the adapter and checkpoint save
    /// succeed; otherwise retain recovery evidence and the primary outcome.
    async fn cleanup_publication(
        &self,
        session: &dyn IssueSession,
        record: &mut IssueRecord,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) {
        if cleanup_saved(session, record, solver, &execution.context)
            .await
            .is_err()
        {
            self.observe(&IssueEvent::CleanupPending);
        }
    }

    // Download, validate and promote as one workflow stage, then enrich its saved
    // fallback with ARI. No renewal query occurs before certificate commitment.
    async fn download(
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
    async fn plan_renewal(
        &self,
        session: &mut dyn IssueSession,
        execution: &crate::solver::ExecutionContext,
    ) -> Result<IssueRecord, IssueError> {
        match crate::renewal::RenewalService::new(self.client.clone())
            .refresh(session, execution)
            .await
        {
            Err(IssueError::Interrupted) => session.record().await,
            result => result,
        }
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

    async fn create(
        &self,
        session: &dyn IssueSession,
        record: &mut IssueRecord,
        execution: &IssueExecution,
    ) -> Result<(), IssueError> {
        if record.new_order_intent_saved {
            return Err(IssueError::CreationUncertain);
        }
        let endpoint = self
            .client
            .directory()
            .new_order
            .as_ref()
            .ok_or(IssueError::InvalidInput("CA directory omitted newOrder"))?;
        let identifiers = record
            .identifiers
            .iter()
            .map(|dns| WireIdentifier {
                kind: "dns".into(),
                value: dns.value(),
            })
            .collect::<Vec<_>>();
        record.submitted_replaces = match self.client.directory().renewal_info.as_ref() {
            Some(_) => record
                .renewal_of
                .as_ref()
                .and_then(|previous| previous.certificate_id.clone()),
            None => None,
        };
        let body = json_payload(&NewOrderRequest {
            identifiers: &identifiers,
            replaces: record.submitted_replaces.as_deref(),
        })?;
        record.new_order_intent_saved = true;
        record.phase = IssuancePhase::CreatingOrder;
        session.save(record).await?;
        tracing::debug!(operation_id = %record.operation_id, "newOrder intent persisted; about to send request");
        self.observe(&IssueEvent::CreatingOrder {
            method: record.challenge,
            solver_id: record.solver_id.clone(),
        });
        let started = std::time::Instant::now();
        let response = match bounded(execution, self.post(endpoint, &body)).await {
            Ok(response) => response,
            Err(error) => {
                if let Some(failure) = super::RequestFailure::from_error(&error) {
                    record.creation_failure = Some(failure);
                    session.save(record).await?;
                    tracing::debug!(operation_id = %record.operation_id, elapsed_ms = started.elapsed().as_millis(), "newOrder error response persisted; no order status inferred");
                } else {
                    tracing::debug!(operation_id = %record.operation_id, elapsed_ms = started.elapsed().as_millis(), "newOrder ended before a usable response; saved intent remains unconfirmed");
                }
                return Err(error);
            }
        };
        tracing::debug!(operation_id = %record.operation_id, status = response.status.as_u16(), elapsed_ms = started.elapsed().as_millis(), has_location = response.headers.contains_key(reqwest::header::LOCATION), "newOrder response received");
        if response.status != reqwest::StatusCode::CREATED {
            return Err(IssueError::InvalidInput("newOrder must return HTTP 201"));
        }
        // Save the Location before parsing its body; malformed JSON must not lose recovery.
        let location = self.client.account_location(&response)?;
        record.order_url = Some(location.clone());
        session.save(record).await?;
        tracing::debug!(operation_id = %record.operation_id, has_order_url = true, "newOrder Location checkpoint persisted");
        self.observe(&IssueEvent::OrderCreated { url: location });
        record.order = Some(parse_order(&response, record)?);
        record.phase = IssuancePhase::Authorizing;
        schedule(record, &response, execution.poll_interval);
        session.save(record).await
    }

    async fn authorization(
        &self,
        record: &mut IssueRecord,
        url: &AcmeUrl,
    ) -> Result<(), IssueError> {
        let response = self.post(url, b"").await?;
        if response.status != reqwest::StatusCode::OK {
            return Err(IssueError::InvalidInput(
                "authorization query must return 200",
            ));
        }
        let resource: AuthorizationObject = serde_json::from_slice(&response.body)
            .map_err(|_| IssueError::InvalidInput("malformed authorization"))?;
        if crate::transport::retry_after(&response.headers).is_some() {
            schedule(record, &response, Duration::ZERO);
        }
        let Identifier::Dns(identifier) =
            authorization_identifier(resource.identifier.clone(), resource.wildcard)?;
        if !record.identifiers.contains(&identifier)
            || resource.challenges.len() > 32
            || matches!(resource.status, AuthorizationStatus::Valid) && resource.expires.is_none()
        {
            return Err(IssueError::InvalidInput(
                "authorization does not match the order or omitted expiry",
            ));
        }
        self.observe(&IssueEvent::AuthorizationObserved {
            identifier: identifier.value(),
            status: resource.status.clone(),
        });
        match record
            .authorizations
            .iter_mut()
            .find(|auth| auth.url == *url)
        {
            Some(saved) => {
                let Identifier::Dns(previous) = authorization_identifier(
                    saved.resource.identifier.clone(),
                    saved.resource.wildcard,
                )?;
                if previous != identifier {
                    return Err(IssueError::InvalidInput("authorization identifier changed"));
                }
                saved.resource = resource;
            }
            None => record.authorizations.push(AuthorizationRecord {
                url: url.clone(),
                resource,
                challenge_url: None,
                validation_requirement: None,
                publication_id: None,
                publication_receipt: None,
                publication_plan: None,
                publication_retry_at: None,
                cleanup_pending: false,
                acknowledgement: SubmissionState::NotSubmitted,
            }),
        }
        Ok(())
    }

    async fn authorize(
        &self,
        session: &dyn IssueSession,
        record: &mut IssueRecord,
        solver: &dyn ChallengeSolver,
        execution: &IssueExecution,
    ) -> Result<Option<Vec<ValidationRequirement>>, IssueError> {
        record.phase = IssuancePhase::Authorizing;
        let urls = record
            .order
            .as_ref()
            .ok_or(IssueError::InvalidInput("missing order"))?
            .authorizations
            .clone();
        if urls.is_empty() {
            return Err(IssueError::InvalidInput(
                "pending order omitted authorizations",
            ));
        }
        for url in urls {
            if record.authorizations.iter().any(|auth| {
                auth.url == url
                    && matches!(auth.resource.status, AuthorizationStatus::Valid)
                    && auth
                        .resource
                        .expires
                        .is_some_and(|at| at > time::OffsetDateTime::now_utc())
            }) {
                continue;
            }
            bounded(execution, self.authorization(record, &url)).await?;
        }
        // Retain expiry/failure observations even when preparation cannot continue.
        session.save(record).await?;
        if let Some(error) = record.authorization_failure() {
            self.cleanup_publication(session, record, solver, execution)
                .await;
            return Err(error);
        }
        let outstanding = crate::issuance::authorization::prepare(
            record,
            &self.client.directory().meta,
            time::OffsetDateTime::now_utc(),
        )?;
        session.save(record).await?;
        if !outstanding.is_empty() {
            match record.challenge.publication_account_proof() {
                PublicationAccountProof::ActiveAccount => {
                    bounded(execution, self.verify_account_control(record)).await?;
                }
                PublicationAccountProof::NotRequired => {}
            }
            self.observe(&IssueEvent::PublicationRequired {
                method: record.challenge,
                count: outstanding.len(),
            });
            crate::issuance::publication::prepare(session, record, solver, &execution.context)
                .await?;
            let publications = outstanding_publications(record, &outstanding)?;
            let result = solver.ready(&publications, &execution.context).await?;
            if checkpoint(record, &result.receipts, result.retry_at)? {
                session.save(record).await?;
            }
            if let Some(error) = result.failure {
                return Err(error);
            }
            if !result.ready {
                return Ok(Some(outstanding));
            }
            let publications = outstanding_publications(record, &outstanding)?;
            if solver.requires_receipt()
                && publications
                    .iter()
                    .any(|publication| publication.receipt.is_none())
            {
                return Err(IssueError::InvalidInput(
                    "publication did not return all required receipts",
                ));
            }
            solver.wait_ready(&publications, &execution.context).await?;
            self.observe(&IssueEvent::PublicationReady {
                method: record.challenge,
            });
        }
        self.acknowledge(session, record, execution).await?;
        if let Some(error) = record.authorization_failure() {
            self.cleanup_publication(session, record, solver, execution)
                .await;
            return Err(error);
        }
        Ok(None)
    }

    // Draft-02 section 4.5: prove the exact digest account URL is controlled by
    // the active signer before giving publication instructions to a DNS operator.
    // Transport already disables redirects; POST-as-GET is an empty byte string.
    async fn verify_account_control(&self, record: &IssueRecord) -> Result<(), IssueError> {
        let response = self.post(&record.account_url, b"").await?;
        if response.status != reqwest::StatusCode::OK {
            return Err(IssueError::InvalidInput(
                "publication account control proof must return 200",
            ));
        }
        let account: AccountObject = serde_json::from_slice(&response.body)
            .map_err(|_| IssueError::InvalidInput("malformed publication account control proof"))?;
        if !matches!(
            account.status,
            aster_acme_core::protocol::AccountStatus::Valid
        ) {
            return Err(IssueError::InvalidInput(
                "publication account control proof requires a valid account",
            ));
        }
        Ok(())
    }

    // The notification boundary owns intent, expiry recheck and response identity validation.
    async fn acknowledge(
        &self,
        session: &dyn IssueSession,
        record: &mut IssueRecord,
        execution: &IssueExecution,
    ) -> Result<(), IssueError> {
        for index in 0..record.authorizations.len() {
            check(execution)?;
            let auth = &record.authorizations[index];
            if !matches!(auth.resource.status, AuthorizationStatus::Pending) {
                continue;
            }
            let url = auth
                .challenge_url
                .clone()
                .ok_or(IssueError::InvalidInput("missing selected challenge"))?;
            let challenge = auth
                .resource
                .challenges
                .iter()
                .find(|challenge| challenge.url == url)
                .ok_or(IssueError::InvalidInput("missing challenge"))?;
            match challenge_action(&challenge.status, auth.acknowledgement)? {
                ChallengeAction::PrepareAndAcknowledge => {
                    let expected = challenge.clone();
                    record.authorizations[index].acknowledgement = SubmissionState::Submitted;
                    session.save(record).await?;
                    // Manual publication may have waited past the CA's expiry.
                    let now = time::OffsetDateTime::now_utc();
                    if record.expired(now)
                        || record.authorizations[index]
                            .resource
                            .expires
                            .is_some_and(|at| at <= now)
                    {
                        return Err(IssueError::Expired);
                    }
                    let response = match bounded(
                        execution,
                        self.post(&url, &json_payload(&AcknowledgeRequest {})?),
                    )
                    .await
                    {
                        Ok(response) => response,
                        Err(
                            error @ IssueError::Transport(
                                crate::transport::TransportError::Problem {
                                    status: 400..=499, ..
                                },
                            ),
                        ) => {
                            let retry_after = match &error {
                                IssueError::Transport(
                                    crate::transport::TransportError::Problem {
                                        retry_after, ..
                                    },
                                ) => retry_after.clone(),
                                _ => None,
                            };
                            record.authorizations[index].acknowledgement =
                                SubmissionState::NotSubmitted;
                            // RFC 8555 §6.6 and RFC 9110 §10.2.3: a rejected
                            // submission still carries a server wait deadline.
                            // Persist it before allowing an explicit retry.
                            schedule_retry(record, retry_after.as_ref(), execution.poll_interval);
                            session.save(record).await?;
                            return Err(error);
                        }
                        Err(error) => return Err(error),
                    };
                    if response.status != reqwest::StatusCode::OK {
                        return Err(IssueError::InvalidInput(
                            "challenge acknowledgement must return 200",
                        ));
                    }
                    let observed: ChallengeObject = serde_json::from_slice(&response.body)
                        .map_err(|_| {
                            IssueError::InvalidInput("malformed challenge acknowledgement response")
                        })?;
                    if !record.challenge.matches_response(&expected, &observed) {
                        return Err(IssueError::InvalidInput(
                            "challenge acknowledgement identity changed",
                        ));
                    }
                    let selected = record.authorizations[index]
                        .resource
                        .challenges
                        .iter_mut()
                        .find(|challenge| challenge.url == url)
                        .ok_or(IssueError::InvalidInput("missing selected challenge"))?;
                    *selected = observed;
                    let Identifier::Dns(identifier) = authorization_identifier(
                        record.authorizations[index].resource.identifier.clone(),
                        record.authorizations[index].resource.wildcard,
                    )?;
                    self.observe(&IssueEvent::ValidationSubmitted {
                        identifier: identifier.value(),
                    });
                    schedule(record, &response, execution.poll_interval);
                    session.save(record).await?;
                }
                ChallengeAction::PollChallenge | ChallengeAction::RefreshAuthorization => {}
            }
        }
        Ok(())
    }

    async fn finalize(
        &self,
        session: &dyn IssueSession,
        record: &mut IssueRecord,
        execution: &IssueExecution,
    ) -> Result<(), IssueError> {
        if matches!(record.finalize_submitted, SubmissionState::Submitted) {
            return Err(IssueError::MutationUncertain(
                "finalize was submitted but the order is still ready",
            ));
        }
        let url = record
            .order
            .as_ref()
            .ok_or(IssueError::InvalidInput("missing order"))?
            .finalize
            .clone();
        let csr = URL_SAFE_NO_PAD.encode(session.csr().await?);
        let body = json_payload(&FinalizeRequest { csr: &csr })?;
        record.finalize_submitted = SubmissionState::Submitted;
        record.phase = IssuancePhase::Finalizing;
        session.save(record).await?;
        if record.expired(time::OffsetDateTime::now_utc()) {
            return Err(IssueError::Expired);
        }
        self.observe(&IssueEvent::Finalizing);
        let response = match bounded(execution, self.post(&url, &body)).await {
            Err(error) => {
                if let IssueError::Transport(crate::transport::TransportError::Problem {
                    status,
                    problem,
                    retry_after,
                }) = &error
                    && (400..500).contains(status)
                {
                    match problem.kind {
                        ProblemKind::BadCsr => {
                            record.finalize_rejection = super::RequestFailure::from_error(&error);
                            session.save(record).await?;
                        }
                        ProblemKind::OrderNotReady => {
                            // RFC 8555 §7.4: this is an explicit refusal, not
                            // an uncertain submission. Query the order next;
                            // only an observed ready state permits another finalize.
                            record.finalize_submitted = SubmissionState::NotSubmitted;
                            record.phase = IssuancePhase::AwaitingOrderReady;
                            schedule_retry(record, retry_after.as_ref(), execution.poll_interval);
                            session.save(record).await?;
                            return Ok(());
                        }
                        ProblemKind::AlreadyReplaced
                        | ProblemKind::AutoRenewalCanceled
                        | ProblemKind::AutoRenewalExpired
                        | ProblemKind::AutoRenewalCancellationInvalid
                        | ProblemKind::AutoRenewalRevocationNotSupported
                        | ProblemKind::AccountDoesNotExist
                        | ProblemKind::AlreadyRevoked
                        | ProblemKind::BadNonce
                        | ProblemKind::BadPublicKey
                        | ProblemKind::BadRevocationReason
                        | ProblemKind::BadSignatureAlgorithm
                        | ProblemKind::Caa
                        | ProblemKind::Compound
                        | ProblemKind::Connection
                        | ProblemKind::Dns
                        | ProblemKind::ExternalAccountRequired
                        | ProblemKind::IncorrectResponse
                        | ProblemKind::InvalidContact
                        | ProblemKind::UnknownDelegation
                        | ProblemKind::Malformed
                        | ProblemKind::OnionCaaRequired
                        | ProblemKind::BadAttestationStatement
                        | ProblemKind::RateLimited
                        | ProblemKind::RejectedIdentifier
                        | ProblemKind::ServerInternal
                        | ProblemKind::Tls
                        | ProblemKind::Unauthorized
                        | ProblemKind::UnsupportedContact
                        | ProblemKind::UnsupportedIdentifier
                        | ProblemKind::UserActionRequired
                        | ProblemKind::Unknown(_) => {
                            // RFC 8555 §§6.7/7.4: an explicit 4xx refusal
                            // permits a later attempt after refreshing the order.
                            record.finalize_submitted = SubmissionState::NotSubmitted;
                            record.phase = IssuancePhase::AwaitingOrderReady;
                            schedule_retry(record, retry_after.as_ref(), execution.poll_interval);
                            session.save(record).await?;
                        }
                    }
                }
                return Err(error);
            }
            Ok(response) => response,
        };
        if response.status != reqwest::StatusCode::OK {
            return Err(IssueError::InvalidInput("finalize must return 200"));
        }
        record.order = Some(parse_order(&response, record)?);
        record.phase = IssuancePhase::AwaitingCertificate;
        schedule(record, &response, execution.poll_interval);
        session.save(record).await
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
                        .unwrap_or(super::PollWaitSource::LocalInterval),
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

fn parse_order(response: &AcmeResponse, record: &IssueRecord) -> Result<OrderObject, IssueError> {
    let order: OrderObject = serde_json::from_slice(&response.body)
        .map_err(|_| IssueError::InvalidInput("malformed order"))?;
    let expected = record
        .identifiers
        .iter()
        .map(crate::identifier::DnsIdentifier::value)
        .collect::<std::collections::BTreeSet<_>>();
    let mut actual = std::collections::BTreeSet::new();
    for wire in &order.identifiers {
        let Identifier::Dns(identifier) = Identifier::try_from(wire.clone())?;
        if !actual.insert(identifier.value()) {
            return Err(IssueError::InvalidInput("duplicate order identifiers"));
        }
    }
    if expected != actual
        || order.authorizations.len() > 100
        || order
            .authorizations
            .iter()
            .map(AcmeUrl::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != order.authorizations.len()
        || matches!(order.status, OrderStatus::Pending | OrderStatus::Valid)
            && order.expires.is_none()
    {
        return Err(IssueError::InvalidInput(
            "CA order identifiers, authorization URLs or expiry are invalid",
        ));
    }
    if let Some(previous) = &record.order
        && (previous.finalize != order.finalize || previous.authorizations != order.authorizations)
    {
        return Err(IssueError::InvalidInput(
            "order's immutable resource URLs changed",
        ));
    }
    // RFC 9773 section 5 requires the exact submitted predecessor on every order
    // observation. Use durable request identity even if directory capabilities change.
    if let Some(expected) = &record.submitted_replaces
        && order.replaces.as_ref() != Some(expected)
    {
        return Err(IssueError::InvalidInput(
            "CA order omitted or changed the renewal replaces identifier",
        ));
    }
    Ok(order)
}

fn schedule(record: &mut IssueRecord, response: &AcmeResponse, fallback: Duration) {
    let retry = crate::transport::retry_after(&response.headers);
    schedule_retry(record, retry.as_ref(), fallback);
}

fn schedule_retry(
    record: &mut IssueRecord,
    retry: Option<&crate::transport::RetryAfter>,
    fallback: Duration,
) {
    let now = time::OffsetDateTime::now_utc();
    tracing::debug!(retry_after = ?retry, local_interval_ms = fallback.as_millis(), "Scheduling next CA poll");
    let source = if retry.is_some() {
        super::PollWaitSource::RetryAfter
    } else {
        super::PollWaitSource::LocalInterval
    };
    let delay = retry
        .map_or(fallback, |hint| match hint {
            crate::transport::RetryAfter::Delay(delay) => *delay,
            crate::transport::RetryAfter::At(at) => at
                .duration_since(std::time::SystemTime::now())
                .unwrap_or(Duration::ZERO),
        })
        .max(Duration::from_millis(100));
    let next = now
        .checked_add(time::Duration::try_from(delay).unwrap_or(time::Duration::MAX))
        .unwrap_or_else(|| time::Date::MAX.midnight().assume_utc());
    if record.next_poll_at.is_none_or(|previous| next >= previous) {
        record.next_poll_at = Some(next);
        record.poll_wait_source = Some(source);
    }
}

fn completed(record: IssueRecord) -> IssueOutcome {
    let cleanup = record
        .authorizations
        .iter()
        .filter(|auth| auth.cleanup_pending)
        .filter_map(|auth| auth.validation_requirement.clone())
        .filter(|requirement| {
            requirement.kind().publication_lifetime() == PublicationLifetime::Temporary
        })
        .collect();
    IssueOutcome::Completed {
        record: Box::new(record),
        cleanup,
    }
}

fn check(execution: &IssueExecution) -> Result<(), IssueError> {
    execution
        .context
        .check()
        .map_err(|_| IssueError::Interrupted)
}

async fn bounded<T>(
    execution: &IssueExecution,
    future: impl std::future::Future<Output = Result<T, IssueError>>,
) -> Result<T, IssueError> {
    check(execution)?;
    tokio::select! {
        biased;
        ()=execution.context.cancellation.cancelled()=>Err(IssueError::Interrupted),
        result=tokio::time::timeout_at(tokio::time::Instant::from_std(execution.context.deadline),future)=>result.map_err(|_|IssueError::Interrupted)?,
    }
}
