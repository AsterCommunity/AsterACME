//! RFC 8555 issuance orchestration. All mutations follow durable checkpoints.
use super::progress::{IssueEvent, IssueObserver};
use super::{
    AuthorizationRecord, DnsReadiness, DnsRequirement, IssueError, IssueExecution, IssueIdentity,
    IssueOutcome, IssueRecord, IssueSession,
};
use crate::{
    challenge::{ChallengeKind, ChallengeMaterial, ChallengeToken},
    identifier::{Identifier, authorization_identifier},
    transport::{AcmeClient, AcmeResponse, json_payload},
};
use aster_acme_core::{
    machine::{
        AuthorizationAction, ChallengeAction, OrderAction, authorization_action, challenge_action,
        order_action,
    },
    protocol::{AuthorizationStatus, ChallengeStatus, OrderStatus},
    workflow::{IssuancePhase, SubmissionState},
};
use aster_acme_protocol::{
    order::{
        AcknowledgeRequest, AuthorizationObject, ChallengeObject, FinalizeRequest, NewOrderRequest,
        OrderObject, WireChallengeKind, WireIdentifier,
    },
    problem::ProblemKind,
    url::AcmeUrl,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{sync::Arc, time::Duration};

/// Embeddable issuance service. Caller owns lifetime, account lease and DNS adapter.
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
    ///
    /// # Errors
    /// Never automatically recreates an uncertain order or resubmits an uncertain finalize.
    pub async fn run(
        &self,
        session: &mut dyn IssueSession,
        dns: &dyn DnsReadiness,
        execution: &IssueExecution,
    ) -> Result<IssueOutcome, IssueError> {
        if execution.poll_interval.is_zero() {
            return Err(IssueError::InvalidInput("poll interval must be nonzero"));
        }
        let mut record = session.record().await?;
        let mut last_order_status = None;
        self.check_identity(&record)?;
        if let Some(problem) = &record.finalize_rejection {
            return Err(crate::transport::TransportError::Problem {
                status: 400,
                problem: Box::new(problem.clone()),
                retry_after: None,
            }
            .into());
        }
        if !matches!(
            record.revocation.state,
            aster_acme_core::revocation::RevocationState::NotRequested
        ) {
            return Err(IssueError::InvalidInput(
                "cannot resume an issuance whose certificate revocation is pending or confirmed",
            ));
        }
        if matches!(record.phase, IssuancePhase::Completed) {
            return Ok(completed(
                self.plan_renewal(session, &execution.context).await?,
            ));
        }
        if record.order_url.is_none() {
            self.create(session, &mut record, execution).await?;
        }
        loop {
            check(execution)?;
            if record.expired(time::OffsetDateTime::now_utc()) {
                return Err(IssueError::Expired);
            }
            self.wait(&record, execution).await?;
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
                    if let Some(records) =
                        self.authorize(session, &mut record, dns, execution).await?
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
                    return Ok(completed(record));
                }
            }
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
                    value.split(';').next() != Some("application/pem-certificate-chain")
                })
        {
            return Err(IssueError::InvalidInput(
                "CA returned an invalid certificate media type or status",
            ));
        }
        record.phase = IssuancePhase::Completed;
        session.complete(record, &response.body).await?;
        self.observe(&IssueEvent::CertificateSaved);
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

    fn check_identity(&self, record: &IssueRecord) -> Result<(), IssueError> {
        if record.solver_id != "manual_dns"
            || record.account_id != self.identity.account.account_id
            || record.directory != *self.client.directory_url()
            || record.account_url
                != self
                    .identity
                    .account
                    .account_url
                    .clone()
                    .ok_or(IssueError::InvalidInput("missing account URL"))?
            || record.account_thumbprint != self.identity.account.key_thumbprint
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
        if record.creation_submitted {
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
        record.creation_submitted = true;
        record.phase = IssuancePhase::CreatingOrder;
        session.save(record).await?;
        self.observe(&IssueEvent::CreatingOrder);
        let response = bounded(execution, self.post(endpoint, &body)).await?;
        if response.status != reqwest::StatusCode::CREATED {
            return Err(IssueError::InvalidInput("newOrder must return HTTP 201"));
        }
        // Save the Location before parsing its body; malformed JSON must not lose recovery.
        let location = self.client.account_location(&response)?;
        record.order_url = Some(location.clone());
        session.save(record).await?;
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
                dns: None,
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
        dns: &dyn DnsReadiness,
        execution: &IssueExecution,
    ) -> Result<Option<Vec<DnsRequirement>>, IssueError> {
        record.phase = IssuancePhase::Authorizing;
        let urls = record
            .order
            .as_ref()
            .ok_or(IssueError::InvalidInput("missing order"))?
            .authorizations
            .clone();
        if urls.is_empty() {
            return Err(IssueError::InvalidInput(
                "pending DNS order omitted authorizations",
            ));
        }
        for url in urls {
            bounded(execution, self.authorization(record, &url)).await?;
        }
        // Retain expiry/failure observations even when preparation cannot continue.
        session.save(record).await?;
        let outstanding = prepare_authorizations(record)?;
        session.save(record).await?;
        if !outstanding.is_empty() {
            self.observe(&IssueEvent::PublicationRequired {
                count: outstanding.len(),
            });
            if !bounded(
                execution,
                dns.ready(&outstanding, execution.skip_dns_check, &execution.context),
            )
            .await?
            {
                return Ok(Some(outstanding));
            }
            self.observe(&IssueEvent::DnsReady {
                forced: execution.skip_dns_check,
            });
        }
        self.acknowledge(session, record, execution).await?;
        Ok(None)
    }

    // The notification boundary owns intent, expiry recheck and response identity validation.
    async fn acknowledge(
        &self,
        session: &dyn IssueSession,
        record: &mut IssueRecord,
        execution: &IssueExecution,
    ) -> Result<(), IssueError> {
        for index in 0..record.authorizations.len() {
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
                    let response = bounded(
                        execution,
                        self.post(&url, &json_payload(&AcknowledgeRequest {})?),
                    )
                    .await?;
                    if response.status != reqwest::StatusCode::OK {
                        return Err(IssueError::InvalidInput(
                            "challenge acknowledgement must return 200",
                        ));
                    }
                    let observed: ChallengeObject = serde_json::from_slice(&response.body)
                        .map_err(|_| {
                            IssueError::InvalidInput("malformed challenge acknowledgement response")
                        })?;
                    if observed.url != expected.url
                        || observed.kind != expected.kind
                        || observed.parameters.get("token") != expected.parameters.get("token")
                    {
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
            Err(IssueError::Transport(crate::transport::TransportError::Problem {
                status: 400,
                problem,
                retry_after,
            })) => {
                match &problem.kind {
                    ProblemKind::BadCsr => {
                        record.finalize_rejection = Some(*problem.clone());
                        session.save(record).await?;
                    }
                    // Other problem types do not establish permanent rejection of
                    // this immutable CSR; preserve their existing transport policy.
                    ProblemKind::AlreadyReplaced
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
                    | ProblemKind::Malformed
                    | ProblemKind::OrderNotReady
                    | ProblemKind::RateLimited
                    | ProblemKind::RejectedIdentifier
                    | ProblemKind::ServerInternal
                    | ProblemKind::Tls
                    | ProblemKind::Unauthorized
                    | ProblemKind::UnsupportedContact
                    | ProblemKind::UnsupportedIdentifier
                    | ProblemKind::UserActionRequired
                    | ProblemKind::Unknown(_) => {}
                }
                return Err(crate::transport::TransportError::Problem {
                    status: 400,
                    problem,
                    retry_after,
                }
                .into());
            }
            result => result?,
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
    ) -> Result<(), IssueError> {
        if let Some(at) = record.next_poll_at {
            let delay = (at - time::OffsetDateTime::now_utc())
                .try_into()
                .unwrap_or(Duration::ZERO);
            if !delay.is_zero() {
                self.observe(&IssueEvent::Waiting { delay });
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
    let now = time::OffsetDateTime::now_utc();
    let delay = crate::transport::retry_after(&response.headers)
        .map_or(fallback, |hint| match hint {
            crate::transport::RetryAfter::Delay(delay) => delay,
            crate::transport::RetryAfter::At(at) => at
                .duration_since(std::time::SystemTime::now())
                .unwrap_or(Duration::ZERO),
        })
        .max(Duration::from_millis(100));
    let next = now
        .checked_add(time::Duration::try_from(delay).unwrap_or(time::Duration::MAX))
        .unwrap_or_else(|| time::Date::MAX.midnight().assume_utc());
    record.next_poll_at = Some(
        record
            .next_poll_at
            .map_or(next, |previous| previous.max(next)),
    );
}

fn completed(record: IssueRecord) -> IssueOutcome {
    let cleanup = record
        .authorizations
        .iter()
        .filter(|auth| auth.cleanup_pending)
        .filter_map(|auth| auth.dns.clone())
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

fn prepare_authorizations(record: &mut IssueRecord) -> Result<Vec<DnsRequirement>, IssueError> {
    let mut outstanding = Vec::new();
    for auth in &mut record.authorizations {
        if auth
            .resource
            .expires
            .is_some_and(|expires| expires <= time::OffsetDateTime::now_utc())
        {
            return Err(IssueError::Expired);
        }
        match authorization_action(&auth.resource.status)? {
            AuthorizationAction::AlreadyValid => {}
            AuthorizationAction::ResolveChallenge => {
                let challenge = match &auth.challenge_url {
                    Some(url) => auth
                        .resource
                        .challenges
                        .iter()
                        .find(|challenge| challenge.url == *url),
                    None => auth
                        .resource
                        .challenges
                        .iter()
                        .find(|challenge| matches!(challenge.kind, WireChallengeKind::Dns01)),
                }
                .ok_or(IssueError::InvalidInput(
                    "CA did not offer the selected DNS challenge",
                ))?;
                match &challenge.kind {
                    WireChallengeKind::Dns01 => {}
                    WireChallengeKind::Http01
                    | WireChallengeKind::TlsAlpn01
                    | WireChallengeKind::Unknown(_) => {
                        return Err(IssueError::InvalidInput(
                            "saved challenge is no longer DNS-01",
                        ));
                    }
                }
                let token = challenge
                    .parameters
                    .get("token")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(IssueError::InvalidInput(
                        "DNS-01 challenge omitted its required string token",
                    ))?;
                let Identifier::Dns(identifier) = authorization_identifier(
                    auth.resource.identifier.clone(),
                    auth.resource.wildcard,
                )?;
                let material = ChallengeMaterial::derive(
                    ChallengeKind::Dns01,
                    &identifier,
                    &ChallengeToken::new(token)?,
                    &record.account_thumbprint,
                )?;
                let ChallengeMaterial::Dns01 {
                    record_name,
                    txt_value,
                } = material
                else {
                    return Err(IssueError::InvalidInput("invalid DNS material"));
                };
                let requirement = DnsRequirement {
                    name: record_name.as_str().into(),
                    value: txt_value,
                };
                if auth
                    .dns
                    .as_ref()
                    .is_some_and(|previous| previous != &requirement)
                {
                    return Err(IssueError::InvalidInput("saved challenge token changed"));
                }
                auth.challenge_url = Some(challenge.url.clone());
                auth.dns = Some(requirement.clone());
                auth.cleanup_pending = true;
                match &challenge.status {
                    ChallengeStatus::Pending => {
                        if matches!(auth.acknowledgement, SubmissionState::NotSubmitted) {
                            outstanding.push(requirement);
                        }
                    }
                    ChallengeStatus::Processing | ChallengeStatus::Valid => {}
                    ChallengeStatus::Invalid => {
                        return Err(IssueError::InvalidInput("CA rejected the DNS challenge"));
                    }
                    ChallengeStatus::Unknown(_) => {
                        return Err(IssueError::InvalidInput("unsupported challenge state"));
                    }
                }
            }
        }
    }

    Ok(outstanding)
}
