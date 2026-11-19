//! Issuance order stage.

use crate::issuance::progress::IssueEvent;
use crate::issuance::service::{
    IssueService,
    execution::bounded,
    response::{parse_order, schedule, schedule_retry},
};
use crate::issuance::{IssueError, IssueExecution, IssueRecord};
use crate::storage::issuance::IssueSession;
use crate::transport::json_payload;
use aster_acme_core::workflow::{IssuancePhase, SubmissionState};
use aster_acme_protocol::{
    order::{FinalizeRequest, NewOrderRequest, WireIdentifier},
    problem::ProblemKind,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

impl IssueService {
    pub(super) async fn create(
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
            .map(WireIdentifier::from)
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
                if let Some(failure) = crate::issuance::RequestFailure::from_error(&error) {
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

    pub(super) async fn finalize(
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
                    if !crate::transport::definitive_rejection(*status) {
                        schedule_retry(record, retry_after.as_ref(), execution.poll_interval);
                        session.save(record).await?;
                        return Err(error);
                    }
                    match problem.kind {
                        ProblemKind::BadCsr => {
                            record.finalize_rejection =
                                crate::issuance::RequestFailure::from_error(&error);
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
}
