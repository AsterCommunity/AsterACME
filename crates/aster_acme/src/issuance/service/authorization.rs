//! Issuance authorization stage.

use crate::issuance::progress::IssueEvent;
use crate::issuance::publication::{checkpoint, outstanding_publications};
use crate::issuance::service::{
    IssueService,
    execution::{bounded, check},
    response::{schedule, schedule_retry},
};
use crate::issuance::{
    AuthorizationRecord, IssueError, IssueExecution, IssueRecord, ValidationRequirement,
};
use crate::solver::ChallengeSolver;
use crate::storage::issuance::IssueSession;
use crate::{
    challenge::PublicationAccountProof,
    identifier::{Identifier, authorization_identifier},
    transport::json_payload,
};
use aster_acme_core::{
    machine::{ChallengeAction, challenge_action},
    protocol::AuthorizationStatus,
    workflow::{IssuancePhase, SubmissionState},
};
use aster_acme_protocol::{
    account::AccountObject,
    order::{AcknowledgeRequest, AuthorizationObject, ChallengeObject},
    url::AcmeUrl,
};
use std::time::Duration;

impl IssueService {
    pub(super) async fn authorization(
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

    pub(super) async fn authorize(
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
    pub(super) async fn verify_account_control(
        &self,
        record: &IssueRecord,
    ) -> Result<(), IssueError> {
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
    pub(super) async fn acknowledge(
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
}
