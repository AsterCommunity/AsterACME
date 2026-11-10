//! Account-signed RFC 8555 section 7.6 revocation of a saved certificate generation.
use crate::{
    issuance::{IssueError, IssueIdentity, IssueRecord, IssueSession},
    transport::{AcmeClient, TransportError, json_payload},
};
use aster_acme_core::{
    revocation::{RevocationAction, RevocationState, revocation_action},
    workflow::IssuancePhase,
};
use aster_acme_protocol::{
    problem::ProblemKind,
    revocation::{RevocationReason, RevocationRequest},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Revocation intent and confirmed observation, independent of issuance/renewal state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// Pending is an uncertain remote outcome, not successful revocation.
    pub state: RevocationState,
    /// Exact optional reason retained across explicit retries.
    pub reason: Option<RevocationReason>,
    /// First submission time; confirmation may happen on a later invocation.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub requested_at: Option<time::OffsetDateTime>,
    /// Local time at which the CA confirmed success or alreadyRevoked.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub confirmed_at: Option<time::OffsetDateTime>,
}

/// Revokes with the issuing account key. Certificate-key signing is not implemented.
pub struct RevocationService {
    client: Arc<AcmeClient>,
    identity: IssueIdentity,
}

impl RevocationService {
    /// Bind the discovered CA and issuing account; the caller holds its account lease.
    #[must_use]
    pub fn new(client: Arc<AcmeClient>, identity: IssueIdentity) -> Self {
        Self { client, identity }
    }

    /// Revoke one exact saved generation, preserving its files and durable intent.
    /// Only badNonce is automatically retried by transport; a timeout remains pending.
    /// An explicit subsequent invocation may repeat the same reason safely.
    ///
    /// # Errors
    /// Rejects unsupported endpoints, identity mismatch, unissued artifacts, reason
    /// changes while pending, protocol/transport failure and failed persistence.
    pub async fn revoke(
        &self,
        session: &mut dyn IssueSession,
        reason: Option<RevocationReason>,
    ) -> Result<IssueRecord, IssueError> {
        let mut record = session.record().await?;
        let reason = reason.or(record.revocation.reason);
        match revocation_action(
            matches!(record.phase, IssuancePhase::Completed),
            record.revocation.state,
            record.revocation.reason == reason,
        ) {
            RevocationAction::NotIssued => {
                return Err(IssueError::InvalidInput(
                    "only an issued certificate can be revoked",
                ));
            }
            RevocationAction::ReasonConflict => {
                return Err(IssueError::InvalidInput(
                    "an unconfirmed revocation must retain its original reason",
                ));
            }
            RevocationAction::AlreadyConfirmed => return Ok(record),
            RevocationAction::Submit => {}
        }
        let account = &self.identity.account;
        if !account.is_usable()
            || record.directory != *self.client.directory_url()
            || record.directory != account.directory_url
            || record.account_id != account.account_id
            || account.account_url.as_ref() != Some(&record.account_url)
            || self.identity.signer.jwk()?.thumbprint()? != account.key_thumbprint
        {
            return Err(IssueError::InvalidInput(
                "revocation requires the matching active issuing account",
            ));
        }
        let endpoint =
            self.client
                .directory()
                .revoke_cert
                .as_ref()
                .ok_or(IssueError::InvalidInput(
                    "CA does not advertise certificate revocation",
                ))?;
        let payload = json_payload(&RevocationRequest {
            certificate: URL_SAFE_NO_PAD.encode(session.certificate_der().await?),
            reason,
        })?;
        let previously_pending = matches!(record.revocation.state, RevocationState::Pending);
        record.revocation.state = RevocationState::Pending;
        record.revocation.reason = reason;
        record
            .revocation
            .requested_at
            .get_or_insert_with(time::OffsetDateTime::now_utc);
        session.save(&record).await?;
        let response = self
            .client
            .signed(
                endpoint,
                self.identity.signer.as_ref(),
                Some(&record.account_url),
                &payload,
            )
            .await;
        match response {
            Ok(response) if response.status == reqwest::StatusCode::OK => {}
            Err(TransportError::Problem {
                status: 400,
                ref problem,
                ..
            }) if matches!(problem.kind, ProblemKind::AlreadyRevoked) => {}
            Ok(response) => {
                return Err(IssueError::RevocationUncertain(
                    TransportError::HttpStatus {
                        status: response.status.as_u16(),
                        retry_after: crate::transport::retry_after(&response.headers),
                    },
                ));
            }
            Err(error) => {
                // A valid 4xx problem is an explicit refusal of this invocation.
                // A previous uncertain invocation is not disproven by a later refusal.
                // Transport failures, 5xx and unstructured responses remain uncertain.
                if !previously_pending
                    && let TransportError::Problem {
                        status: 400..=499, ..
                    } = &error
                {
                    record.revocation = RevocationRecord::default();
                    session.save(&record).await?;
                    return Err(error.into());
                }
                return Err(IssueError::RevocationUncertain(error));
            }
        }
        record.revocation.state = RevocationState::Confirmed;
        record.revocation.confirmed_at = Some(time::OffsetDateTime::now_utc());
        session.save(&record).await?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests;
