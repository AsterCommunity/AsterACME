//! RFC 8555 section 7.6 revocation with account or certificate-key authorization.
use crate::revocation::authority::RevocationAuthority;
use crate::{
    issuance::IssueError,
    solver::ExecutionContext,
    storage::revocation::RevocationSession,
    transport::{AcmeClient, AcmeResponse, TransportError, json_payload},
};
use aster_acme_core::revocation::{RevocationAction, RevocationState, revocation_action};
use aster_acme_protocol::{
    problem::ProblemKind,
    revocation::{RevocationReason, RevocationRequest},
    url::AcmeUrl,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use x509_parser::prelude::FromDer as _;

pub mod authority;

/// Caller selection; never inferred from missing account files or a rejected request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevocationSigningMethod {
    /// Authorize with an account kid.
    #[default]
    Account,
    /// Authorize with the certificate public JWK.
    CertificateKey,
}

impl RevocationSigningMethod {
    /// Explicit choices shared by embedders and CLI parsers.
    pub const ALL: [Self; 2] = [Self::Account, Self::CertificateKey];
    /// Stable selection and diagnostic name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::CertificateKey => "certificate-key",
        }
    }
}

/// Known issuer binding; absent for an externally supplied certificate target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationIssuer {
    /// Stable account identity, independent of key rollover.
    pub account_id: String,
    /// Exact kid bound to the original issuer.
    pub account_url: AcmeUrl,
}

/// One exact certificate; no CSR, certificate private key or account is required here.
#[derive(Clone)]
pub struct RevocationTarget {
    /// CA directory supplied by the caller, never guessed from a certificate URL.
    pub directory: AcmeUrl,
    /// One complete DER certificate, not PEM or a chain.
    pub certificate_der: Vec<u8>,
    /// Optional known issuing account restriction for managed certificates.
    pub issuer: Option<RevocationIssuer>,
}

impl RevocationTarget {
    /// Validate structural DER and bind the exact bytes without applying expiry/trust policy.
    /// # Errors
    /// Rejects missing, oversized, malformed or trailing certificate bytes.
    pub fn fingerprint(&self) -> Result<String, IssueError> {
        if self.certificate_der.len() > 1024 * 1024 {
            return Err(IssueError::RevocationInput(
                "revocation certificate exceeds size limit",
            ));
        }
        let (rest, _) = x509_parser::certificate::X509Certificate::from_der(&self.certificate_der)
            .map_err(|_| IssueError::RevocationInput("invalid revocation certificate DER"))?;
        if !rest.is_empty() {
            return Err(IssueError::RevocationInput(
                "trailing revocation certificate DER",
            ));
        }
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&self.certificate_der)))
    }
}

/// Public authority observed for the most recent attempt; never contains a private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "kebab-case")]
pub enum RevocationSigner {
    /// Account identity may survive account-key rollover.
    Account {
        /// Stable local account identity.
        account_id: String,
        /// Exact authenticated account URI.
        account_url: AcmeUrl,
        /// Public key used for this specific attempt, including after rollover.
        key_thumbprint: String,
    },
    /// Public fingerprint of the key matching the certificate.
    CertificateKey {
        /// RFC 7638 public JWK thumbprint.
        key_thumbprint: String,
    },
}

impl RevocationSigner {
    /// Actual authorization mode recorded at the submission boundary.
    #[must_use]
    pub const fn method(&self) -> RevocationSigningMethod {
        match self {
            Self::Account { .. } => RevocationSigningMethod::Account,
            Self::CertificateKey { .. } => RevocationSigningMethod::CertificateKey,
        }
    }
}

/// Revocation intent and confirmed observation, independent of issuance/renewal state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// Pending is an uncertain remote outcome, not successful revocation.
    pub state: RevocationState,
    /// Exact optional reason retained across explicit retries.
    pub reason: Option<RevocationReason>,
    /// Exact target retained across uncertain attempts; required after first submission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha256: Option<String>,
    /// Exact CA directory pinned to the uncertain request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<AcmeUrl>,
    /// Actual authority of the most recent attempt; changing it does not erase prior uncertainty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<RevocationSigner>,
    /// First submission time; confirmation may happen on a later invocation.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub requested_at: Option<time::OffsetDateTime>,
    /// Local time at which the CA confirmed success or alreadyRevoked.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub confirmed_at: Option<time::OffsetDateTime>,
}

impl RevocationRecord {
    /// Bind a requested operation to its target and preserve an uncertain request's reason.
    /// Confirmed results retain their original reason regardless of a repeated CLI option.
    /// # Errors
    /// Rejects target drift, incomplete checkpoints and changed pending reasons.
    pub fn check_request(
        &self,
        target: &RevocationTarget,
        reason: Option<RevocationReason>,
    ) -> Result<(String, Option<RevocationReason>), IssueError> {
        let fingerprint = self.check_target(target)?;
        let requested = reason.or(self.reason);
        match revocation_action(self.state, self.reason == requested) {
            RevocationAction::ReasonConflict => Err(IssueError::RevocationInput(
                "an unconfirmed revocation must retain its original reason",
            )),
            RevocationAction::AlreadyConfirmed => Ok((fingerprint, self.reason)),
            RevocationAction::Submit => Ok((fingerprint, requested)),
        }
    }

    /// Validate the exact target of a saved request, including confirmed local results.
    /// # Errors
    /// Rejects target drift and requested checkpoints lacking their submission binding.
    pub fn check_target(&self, target: &RevocationTarget) -> Result<String, IssueError> {
        let fingerprint = target.fingerprint()?;
        if self.state != RevocationState::NotRequested
            && (self.certificate_sha256.as_ref() != Some(&fingerprint)
                || self.directory.as_ref() != Some(&target.directory)
                || self.signer.is_none()
                || self.requested_at.is_none()
                || self.state == RevocationState::Confirmed && self.confirmed_at.is_none())
        {
            return Err(IssueError::RevocationInput(
                "revocation checkpoint does not match the certificate or lacks submission identity",
            ));
        }
        Ok(fingerprint)
    }
}

/// One submission path; authority selection cannot introduce an account prerequisite.
pub struct RevocationService {
    client: Arc<AcmeClient>,
    authority: RevocationAuthority,
}

impl RevocationService {
    /// Bind the discovered CA and explicit authority. The caller owns the execution lease.
    #[must_use]
    pub fn new(client: Arc<AcmeClient>, authority: RevocationAuthority) -> Self {
        Self { client, authority }
    }

    /// Revoke the session's immutable certificate. Explicit retries retain its DER and reason.
    /// # Errors
    /// Rejects identity drift, malformed/mismatched keys, checkpoint failures and CA errors.
    /// Cancellation or an unknown response retains pending intent; only badNonce is retried.
    pub async fn revoke(
        &self,
        session: &mut dyn RevocationSession,
        reason: Option<RevocationReason>,
        execution: &ExecutionContext,
    ) -> Result<RevocationRecord, IssueError> {
        execution
            .check()
            .map_err(|_| IssueError::RevocationInterrupted)?;
        let target = session.target().await?;
        if target.directory != *self.client.directory_url() {
            return Err(IssueError::RevocationInput(
                "revocation CA directory changed",
            ));
        }
        let mut record = session.revocation().await?;
        let (fingerprint, reason) = record.check_request(&target, reason)?;
        if record.state == RevocationState::Confirmed {
            return Ok(record);
        }
        let authority = self.authority.authorize(&target)?;
        let endpoint =
            self.client
                .directory()
                .revoke_cert
                .as_ref()
                .ok_or(IssueError::RevocationInput(
                    "CA does not advertise certificate revocation",
                ))?;
        let payload = json_payload(&RevocationRequest {
            certificate: URL_SAFE_NO_PAD.encode(&target.certificate_der),
            reason,
        })?;
        let previous = record.clone();
        record.state = RevocationState::Pending;
        record.reason = reason;
        record.certificate_sha256 = Some(fingerprint);
        record.directory = Some(target.directory.clone());
        record.signer = Some(authority.observation);
        record
            .requested_at
            .get_or_insert_with(time::OffsetDateTime::now_utc);
        let submitted = AtomicBool::new(false);
        let intent_attempted = AtomicBool::new(false);
        let response = bounded(
            execution,
            self.client.signed_observed(
                endpoint,
                authority.signer,
                authority.kid,
                &payload,
                &submitted,
                || async {
                    intent_attempted.store(true, Ordering::SeqCst);
                    session
                        .save_revocation(&record)
                        .await
                        .map_err(|error| error.to_string())?;
                    execution
                        .check()
                        .map_err(|_| "revocation interrupted before submission".to_owned())
                },
            ),
        )
        .await;
        // A failed first attempt known not to have been sent must not create uncertainty.
        // Existing pending evidence always survives, including after an identity change.
        if response.is_err() && !submitted.load(Ordering::SeqCst) {
            if intent_attempted.load(Ordering::SeqCst) {
                session.save_revocation(&previous).await?;
            }
            if execution.check().is_err() {
                return Err(IssueError::RevocationInterrupted);
            }
            return response.map(|_| record);
        }
        classify(response, &previous, &mut record, session).await?;
        Ok(record)
    }
}

async fn classify(
    response: Result<AcmeResponse, IssueError>,
    previous: &RevocationRecord,
    record: &mut RevocationRecord,
    session: &dyn RevocationSession,
) -> Result<(), IssueError> {
    match response {
        Ok(response) if response.status == reqwest::StatusCode::OK => {}
        Err(IssueError::Transport(TransportError::Problem {
            status: 400,
            ref problem,
            ..
        })) if problem.kind == ProblemKind::AlreadyRevoked => {}
        Err(IssueError::Transport(error)) => {
            if previous.state == RevocationState::NotRequested
                && matches!(
                    error,
                    TransportError::Problem {
                        status: 400..=499,
                        ..
                    }
                )
            {
                session
                    .save_revocation(&RevocationRecord::default())
                    .await?;
                return Err(error.into());
            }
            return Err(IssueError::RevocationUncertain(error));
        }
        Err(error) => return Err(error),
        Ok(response) => {
            return Err(IssueError::RevocationUncertain(
                TransportError::HttpStatus {
                    status: response.status.as_u16(),
                    retry_after: crate::transport::retry_after(&response.headers),
                },
            ));
        }
    }
    record.state = RevocationState::Confirmed;
    record.confirmed_at = Some(time::OffsetDateTime::now_utc());
    session.save_revocation(record).await
}

async fn bounded(
    execution: &ExecutionContext,
    future: impl std::future::Future<Output = Result<AcmeResponse, TransportError>>,
) -> Result<AcmeResponse, IssueError> {
    execution
        .check()
        .map_err(|_| IssueError::RevocationInterrupted)?;
    tokio::select! {
        biased;
        ()=execution.cancellation.cancelled()=>Err(IssueError::RevocationInterrupted),
        result=tokio::time::timeout_at(execution.deadline.into(),future)=>result.map_err(|_|IssueError::RevocationInterrupted)?.map_err(IssueError::Transport),
    }
}

#[cfg(test)]
mod tests;
