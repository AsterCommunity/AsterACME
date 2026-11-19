//! Issuance record contracts.
use crate::issuance::{
    AuthorizationRecord, CertificateName, IssueError, IssueRequest, PollWaitSource,
    RenewalPredecessor, RenewalRetryState, RequestFailure, ValidationRequirement,
};
use crate::{account::AccountRecord, identifier::Identifier};
use aster_acme_core::workflow::{IssuancePhase, SubmissionState};
use aster_acme_protocol::{order::OrderObject, url::AcmeUrl};
use serde::{Deserialize, Serialize};

/// A generation and its remote order, with no private keys or provider credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRecord {
    /// Immutable selected ACME verification method.
    pub challenge: crate::challenge::ChallengeKind,
    /// Non-secret implementation configuration, interpreted only by the caller.
    pub solver_config: serde_json::Value,
    /// Adapter-provided `in_use` selection snapshot; never persisted in the journal.
    #[serde(skip)]
    pub is_in_use: bool,
    /// Adapter-provided deployment binding count; `None` means unavailable.
    /// This local inventory snapshot is never persisted in the issuance journal.
    #[serde(skip)]
    pub deployment_count: Option<usize>,
    /// Previous `in_use` generation; retained across retries and restart.
    #[serde(default)]
    pub renewal_of: Option<RenewalPredecessor>,
    /// Publication adapter identity, retained so resume never selects a different method.
    pub solver_id: String,
    /// Internal opaque unique ID, selectable explicitly for scripts.
    pub operation_id: String,
    /// Long-lived certificate name.
    pub name: CertificateName,
    /// UTC local request creation time, not the CA's timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    /// Fixed account binding; rename/replacement must not silently retarget recovery.
    pub account_name: String,
    /// Account's stable identity.
    pub account_id: String,
    /// Directory bound at creation.
    pub directory: AcmeUrl,
    /// Original kid; invariant through this generation.
    pub account_url: AcmeUrl,
    /// Thumbprint used to derive the outstanding key authorizations.
    pub account_thumbprint: String,
    /// Immutable certificate key choice used by this generation.
    pub key_algorithm: crate::crypto::key_algorithm::KeyAlgorithm,
    /// Ordered canonical DNS and IP identifiers.
    pub identifiers: Vec<Identifier>,
    /// Local execution stage, independent of order status.
    pub phase: IssuancePhase,
    /// `NewOrder` intent was durably saved before sending; without a Location the
    /// remote outcome is uncertain, even if the process stopped before the POST.
    pub new_order_intent_saved: bool,
    /// A complete newOrder error response; no Order status is inferred from it.
    pub creation_failure: Option<RequestFailure>,
    /// Actual RFC 9773 replaces value selected before newOrder; a refreshed directory
    /// cannot change the submitted request identity during recovery.
    #[serde(default)]
    pub submitted_replaces: Option<String>,
    /// Exact Location returned by newOrder.
    pub order_url: Option<AcmeUrl>,
    /// Most recent CA snapshot.
    pub order: Option<OrderObject>,
    /// Authorizations and publication checkpoints.
    pub authorizations: Vec<AuthorizationRecord>,
    /// Saved before finalize; the same CSR is never regenerated or silently replaced.
    pub finalize_submitted: SubmissionState,
    /// Explicit CA rejection of this fixed CSR. Later changes to a reused order
    /// cannot turn this generation into a different certificate/key identity.
    #[serde(default)]
    pub finalize_rejection: Option<RequestFailure>,
    /// Earliest next query, respecting CA Retry-After across process restart.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub next_poll_at: Option<time::OffsetDateTime>,
    /// Source of the persisted query deadline; retained across recovery.
    pub poll_wait_source: Option<PollWaitSource>,
    /// Certificate revocation is independent of issuance completion.
    #[serde(default)]
    pub revocation: crate::revocation::RevocationRecord,
    /// Durable renewal schedule, available only after certificate validation.
    #[serde(default)]
    pub renewal: Option<crate::renewal::RenewalPlan>,
    /// Backoff for renewal attempts against this generation while it remains in use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_retry: Option<RenewalRetryState>,
}

impl IssueRecord {
    /// Long-lived publication carried forward from the confirmed generation.
    /// Current observations replace the same method-owned publication scope;
    /// unrefreshed scopes survive CA authorization reuse without history growth.
    #[must_use]
    pub fn retained_validation_requirements(&self) -> Vec<ValidationRequirement> {
        let retain = |requirement: &&ValidationRequirement| {
            requirement.kind() == self.challenge
                && requirement.kind().publication_lifetime()
                    == crate::challenge::PublicationLifetime::Persistent
        };
        let current = self
            .authorizations
            .iter()
            .filter_map(|auth| auth.validation_requirement.as_ref())
            .filter(retain)
            .cloned()
            .collect::<Vec<_>>();
        let mut retained = Vec::new();
        for requirement in &current {
            if !retained.contains(requirement) {
                retained.push(requirement.clone());
            }
        }
        if let Some(previous) = &self.renewal_of {
            for requirement in previous.retained_validation.iter().filter(retain) {
                if !current
                    .iter()
                    .any(|current| current.same_publication_scope(requirement))
                    && !retained.contains(requirement)
                {
                    retained.push(requirement.clone());
                }
            }
        }
        retained
    }

    /// Expiration of the verified leaf certificate, recorded by its renewal plan.
    #[must_use]
    pub fn certificate_not_after(&self) -> Option<time::OffsetDateTime> {
        self.renewal.as_ref().map(|plan| plan.not_after)
    }

    /// Whether this completed local generation can be offered for deployment.
    /// The storage adapter must additionally verify it is still the selected version.
    #[must_use]
    pub fn deployment_eligible(&self) -> bool {
        self.phase == IssuancePhase::Completed
            && self.revocation.state == aster_acme_core::revocation::RevocationState::NotRequested
    }

    /// Human-readable immutable directory name: UTC request time plus random ID prefix.
    #[must_use]
    pub fn generation_name(&self) -> String {
        let at = self.created_at.to_offset(time::UtcOffset::UTC);
        let suffix = self.operation_id.chars().take(8).collect::<String>();
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z-{suffix}",
            at.year(),
            u8::from(at.month()),
            at.day(),
            at.hour(),
            at.minute(),
            at.second()
        )
    }

    /// Match an unfinished saved request against a complete desired definition.
    /// Domain ordering is presentation only; CA/account/method/config/key must match.
    /// Rejected/expired requests are excluded. Unconfirmed creation remains a candidate
    /// so callers must explicitly choose recovery/new issuance; matching never authorizes
    /// replaying a submitted newOrder without its saved Location.
    #[must_use]
    pub fn matches_unfinished_request(
        &self,
        request: &IssueRequest,
        account: &AccountRecord,
        now: time::OffsetDateTime,
    ) -> bool {
        self.unfinished()
            && self.creation_failure.is_none()
            && self.authorization_failure().is_none()
            && self.finalize_rejection.is_none()
            && !self.expired(now)
            && matches!(
                self.revocation.state,
                aster_acme_core::revocation::RevocationState::NotRequested
            )
            && self.order.as_ref().is_none_or(|order| {
                !matches!(
                    order.status,
                    aster_acme_core::protocol::OrderStatus::Invalid
                )
            })
            && (self.order.as_ref().is_some_and(|order| {
                matches!(order.status, aster_acme_core::protocol::OrderStatus::Valid)
            }) || self.authorizations.iter().all(|auth| {
                matches!(
                    auth.resource.status,
                    aster_acme_core::protocol::AuthorizationStatus::Pending
                        | aster_acme_core::protocol::AuthorizationStatus::Valid
                ) && auth.resource.expires.is_none_or(|expires| expires > now)
            }))
            && self.account_id == account.account_id
            && self.account_name == request.account_name
            && self.directory == account.directory_url
            && account.account_url.as_ref() == Some(&self.account_url)
            && self.challenge == request.challenge
            && self.solver_id == request.solver_id
            && self.solver_config == request.solver_config
            && self.key_algorithm == request.key_algorithm
            && self.identifiers.len() == request.identifiers.len()
            && self
                .identifiers
                .iter()
                .all(|identifier| request.identifiers.contains(identifier))
    }

    /// Reject deterministic recovery failures before transport discovery or mutations.
    /// This cannot reconstruct a missing newOrder Location and never authorizes replay.
    ///
    /// # Errors
    /// Reports rejected fixed CSR, unknown creation outcome or saved order expiry.
    pub fn check_recovery(&self, now: time::OffsetDateTime) -> Result<(), IssueError> {
        if let Some(problem) = &self.finalize_rejection {
            return Err(problem.error());
        }
        if let Some(failure) = &self.creation_failure {
            return Err(failure.error());
        }
        if self.order.as_ref().is_some_and(|order| {
            matches!(
                order.status,
                aster_acme_core::protocol::OrderStatus::Invalid
            )
        }) {
            return Err(IssueError::InvalidOrder {
                problem: self.failure_problem().cloned().map(Box::new),
            });
        }
        if self.new_order_intent_saved && self.order_url.is_none() {
            return Err(IssueError::CreationUncertain);
        }
        if let Some(error) = self.authorization_failure() {
            return Err(error);
        }
        if self.expired(now) {
            return Err(IssueError::Expired);
        }
        Ok(())
    }

    /// An unissued request with affirmative, terminal failure evidence.
    /// Unknown network outcomes and deferred 408/429/5xx responses are retained;
    /// being absent from resume candidates alone never authorizes deletion.
    #[must_use]
    pub fn failed_unresumable(&self, now: time::OffsetDateTime) -> bool {
        use aster_acme_core::protocol::OrderStatus;
        self.unfinished()
            && self.certificate_not_after().is_none()
            && !self
                .order
                .as_ref()
                .is_some_and(|order| matches!(order.status, OrderStatus::Valid))
            && (self
                .creation_failure
                .as_ref()
                .is_some_and(|failure| crate::transport::definitive_rejection(failure.status))
                || self.finalize_rejection.is_some()
                || self.authorization_failure().is_some()
                || self
                    .order
                    .as_ref()
                    .is_some_and(|order| matches!(order.status, OrderStatus::Invalid))
                || (self.expired(now)
                    && !(self.finalize_submitted == SubmissionState::Submitted
                        && self.finalize_rejection.is_none())))
    }

    /// Known terminal orders are retained for inspection but excluded from resume selection.
    #[must_use]
    pub fn resume_candidate(&self) -> bool {
        self.unfinished()
            && self.creation_failure.is_none()
            && self.finalize_rejection.is_none()
            && self.authorization_failure().is_none()
            && !self.order.as_ref().is_some_and(|order| {
                matches!(
                    order.status,
                    aster_acme_core::protocol::OrderStatus::Invalid
                )
            })
    }

    /// Prefer the order explanation; fall back to an authorization's challenge problem.
    #[must_use]
    pub fn failure_problem(&self) -> Option<&aster_acme_protocol::problem::Problem> {
        self.creation_failure
            .as_ref()
            .and_then(|failure| failure.problem.as_ref())
            .or_else(|| {
                self.finalize_rejection
                    .as_ref()
                    .and_then(|failure| failure.problem.as_ref())
            })
            .or_else(|| {
                self.order
                    .as_ref()
                    .and_then(|order| order.error.as_ref())
                    .or_else(|| {
                        self.authorizations
                            .iter()
                            .flat_map(|auth| &auth.resource.challenges)
                            .find_map(|challenge| challenge.error.as_ref())
                    })
            })
    }

    /// Terminal authorization/challenge observations are distinct from order invalid.
    /// An already-valid order may still be downloaded despite expired authorization history.
    #[must_use]
    pub fn authorization_failure(&self) -> Option<IssueError> {
        use aster_acme_core::protocol::{AuthorizationStatus, ChallengeStatus, OrderStatus};
        if self
            .order
            .as_ref()
            .is_some_and(|order| matches!(order.status, OrderStatus::Valid))
        {
            return None;
        }
        for auth in &self.authorizations {
            let selected = auth.resource.challenges.iter().find(|challenge| {
                auth.challenge_url.as_ref().map_or_else(
                    || crate::challenge::known_method(&challenge.kind) == Some(self.challenge),
                    |url| &challenge.url == url,
                )
            });
            let failed = match auth.resource.status {
                AuthorizationStatus::Invalid
                | AuthorizationStatus::Deactivated
                | AuthorizationStatus::Expired
                | AuthorizationStatus::Revoked => true,
                AuthorizationStatus::Pending
                | AuthorizationStatus::Valid
                | AuthorizationStatus::Unknown(_) => false,
            };
            if failed
                || (matches!(auth.resource.status, AuthorizationStatus::Pending)
                    && selected.is_some_and(|challenge| {
                        matches!(challenge.status, ChallengeStatus::Invalid)
                    }))
            {
                return Some(IssueError::AuthorizationFailed {
                    status: auth.resource.status.clone(),
                    problem: selected
                        .and_then(|c| c.error.clone())
                        .or_else(|| {
                            auth.resource
                                .challenges
                                .iter()
                                .find_map(|c| c.error.clone())
                        })
                        .map(Box::new),
                });
            }
        }
        None
    }

    /// Pending operations can be selected for recovery; expiry is reported separately.
    #[must_use]
    pub fn unfinished(&self) -> bool {
        !matches!(self.phase, IssuancePhase::Completed)
    }
    /// Local observation of expiry; a valid issued order can still be downloaded.
    #[must_use]
    pub fn expired(&self, now: time::OffsetDateTime) -> bool {
        self.order.as_ref().is_some_and(|order| {
            !matches!(order.status, aster_acme_core::protocol::OrderStatus::Valid)
                && order.expires.is_some_and(|expires| expires <= now)
        })
    }

    /// Whether external temporary publications are safe to clean up without risking
    /// an order that can still issue a certificate or has an unknown finalize result.
    #[must_use]
    pub fn publication_cleanup_eligible(&self, now: time::OffsetDateTime) -> bool {
        self.phase == IssuancePhase::Completed
            || self.finalize_rejection.is_some()
            || self.authorization_failure().is_some()
            || self.order.as_ref().is_some_and(|order| {
                matches!(
                    order.status,
                    aster_acme_core::protocol::OrderStatus::Invalid
                )
            })
            || (self.finalize_submitted != SubmissionState::Submitted
                && self.expired(now)
                && self.order.as_ref().is_some_and(|order| {
                    matches!(
                        order.status,
                        aster_acme_core::protocol::OrderStatus::Pending
                            | aster_acme_core::protocol::OrderStatus::Ready
                    )
                }))
    }
}
