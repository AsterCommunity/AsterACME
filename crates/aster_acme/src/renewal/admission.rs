//! Renewal eligibility and recovery from saved observations; no clocks, locks or files.
use crate::issuance::{IssueError, IssueRecord, RenewalPredecessor, RenewalRetryState};
use aster_acme_core::renewal::{RenewalDecision, RetryAdmission, renewal_decision};
use time::OffsetDateTime;

/// Failure evidence the execution host asks the storage session to checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalFailure {
    pub occurred_at: OffsetDateTime,
    pub ca_retry_at: Option<OffsetDateTime>,
    pub blocked_reason: Option<String>,
}

impl IssueRecord {
    /// Classify a failed foreground attempt from its saved protocol evidence.
    /// Returns None for initial issuance or terminal/completed records.
    #[must_use]
    pub fn renewal_failure(&self, occurred_at: OffsetDateTime) -> Option<RenewalFailure> {
        if self.renewal_of.is_none() || !self.unfinished() {
            return None;
        }
        let blocked_reason = if self.new_order_intent_saved
            && self.order_url.is_none()
            && self.creation_failure.is_none()
        {
            Some("newOrder may have been accepted but no Location was saved".into())
        } else if self
            .creation_failure
            .as_ref()
            .is_some_and(|failure| failure.status == 408 || failure.status >= 500)
        {
            Some("newOrder response does not establish whether the CA accepted the order".into())
        } else {
            None
        };
        let ca_retry_at = [
            self.creation_failure
                .as_ref()
                .and_then(|failure| failure.retry_at),
            self.finalize_rejection
                .as_ref()
                .and_then(|failure| failure.retry_at),
        ]
        .into_iter()
        .flatten()
        .max()
        .or_else(|| {
            (self.poll_wait_source == Some(crate::issuance::PollWaitSource::RetryAfter))
                .then_some(self.next_poll_at)
                .flatten()
        });
        Some(RenewalFailure {
            occurred_at,
            ca_retry_at,
            blocked_reason,
        })
    }
}

/// A renewal admission failure, independent of storage and publication adapters.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// An earlier attempt may have changed the CA and needs explicit reconciliation.
    #[error("automatic renewal is blocked by an uncertain prior result: {0}")]
    Uncertain(String),
    /// Operator intent cannot override a CA-imposed minimum deadline.
    #[error("CA Retry-After has not elapsed; --now cannot bypass it")]
    CaBackoff,
    /// The selected certificate does not carry an issuance-owned renewal plan.
    #[error("in_use certificate has no renewal plan")]
    MissingPlan,
    /// Revocation must be reconciled before another issuance is admitted.
    #[error("certificate revocation is unconfirmed; resolve it before renewing")]
    RevocationUncertain,
    /// Choosing between saved requests requires explicit operator input.
    #[error("several unfinished renewals match in_use; select an exact operation")]
    Ambiguous,
}

/// An admitted foreground action; refusals are returned as typed errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalAdmission {
    /// Preserve the selected certificate without allocating another generation.
    NotDue,
    /// Allocate a new fixed key/CSR generation after checking saved child evidence.
    Start,
    /// Reuse an existing generation without regenerating its material.
    Resume,
}

/// Decide whether the selected certificate may start or resume a foreground renewal.
/// The adapter must first revalidate the live selection under its certificate lease.
///
/// # Errors
/// Rejects uncertain attempts, unelapsed CA deadlines, missing plans and uncertain revocation.
pub fn request(
    current: &IssueRecord,
    generations: &[IssueRecord],
    immediate: bool,
    now: OffsetDateTime,
) -> Result<RenewalAdmission, IssueError> {
    if let Some(retry) = &current.renewal_retry {
        match retry.admission(now, immediate) {
            RetryAdmission::Uncertain => {
                return Err(AdmissionError::Uncertain(
                    retry.blocked_reason.clone().unwrap_or_default(),
                )
                .into());
            }
            RetryAdmission::CaBackoff => {
                return Err(AdmissionError::CaBackoff.into());
            }
            RetryAdmission::LocalBackoff => return Ok(RenewalAdmission::NotDue),
            RetryAdmission::Ready => {}
        }
    }
    let pending = generations.iter().any(|record| {
        record.resume_candidate()
            && !record.expired(now)
            && record
                .renewal_of
                .as_ref()
                .is_some_and(|previous| previous.operation_id == current.operation_id)
    });
    let due = current
        .renewal
        .as_ref()
        .ok_or(AdmissionError::MissingPlan)?;
    let decision = renewal_decision(
        pending,
        current.revocation.state,
        due.renew_at,
        now,
        immediate,
    );
    match decision {
        RenewalDecision::RevocationUncertain => Err(AdmissionError::RevocationUncertain.into()),
        RenewalDecision::NotDue => Ok(RenewalAdmission::NotDue),
        RenewalDecision::Start => Ok(RenewalAdmission::Start),
        RenewalDecision::Resume => Ok(RenewalAdmission::Resume),
    }
}

/// Calculate a retry checkpoint for one admitted preparation failure.
/// Identity and previous-checkpoint comparisons remain the adapter's atomic write condition.
#[must_use]
pub fn preparation_failure(
    current: &IssueRecord,
    immediate: bool,
    now: OffsetDateTime,
) -> Option<RenewalRetryState> {
    if !current.deployment_eligible()
        || current
            .renewal
            .as_ref()
            .is_none_or(|plan| !immediate && plan.renew_at > now)
        || current
            .renewal_retry
            .as_ref()
            .is_some_and(|retry| retry.admission(now, immediate) != RetryAdmission::Ready)
    {
        return None;
    }
    Some(RenewalRetryState::after_failure(
        current.renewal_retry.as_ref(),
        now,
        None,
        None,
    ))
}

/// Choose one resumable child, retaining submission barriers even if the parent
/// retry checkpoint was never written. The adapter supplies observations from its lease.
///
/// # Errors
/// Rejects unknown newOrder results, outstanding CA deadlines and ambiguous children.
pub fn existing<'a>(
    generations: &'a [IssueRecord],
    previous: Option<&RenewalPredecessor>,
    now: OffsetDateTime,
) -> Result<Option<&'a IssueRecord>, IssueError> {
    let Some(previous) = previous else {
        return Ok(None);
    };
    for record in generations
        .iter()
        .filter(|record| record.unfinished() && record.renewal_of.as_ref() == Some(previous))
    {
        if let Some(response) = &record.finalize_rejection
            && response.retry_at.is_some_and(|at| at > now)
        {
            return Err(response.error());
        }
        if let Some(response) = &record.creation_failure {
            if !(400..500).contains(&response.status) || response.status == 408 {
                return Err(IssueError::MutationUncertain(
                    "previous newOrder outcome is unconfirmed",
                ));
            }
            if response.retry_at.is_some_and(|at| at > now) {
                return Err(response.error());
            }
        } else if record.new_order_intent_saved && record.order_url.is_none() {
            return Err(IssueError::CreationUncertain);
        }
    }
    let mut pending = generations.iter().filter(|record| {
        record.resume_candidate()
            && !record.expired(now)
            && record.renewal_of.as_ref() == Some(previous)
    });
    let first = pending.next();
    if pending.next().is_some() {
        return Err(AdmissionError::Ambiguous.into());
    }
    Ok(first)
}

#[cfg(test)]
mod tests;
