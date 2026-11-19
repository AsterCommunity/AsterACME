//! Issuance retry contracts.
use crate::issuance::{IssueError, ValidationRequirement};
use serde::{Deserialize, Serialize};

/// Immutable predecessor linking a renewal generation to its original `in_use` certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalPredecessor {
    /// Exact previous local generation, not a DNS name or CA order identifier.
    pub operation_id: String,
    /// [RFC 9773](https://datatracker.ietf.org/doc/html/rfc9773) identifier, absent when the certificate cannot provide one.
    pub certificate_id: Option<String>,
    /// Confirmed persistent records captured under the predecessor lease.
    /// They retain historical-key binding across account rollover without
    /// assuming that a freshly derived record has already been published.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained_validation: Vec<ValidationRequirement>,
}

/// Why the next CA query must wait. This records the winning deadline, not an
/// unparsed HTTP header; a minimum delay still avoids a zero-delay busy loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PollWaitSource {
    /// The CA's Retry-After deadline won over the configured interval.
    RetryAfter,
    /// The configured polling interval applied; the CA gave no usable deadline.
    LocalInterval,
}

/// Durable HTTP error evidence, independent of any ACME resource status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestFailure {
    /// Actual HTTP status, independent of the optional problem body.
    pub status: u16,
    /// Structured [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) problem, including unknown extensions and subproblems.
    pub problem: Option<aster_acme_protocol::problem::Problem>,
    /// Absolute retry deadline computed when the response was received.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub retry_at: Option<time::OffsetDateTime>,
}

impl RequestFailure {
    /// Retain complete HTTP failures only; dropped/malformed responses remain uncertain.
    pub(crate) fn from_error(error: &IssueError) -> Option<Self> {
        use crate::transport::{RetryAfter, TransportError};
        let (status, problem, retry) = match error {
            IssueError::Transport(TransportError::Problem {
                status,
                problem,
                retry_after,
            }) => (*status, Some(*problem.clone()), retry_after),
            IssueError::Transport(TransportError::HttpStatus {
                status,
                retry_after,
            }) => (*status, None, retry_after),
            _ => return None,
        };
        let retry_at = retry.as_ref().and_then(|retry| match retry {
            RetryAfter::Delay(delay) => time::Duration::try_from(*delay)
                .ok()
                .and_then(|delay| time::OffsetDateTime::now_utc().checked_add(delay)),
            RetryAfter::At(at) => Some(time::OffsetDateTime::from(*at)),
        });
        Some(Self {
            status,
            problem,
            retry_at,
        })
    }

    /// Recreate the original response diagnostic without inventing an HTTP status.
    #[must_use]
    pub fn error(&self) -> IssueError {
        let retry_after = self
            .retry_at
            .map(|at| crate::transport::RetryAfter::At(at.into()));
        match &self.problem {
            Some(problem) => crate::transport::TransportError::Problem {
                status: self.status,
                problem: Box::new(problem.clone()),
                retry_after,
            }
            .into(),
            None => crate::transport::TransportError::HttpStatus {
                status: self.status,
                retry_after,
            }
            .into(),
        }
    }
}

/// Automatic renewal retry state attached to the still-selected predecessor.
/// Historical issue records remain the source of the failed attempt details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalRetryState {
    /// Consecutive failed attempts for this selected certificate generation.
    pub failures: u32,
    /// Earliest automatic retry; absent when the remote outcome needs inspection.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub retry_at: Option<time::OffsetDateTime>,
    /// CA-provided minimum deadline; administrators cannot bypass this with `--now`.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub ca_retry_at: Option<time::OffsetDateTime>,
    /// A mutation outcome that cannot safely be replayed automatically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

impl RenewalRetryState {
    /// Classify persisted barriers without reducing the timestamp precision.
    #[must_use]
    pub fn admission(
        &self,
        now: time::OffsetDateTime,
        immediate: bool,
    ) -> aster_acme_core::renewal::RetryAdmission {
        aster_acme_core::renewal::retry_admission(
            self.blocked_reason.is_some(),
            self.retry_at,
            self.ca_retry_at,
            now,
            immediate,
        )
    }

    /// Advance one failed invocation without erasing earlier CA deadlines or
    /// uncertainty. All callers persist this while owning the certificate lease.
    #[must_use]
    pub fn after_failure(
        previous: Option<&Self>,
        now: time::OffsetDateTime,
        ca_retry_at: Option<time::OffsetDateTime>,
        blocked_reason: Option<String>,
    ) -> Self {
        let failures = previous.map_or(1, |state| state.failures.saturating_add(1));
        let retry_at = now.checked_add(time::Duration::seconds(
            aster_acme_core::renewal::renewal_retry_delay_seconds(failures),
        ));
        let blocked_reason = previous
            .and_then(|state| state.blocked_reason.clone())
            .or(blocked_reason)
            .or_else(|| retry_at.is_none().then(|| "retry deadline overflow".into()));
        Self {
            failures,
            retry_at: blocked_reason.is_none().then_some(retry_at).flatten(),
            ca_retry_at: previous
                .and_then(|state| state.ca_retry_at)
                .into_iter()
                .chain(ca_retry_at)
                .max(),
            blocked_reason,
        }
    }
}
