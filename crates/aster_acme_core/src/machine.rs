//! Pure decisions based on observed server state, without challenge method knowledge.

use crate::workflow::SubmissionState;
use thiserror::Error;

use crate::protocol::{AuthorizationStatus, ChallengeStatus, OrderStatus};

/// Next order-level protocol operation, executed by an external orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderAction {
    /// Resolve outstanding authorizations through an externally selected method.
    ResolveAuthorizations,
    /// Refresh the order after all authorizations were observed valid.
    RefreshOrder,
    /// Submit the persisted CSR.
    Finalize,
    /// Poll the existing order, without resubmitting the CSR.
    PollOrder,
    /// Retrieve the issued certificate; local persistence is not implied.
    DownloadCertificate,
}

/// Next authorization-level decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationAction {
    /// Delegate challenge handling to the upper layer.
    ResolveChallenge,
    /// No further validation is necessary.
    AlreadyValid,
}

/// Next challenge-level protocol operation, independent of validation method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeAction {
    /// Upper layer must prepare material before acknowledging the challenge.
    PrepareAndAcknowledge,
    /// Poll without preparing a new response or acknowledging again.
    PollChallenge,
    /// Challenge succeeded; authorization still needs to be refreshed.
    RefreshAuthorization,
}

/// A resource cannot safely advance.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateError {
    /// CA order is invalid.
    #[error("order is invalid")]
    InvalidOrder,
    /// Authorization is terminal and unsuccessful.
    #[error("authorization is not usable: {0:?}")]
    UnusableAuthorization(AuthorizationStatus),
    /// Challenge failed.
    #[error("challenge is invalid")]
    InvalidChallenge,
    /// A future wire value cannot be interpreted as a known state.
    #[error("unknown {resource} status: {value}")]
    UnknownStatus {
        /// Resource whose status could not be interpreted.
        resource: &'static str,
        /// Original wire value.
        value: String,
    },
}

/// Determine an order action from a fresh observation, allowing skipped intermediate states.
///
/// None means authorizations have not been refreshed and must be resolved first.
/// Some(empty) is an explicitly fetched empty set, never a stand-in for missing resources.
/// A submitted finalize is polled even while the CA still reports ready.
///
/// # Errors
/// Rejects unknown or invalid orders and unusable authorizations on pending orders.
pub fn order_action(
    status: &OrderStatus,
    authorizations: Option<&[AuthorizationStatus]>,
    finalize_submitted: SubmissionState,
) -> Result<OrderAction, StateError> {
    match status {
        OrderStatus::Pending => {
            let Some(authorizations) = authorizations else {
                return Ok(OrderAction::ResolveAuthorizations);
            };
            let mut outstanding = false;
            for status in authorizations {
                match authorization_action(status)? {
                    AuthorizationAction::ResolveChallenge => outstanding = true,
                    AuthorizationAction::AlreadyValid => {}
                }
            }
            Ok(if outstanding {
                OrderAction::ResolveAuthorizations
            } else {
                OrderAction::RefreshOrder
            })
        }
        OrderStatus::Ready => Ok(match finalize_submitted {
            SubmissionState::NotSubmitted => OrderAction::Finalize,
            SubmissionState::Submitted => OrderAction::PollOrder,
        }),
        OrderStatus::Processing => Ok(OrderAction::PollOrder),
        OrderStatus::Valid => Ok(OrderAction::DownloadCertificate),
        OrderStatus::Invalid => Err(StateError::InvalidOrder),
        OrderStatus::Unknown(value) => Err(StateError::UnknownStatus {
            resource: "order",
            value: value.clone(),
        }),
    }
}

/// Determine whether an observed authorization needs upper-layer challenge handling.
///
/// # Errors
/// Rejects unknown, invalid, deactivated, expired and revoked authorizations.
pub fn authorization_action(
    status: &AuthorizationStatus,
) -> Result<AuthorizationAction, StateError> {
    match status {
        AuthorizationStatus::Pending => Ok(AuthorizationAction::ResolveChallenge),
        AuthorizationStatus::Valid => Ok(AuthorizationAction::AlreadyValid),
        AuthorizationStatus::Unknown(value) => Err(StateError::UnknownStatus {
            resource: "authorization",
            value: value.clone(),
        }),
        AuthorizationStatus::Invalid
        | AuthorizationStatus::Deactivated
        | AuthorizationStatus::Expired
        | AuthorizationStatus::Revoked => Err(StateError::UnusableAuthorization(status.clone())),
    }
}

/// Determine the protocol action from an observed challenge status.
///
/// # Errors
/// Rejects unknown and invalid challenges.
pub fn challenge_action(
    status: &ChallengeStatus,
    acknowledged: SubmissionState,
) -> Result<ChallengeAction, StateError> {
    match status {
        ChallengeStatus::Pending => Ok(match acknowledged {
            SubmissionState::NotSubmitted => ChallengeAction::PrepareAndAcknowledge,
            SubmissionState::Submitted => ChallengeAction::PollChallenge,
        }),
        ChallengeStatus::Processing => Ok(ChallengeAction::PollChallenge),
        ChallengeStatus::Valid => Ok(ChallengeAction::RefreshAuthorization),
        ChallengeStatus::Invalid => Err(StateError::InvalidChallenge),
        ChallengeStatus::Unknown(value) => Err(StateError::UnknownStatus {
            resource: "challenge",
            value: value.clone(),
        }),
    }
}
