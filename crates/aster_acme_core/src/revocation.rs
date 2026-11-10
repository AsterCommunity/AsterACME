//! Explicit certificate revocation decisions, independent of order/account lifecycle.
use serde::{Deserialize, Serialize};

/// Last durable revocation observation; pending is never presented as revoked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationState {
    /// No revocation has been requested, or the CA explicitly rejected it.
    #[default]
    NotRequested,
    /// A request may have reached the CA; its result is not confirmed locally.
    Pending,
    /// HTTP 200 or the CA's alreadyRevoked problem confirmed revocation.
    Confirmed,
}

/// Action for an explicit revoke invocation, never an automatic background retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationAction {
    /// Only certificates with a completed local artifact set may be revoked.
    NotIssued,
    /// Send a durable request; a pending request must retain its exact original reason.
    Submit,
    /// No request is needed for an already confirmed certificate.
    AlreadyConfirmed,
    /// Do not change the semantics of an uncertain request.
    ReasonConflict,
}

/// Repeating an explicit revoke is safe for the same certificate and reason: the CA
/// either revokes it or reports alreadyRevoked. Network failures are not auto-replayed.
#[must_use]
pub fn revocation_action(
    issued: bool,
    state: RevocationState,
    same_reason: bool,
) -> RevocationAction {
    match (issued, state, same_reason) {
        (false, _, _) => RevocationAction::NotIssued,
        (true, RevocationState::Confirmed, _) => RevocationAction::AlreadyConfirmed,
        (true, RevocationState::Pending, false) => RevocationAction::ReasonConflict,
        (true, RevocationState::NotRequested | RevocationState::Pending, _) => {
            RevocationAction::Submit
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_revocation_decisions_preserve_uncertain_request_identity() {
        for state in [
            RevocationState::NotRequested,
            RevocationState::Pending,
            RevocationState::Confirmed,
        ] {
            assert_eq!(
                revocation_action(false, state, true),
                RevocationAction::NotIssued
            );
        }
        assert_eq!(
            revocation_action(true, RevocationState::NotRequested, false),
            RevocationAction::Submit
        );
        assert_eq!(
            revocation_action(true, RevocationState::Pending, true),
            RevocationAction::Submit
        );
        assert_eq!(
            revocation_action(true, RevocationState::Pending, false),
            RevocationAction::ReasonConflict
        );
        assert_eq!(
            revocation_action(true, RevocationState::Confirmed, false),
            RevocationAction::AlreadyConfirmed
        );
    }
}
