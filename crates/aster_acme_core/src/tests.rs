//! State machine regression tests.

use crate::workflow::SubmissionState;
use serde::{Serialize, de::DeserializeOwned};

use crate::{machine::*, protocol::*};

fn roundtrip<T: DeserializeOwned + Serialize>(wire: &str) -> T {
    let json = serde_json::to_string(wire).unwrap();
    let value: T = serde_json::from_str(&json).unwrap();
    assert_eq!(serde_json::to_string(&value).unwrap(), json);
    value
}

#[test]
fn resource_wire_states_roundtrip_and_preserve_unknown_values() {
    for (wire, expected) in [
        ("valid", AccountStatus::Valid),
        ("deactivated", AccountStatus::Deactivated),
        ("revoked", AccountStatus::Revoked),
        (
            "future-account-state",
            AccountStatus::Unknown("future-account-state".into()),
        ),
    ] {
        assert_eq!(roundtrip::<AccountStatus>(wire), expected);
    }
    for (wire, expected) in [
        ("pending", OrderStatus::Pending),
        ("ready", OrderStatus::Ready),
        ("processing", OrderStatus::Processing),
        ("valid", OrderStatus::Valid),
        ("invalid", OrderStatus::Invalid),
        (
            "future-order-state",
            OrderStatus::Unknown("future-order-state".into()),
        ),
    ] {
        assert_eq!(roundtrip::<OrderStatus>(wire), expected);
    }
    for (wire, expected) in [
        ("pending", AuthorizationStatus::Pending),
        ("valid", AuthorizationStatus::Valid),
        ("invalid", AuthorizationStatus::Invalid),
        ("deactivated", AuthorizationStatus::Deactivated),
        ("expired", AuthorizationStatus::Expired),
        ("revoked", AuthorizationStatus::Revoked),
        (
            "future-auth-state",
            AuthorizationStatus::Unknown("future-auth-state".into()),
        ),
    ] {
        assert_eq!(roundtrip::<AuthorizationStatus>(wire), expected);
    }
    for (wire, expected) in [
        ("pending", ChallengeStatus::Pending),
        ("processing", ChallengeStatus::Processing),
        ("valid", ChallengeStatus::Valid),
        ("invalid", ChallengeStatus::Invalid),
        (
            "future-challenge-state",
            ChallengeStatus::Unknown("future-challenge-state".into()),
        ),
    ] {
        assert_eq!(roundtrip::<ChallengeStatus>(wire), expected);
    }
    assert_eq!(
        roundtrip::<OrderStatus>("VALID"),
        OrderStatus::Unknown("VALID".into())
    );
    assert!(serde_json::from_str::<OrderStatus>("42").is_err());
}

#[test]
fn order_decisions_use_authoritative_observations() {
    assert_eq!(
        order_action(
            &OrderStatus::Pending,
            Some(&[AuthorizationStatus::Valid, AuthorizationStatus::Pending]),
            SubmissionState::NotSubmitted
        ),
        Ok(OrderAction::ResolveAuthorizations)
    );
    assert_eq!(
        order_action(
            &OrderStatus::Pending,
            Some(&[AuthorizationStatus::Valid]),
            SubmissionState::NotSubmitted
        ),
        Ok(OrderAction::RefreshOrder)
    );
    assert_eq!(
        order_action(
            &OrderStatus::Pending,
            Some(&[]),
            SubmissionState::NotSubmitted
        ),
        Ok(OrderAction::RefreshOrder)
    );
    for (state, action) in [
        (OrderStatus::Ready, OrderAction::Finalize),
        (OrderStatus::Processing, OrderAction::PollOrder),
        (OrderStatus::Valid, OrderAction::DownloadCertificate),
    ] {
        // A fresh order observation supersedes stale cached authorization state.
        assert_eq!(
            order_action(
                &state,
                Some(&[AuthorizationStatus::Pending]),
                SubmissionState::NotSubmitted
            ),
            Ok(action)
        );
    }
    assert_eq!(
        order_action(
            &OrderStatus::Invalid,
            Some(&[]),
            SubmissionState::NotSubmitted
        ),
        Err(StateError::InvalidOrder)
    );
    assert!(
        order_action(
            &OrderStatus::Unknown("future".into()),
            Some(&[]),
            SubmissionState::NotSubmitted
        )
        .is_err()
    );
}

#[test]
fn failed_or_unknown_authorizations_cannot_advance_a_pending_order() {
    for state in [
        AuthorizationStatus::Invalid,
        AuthorizationStatus::Expired,
        AuthorizationStatus::Revoked,
        AuthorizationStatus::Deactivated,
        AuthorizationStatus::Unknown("future".into()),
    ] {
        assert!(authorization_action(&state).is_err());
        assert!(
            order_action(
                &OrderStatus::Pending,
                Some(&[AuthorizationStatus::Pending, state]),
                SubmissionState::NotSubmitted
            )
            .is_err()
        );
    }
    assert_eq!(
        authorization_action(&AuthorizationStatus::Valid),
        Ok(AuthorizationAction::AlreadyValid)
    );
}

#[test]
fn processing_challenges_are_polled_and_success_requires_authorization_refresh() {
    assert_eq!(
        challenge_action(&ChallengeStatus::Pending, SubmissionState::NotSubmitted),
        Ok(ChallengeAction::PrepareAndAcknowledge)
    );
    assert_eq!(
        challenge_action(&ChallengeStatus::Processing, SubmissionState::NotSubmitted),
        Ok(ChallengeAction::PollChallenge)
    );
    assert_eq!(
        challenge_action(&ChallengeStatus::Valid, SubmissionState::NotSubmitted),
        Ok(ChallengeAction::RefreshAuthorization)
    );
    assert!(challenge_action(&ChallengeStatus::Invalid, SubmissionState::NotSubmitted).is_err());
    assert!(
        challenge_action(
            &ChallengeStatus::Unknown("future".into()),
            SubmissionState::NotSubmitted
        )
        .is_err()
    );
}

#[test]
fn submitted_mutations_only_poll_until_authoritative_state_advances() {
    assert_eq!(
        order_action(&OrderStatus::Ready, Some(&[]), SubmissionState::Submitted),
        Ok(OrderAction::PollOrder)
    );
    assert_eq!(
        challenge_action(&ChallengeStatus::Pending, SubmissionState::Submitted),
        Ok(ChallengeAction::PollChallenge)
    );
}

#[test]
fn unfetched_authorizations_are_distinct_from_an_explicit_empty_set() {
    assert_eq!(
        order_action(&OrderStatus::Pending, None, SubmissionState::NotSubmitted),
        Ok(OrderAction::ResolveAuthorizations)
    );
    assert_eq!(
        order_action(
            &OrderStatus::Pending,
            Some(&[]),
            SubmissionState::NotSubmitted
        ),
        Ok(OrderAction::RefreshOrder)
    );
}
