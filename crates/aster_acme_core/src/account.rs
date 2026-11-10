//! Explicit pure account lifecycle decisions; effects belong to the client orchestrator.
use crate::protocol::AccountStatus;
use serde::{Deserialize, Serialize};

/// Persisted local lifecycle of an account key and its server-side registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRecordState {
    /// Key exists locally and registration intent is durable; server result may be unknown.
    RegistrationPending,
    /// Account URL is known and the account key is reusable.
    Registered,
}

/// Local deactivation intent is separate from the last authoritative CA status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeactivationState {
    /// No outstanding deactivation request.
    NotRequested,
    /// Intent was saved before POST; the remote result may be unknown.
    Pending,
    /// A CA response explicitly confirmed deactivated status.
    Confirmed,
}

/// Requested account operation, independent of transport and storage.
#[derive(Debug, Clone, Copy)]
pub enum AccountOperation {
    Register,
    Deactivate,
    Select,
}

/// Next permitted action, or an explicit refusal requiring reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAction {
    LookupExisting,
    Inspect,
    SendDeactivation,
    AlreadyDeactivated,
    Select,
}

/// Account lifecycle refusal; the caller maps it to its user-facing error contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStateError {
    NotRegistered,
    NotActive,
    ReconciliationRequired,
}

/// Decide from persisted lifecycle and the last authoritative CA observation.
/// Unknown statuses never authorize an operation intended for active accounts.
///
/// # Errors
/// Rejects missing registration, inactive accounts, or outstanding uncertain deactivation.
pub fn account_action(
    operation: AccountOperation,
    registration: AccountRecordState,
    deactivation: DeactivationState,
    status: Option<&AccountStatus>,
) -> Result<AccountAction, AccountStateError> {
    use AccountAction::{AlreadyDeactivated, Inspect, LookupExisting, Select, SendDeactivation};
    use AccountStateError::{NotActive, NotRegistered, ReconciliationRequired};
    match (operation, deactivation) {
        (AccountOperation::Deactivate, DeactivationState::Confirmed) => Ok(AlreadyDeactivated),
        (_, DeactivationState::Pending) => Err(ReconciliationRequired),
        (_, DeactivationState::Confirmed) => Err(NotActive),
        (operation, DeactivationState::NotRequested) => match (registration, status) {
            (
                _,
                Some(
                    AccountStatus::Deactivated | AccountStatus::Revoked | AccountStatus::Unknown(_),
                ),
            ) => Err(NotActive),
            (AccountRecordState::RegistrationPending, _) => match operation {
                AccountOperation::Register => Ok(LookupExisting),
                AccountOperation::Deactivate | AccountOperation::Select => Err(NotRegistered),
            },
            (AccountRecordState::Registered, None | Some(AccountStatus::Valid)) => {
                match operation {
                    AccountOperation::Register => Ok(Inspect),
                    AccountOperation::Deactivate => Ok(SendDeactivation),
                    AccountOperation::Select => Ok(Select),
                }
            }
        },
    }
}

/// Transition only from an authoritative account object; HTTP error codes are not states.
#[must_use]
pub fn observed_deactivation(
    previous: DeactivationState,
    status: &AccountStatus,
) -> DeactivationState {
    match status {
        AccountStatus::Valid => DeactivationState::NotRequested,
        AccountStatus::Deactivated => DeactivationState::Confirmed,
        AccountStatus::Revoked | AccountStatus::Unknown(_) => previous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_and_deactivation_return_explicit_next_actions() {
        for (operation, registration, expected) in [
            (
                AccountOperation::Register,
                AccountRecordState::RegistrationPending,
                Ok(AccountAction::LookupExisting),
            ),
            (
                AccountOperation::Register,
                AccountRecordState::Registered,
                Ok(AccountAction::Inspect),
            ),
            (
                AccountOperation::Deactivate,
                AccountRecordState::RegistrationPending,
                Err(AccountStateError::NotRegistered),
            ),
            (
                AccountOperation::Deactivate,
                AccountRecordState::Registered,
                Ok(AccountAction::SendDeactivation),
            ),
            (
                AccountOperation::Select,
                AccountRecordState::Registered,
                Ok(AccountAction::Select),
            ),
        ] {
            assert_eq!(
                account_action(
                    operation,
                    registration,
                    DeactivationState::NotRequested,
                    Some(&AccountStatus::Valid)
                ),
                expected
            );
        }
    }

    #[test]
    fn uncertain_or_inactive_accounts_cannot_authorize_new_mutations() {
        for operation in [
            AccountOperation::Register,
            AccountOperation::Select,
            AccountOperation::Deactivate,
        ] {
            for registration in [
                AccountRecordState::RegistrationPending,
                AccountRecordState::Registered,
            ] {
                for status in [
                    AccountStatus::Valid,
                    AccountStatus::Revoked,
                    AccountStatus::Deactivated,
                    AccountStatus::Unknown("future".into()),
                ] {
                    assert_eq!(
                        account_action(
                            operation,
                            registration,
                            DeactivationState::Pending,
                            Some(&status)
                        ),
                        Err(AccountStateError::ReconciliationRequired)
                    );
                }
            }
            for status in [
                AccountStatus::Revoked,
                AccountStatus::Deactivated,
                AccountStatus::Unknown("future".into()),
            ] {
                assert_eq!(
                    account_action(
                        operation,
                        AccountRecordState::Registered,
                        DeactivationState::NotRequested,
                        Some(&status)
                    ),
                    Err(AccountStateError::NotActive)
                );
            }
        }
        assert_eq!(
            account_action(
                AccountOperation::Deactivate,
                AccountRecordState::Registered,
                DeactivationState::Confirmed,
                Some(&AccountStatus::Deactivated)
            ),
            Ok(AccountAction::AlreadyDeactivated)
        );
        assert_eq!(
            account_action(
                AccountOperation::Select,
                AccountRecordState::Registered,
                DeactivationState::Confirmed,
                None
            ),
            Err(AccountStateError::NotActive)
        );
    }

    #[test]
    fn only_authoritative_known_observations_resolve_uncertain_deactivation() {
        assert_eq!(
            observed_deactivation(DeactivationState::Pending, &AccountStatus::Valid),
            DeactivationState::NotRequested
        );
        assert_eq!(
            observed_deactivation(DeactivationState::Pending, &AccountStatus::Deactivated),
            DeactivationState::Confirmed
        );
        assert_eq!(
            observed_deactivation(DeactivationState::Pending, &AccountStatus::Revoked),
            DeactivationState::Pending
        );
        assert_eq!(
            observed_deactivation(
                DeactivationState::Pending,
                &AccountStatus::Unknown("future".into())
            ),
            DeactivationState::Pending
        );
    }
}
