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

/// Durable local progress for RFC 8555 §7.3.5 key rollover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotation {
    /// Thumbprint of the new key staged locally before the CA request.
    pub new_thumbprint: String,
    /// Server outcome; confirmed allows the adapter to finish an interrupted local swap.
    pub phase: KeyRotationPhase,
}

/// A pending result is never assumed to mean the CA changed the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationPhase {
    Pending,
    Confirmed,
}

/// Requested account operation, independent of transport and storage.
#[derive(Debug, Clone, Copy)]
pub enum AccountOperation {
    Inspect,
    Register,
    Deactivate,
    Select,
    Update,
    RotateKey,
}

/// Next permitted action, or an explicit refusal requiring reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAction {
    LookupExisting,
    Inspect,
    SendDeactivation,
    AlreadyDeactivated,
    Select,
    Update,
    SendKeyChange,
    ReconcileKeyChange,
    FinalizeKeyChange,
}

/// Account lifecycle refusal; the caller maps it to its user-facing error contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AccountStateError {
    #[error("account is not registered")]
    NotRegistered,
    #[error("account is not active")]
    NotActive,
    #[error("account deactivation requires reconciliation")]
    ReconciliationRequired,
    #[error("account key rotation requires reconciliation")]
    KeyRotationUncertain,
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
    key_rotation: Option<&KeyRotation>,
) -> Result<AccountAction, AccountStateError> {
    use AccountAction::{AlreadyDeactivated, Inspect, LookupExisting, Select, SendDeactivation};
    use AccountStateError::{NotActive, NotRegistered, ReconciliationRequired};
    match key_rotation {
        Some(KeyRotation {
            phase: KeyRotationPhase::Pending,
            ..
        }) => {
            return match operation {
                AccountOperation::RotateKey => Ok(AccountAction::ReconcileKeyChange),
                _ => Err(AccountStateError::KeyRotationUncertain),
            };
        }
        Some(KeyRotation {
            phase: KeyRotationPhase::Confirmed,
            ..
        }) => {
            return match operation {
                AccountOperation::RotateKey => Ok(AccountAction::FinalizeKeyChange),
                _ => Err(AccountStateError::KeyRotationUncertain),
            };
        }
        None => {}
    }
    match (operation, deactivation) {
        (AccountOperation::Inspect, _) => match registration {
            AccountRecordState::Registered => Ok(Inspect),
            AccountRecordState::RegistrationPending => Ok(LookupExisting),
        },
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
                AccountOperation::Register | AccountOperation::Inspect => Ok(LookupExisting),
                AccountOperation::Deactivate
                | AccountOperation::Select
                | AccountOperation::Update
                | AccountOperation::RotateKey => Err(NotRegistered),
            },
            (AccountRecordState::Registered, None | Some(AccountStatus::Valid)) => {
                match operation {
                    AccountOperation::Register | AccountOperation::Inspect => Ok(Inspect),
                    AccountOperation::Deactivate => Ok(SendDeactivation),
                    AccountOperation::Select => Ok(Select),
                    AccountOperation::Update => Ok(AccountAction::Update),
                    AccountOperation::RotateKey => Ok(AccountAction::SendKeyChange),
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
    use crate::account::*;

    #[test]
    fn rollover_states_block_other_operations_and_only_resume_saved_key() {
        for (phase, expected) in [
            (KeyRotationPhase::Pending, AccountAction::ReconcileKeyChange),
            (
                KeyRotationPhase::Confirmed,
                AccountAction::FinalizeKeyChange,
            ),
        ] {
            let rotation = KeyRotation {
                new_thumbprint: "new".into(),
                phase,
            };
            for operation in [
                AccountOperation::Inspect,
                AccountOperation::Register,
                AccountOperation::Select,
                AccountOperation::Update,
                AccountOperation::Deactivate,
            ] {
                assert_eq!(
                    account_action(
                        operation,
                        AccountRecordState::Registered,
                        DeactivationState::NotRequested,
                        Some(&AccountStatus::Valid),
                        Some(&rotation)
                    ),
                    Err(AccountStateError::KeyRotationUncertain)
                );
            }
            assert_eq!(
                account_action(
                    AccountOperation::RotateKey,
                    AccountRecordState::Registered,
                    DeactivationState::NotRequested,
                    Some(&AccountStatus::Valid),
                    Some(&rotation)
                ),
                Ok(expected)
            );
        }
        for operation in [AccountOperation::Update, AccountOperation::RotateKey] {
            assert_eq!(
                account_action(
                    operation,
                    AccountRecordState::RegistrationPending,
                    DeactivationState::NotRequested,
                    None,
                    None
                ),
                Err(AccountStateError::NotRegistered)
            );
        }
    }

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
                    Some(&AccountStatus::Valid),
                    None
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
                            Some(&status),
                            None
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
                        Some(&status),
                        None
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
                Some(&AccountStatus::Deactivated),
                None
            ),
            Ok(AccountAction::AlreadyDeactivated)
        );
        assert_eq!(
            account_action(
                AccountOperation::Select,
                AccountRecordState::Registered,
                DeactivationState::Confirmed,
                None,
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
