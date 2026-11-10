//! Account command results, independent of terminal styling and output side effects.
use aster_acme_protocol::url::AcmeUrl;

use aster_acme::account::{AccountRecord, AcmeAccount};

pub(crate) enum AccountReport {
    KeyRotated {
        name: String,
        record: AccountRecord,
    },
    Removed {
        name: String,
        directory: AcmeUrl,
    },
    /// Enumeration with optional per-account CA verification.
    List {
        accounts: Vec<aster_acme_cli_storage::LocalAccount>,
        default: String,
        verification: Option<Vec<AccountVerification>>,
    },
    /// CA-confirmed irreversible deactivation, or an already confirmed local result.
    Deactivated {
        name: String,
        account: AcmeAccount,
        verified: bool,
    },
    /// Local lifecycle is distinct from current remote validity, including key-only state.
    Local(LocalAccountReport),
    Remote {
        name: String,
        account: AcmeAccount,
        action: RemoteAction,
        /// This register invocation explicitly reused a pre-existing local identity.
        reused: bool,
    },
    Switched {
        name: String,
        directory: AcmeUrl,
    },
}

#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RemoteAction {
    UpdateContact,
    Register,
    Recover,
    Show,
}

#[derive(serde::Serialize)]
pub(crate) struct AccountVerification {
    pub(crate) name: String,
    pub(crate) status: Option<aster_acme_core::protocol::AccountStatus>,
    pub(crate) error: Option<String>,
}

impl AccountReport {
    pub(crate) fn has_failures(&self) -> bool {
        match self {
            Self::List {
                verification: Some(results),
                ..
            } => results.iter().any(|result| result.error.is_some()),
            Self::List {
                verification: None, ..
            }
            | Self::Local(_)
            | Self::KeyRotated { .. }
            | Self::Remote { .. }
            | Self::Switched { .. }
            | Self::Removed { .. }
            | Self::Deactivated { .. } => false,
        }
    }
}

pub(crate) struct LocalAccountReport {
    pub(crate) name: String,
    pub(crate) directory: AcmeUrl,
    pub(crate) key_thumbprint: String,
    pub(crate) record: Option<AccountRecord>,
}

/// Local lifecycle labels shared by lists, account detail, and selection prompts.
pub(super) fn state_label(state: aster_acme_core::account::AccountRecordState) -> &'static str {
    match state {
        aster_acme_core::account::AccountRecordState::Registered => "registered locally",
        aster_acme_core::account::AccountRecordState::RegistrationPending => "registration pending",
    }
}

pub(super) fn deactivation_label(
    state: aster_acme_core::account::DeactivationState,
) -> &'static str {
    match state {
        aster_acme_core::account::DeactivationState::NotRequested => "not requested",
        aster_acme_core::account::DeactivationState::Pending => "pending reconciliation",
        aster_acme_core::account::DeactivationState::Confirmed => "confirmed deactivated",
    }
}
