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
        accounts: Vec<aster_acme_cli_storage::inventory::LocalAccount>,
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
        /// The current directory terms URL changed and was accepted by persisted delegation.
        auto_accepted_terms: bool,
        /// This register invocation explicitly reused a pre-existing local identity.
        reused: bool,
    },
    Switched {
        name: String,
        directory: AcmeUrl,
    },
    /// Draft-ietf-acme-profiles listing
    /// (<https://datatracker.ietf.org/doc/html/draft-ietf-acme-profiles>).
    Profiles {
        directory: AcmeUrl,
        /// Advertised profile name to CA-provided description.
        profiles: Option<std::collections::BTreeMap<String, String>>,
    },
    /// One `account update` invocation: every requested scope reports its own
    /// outcome, so a committed CA mutation never loses its evidence to a later
    /// local preference in the same call.
    Updated(UpdateOutcome),
}

/// Every scope applied by one `account update`, in contacts → profile → terms order.
/// Absent scopes are `None`; at least one is always present.
pub(crate) struct UpdateOutcome {
    pub(crate) name: String,
    /// Contacts committed at the CA, echoing the CA's account response.
    pub(crate) contacts: Option<ContactsUpdate>,
    /// Default profile preference change (local metadata).
    pub(crate) profile: Option<ProfileChange>,
    /// Future terms delegation change (local metadata; enabling reads the directory).
    pub(crate) terms: Option<TermsChange>,
}

pub(crate) struct ContactsUpdate {
    pub(crate) account: AcmeAccount,
}

pub(crate) struct ProfileChange {
    pub(crate) previous: Option<String>,
    pub(crate) current: Option<String>,
}

pub(crate) struct TermsChange {
    pub(crate) previous: bool,
    pub(crate) current: bool,
    /// Accepted terms value after the change, kept verbatim; retained when disabling.
    pub(crate) accepted_terms_url: Option<String>,
    /// Terms value read from the live directory; None when not checked or absent.
    pub(crate) advertised_terms_url: Option<String>,
    /// Whether this invocation read the live directory (enabling) or stayed local.
    pub(crate) directory_checked: bool,
}

#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RemoteAction {
    Register,
    Recover,
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
            | Self::Deactivated { .. }
            | Self::Profiles { .. }
            | Self::Updated(_) => false,
        }
    }
}

pub(crate) struct LocalAccountReport {
    pub(crate) verified: bool,
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
