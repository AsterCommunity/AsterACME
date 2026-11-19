//! ACME account registration and recovery (RFC 8555 §7.3).

use crate::storage::account::{AccountStore, AccountStoreError};
use crate::{
    crypto::{CryptoError, ExternalAccountCredentials},
    transport::{AcmeClient, TransportError},
};
use aster_acme_core::{
    account::{
        AccountAction, AccountOperation, AccountRecordState, AccountStateError, DeactivationState,
        KeyRotation, account_action, observed_deactivation,
    },
    protocol::AccountStatus,
};
use aster_acme_protocol::account::AccountObject;
use aster_acme_protocol::url::AcmeUrl;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

/// Local UTC observations, never a claim about the CA's original account creation time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountTimes {
    /// First successful local confirmation that the account is registered.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub registered_at: Option<time::OffsetDateTime>,
    /// Last successful authoritative CA status observation.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_status_at: Option<time::OffsetDateTime>,
    /// Last successful authenticated account operation; local reads do not update it.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<time::OffsetDateTime>,
}

/// Injectable wall clock for observation timestamps, shared by embedded use and tests.
pub trait AccountClock: Send + Sync {
    /// Current wall time; the service normalizes observations to UTC.
    fn now(&self) -> time::OffsetDateTime;
}

struct SystemAccountClock;
impl AccountClock for SystemAccountClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }
}

/// Provider-neutral account metadata. The private key is kept in a separate key store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    /// Actual account signing key choice, checked against the stored key.
    pub key_algorithm: crate::crypto::key_algorithm::KeyAlgorithm,
    /// Explicit account HTTP identity; absence uses the client's built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Locally observed lifecycle timestamps, encoded as root account fields.
    #[serde(flatten)]
    pub times: AccountTimes,
    /// Stable local identifier derived at initialization; unchanged by key rollover.
    pub account_id: String,
    /// Exact CA directory URL bound to this account identity.
    pub directory_url: AcmeUrl,
    /// RFC 7638 thumbprint of the persisted signing key.
    pub key_thumbprint: String,
    /// `kid` returned by the server. None only while recovering a pending registration.
    pub account_url: Option<AcmeUrl>,
    /// Locally configured contact URIs; CA responses never erase the requested values.
    pub contacts: Vec<String>,
    /// Latest contacts returned by the CA, distinct from local registration input.
    pub server_contacts: Option<Vec<String>>,
    /// Latest status actually received from the CA; not a current offline assertion.
    pub last_status: Option<AccountStatus>,
    /// Durable deactivation intent; uncertain outcomes never silently become success.
    pub deactivation: DeactivationState,
    /// Durable key rollover state; pending and confirmed phases make interrupted local swaps recoverable.
    pub key_rotation: Option<KeyRotation>,
    /// Terms URL shown to the user and explicitly accepted.
    pub accepted_terms_url: Option<AcmeUrl>,
    /// Persisted opt-in to accept future directory terms URL changes.
    #[serde(default)]
    pub auto_accept_terms_updates: bool,
    /// Local protocol stage.
    pub state: AccountRecordState,
}

impl AccountRecord {
    /// Derive the stable local account ID for an exact directory and key identity.
    /// Storage adapters call this instead of maintaining a parallel hash scheme.
    #[must_use]
    pub fn stable_id(directory: &AcmeUrl, thumbprint: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest as _, Sha256};
        URL_SAFE_NO_PAD.encode(Sha256::digest(
            format!("{}\0{thumbprint}", directory.as_str()).as_bytes(),
        ))
    }

    /// Whether local metadata permits selecting this account for active use. This is
    /// a local eligibility check, not a fresh assertion that the CA still accepts it.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.account_url.is_some()
            && self.action(AccountOperation::Select) == Ok(AccountAction::Select)
    }

    /// Delegate all lifecycle eligibility to the pure core state machine.
    ///
    /// # Errors
    /// Rejects unregistered, inactive or uncertain-deactivation states as directed by core.
    pub fn action(&self, operation: AccountOperation) -> Result<AccountAction, AccountStateError> {
        account_action(
            operation,
            self.state,
            self.deactivation,
            self.last_status.as_ref(),
            self.key_rotation.as_ref(),
        )
    }

    /// Apply one authoritative CA observation without changing local contact intent.
    fn observe(&mut self, account: &AccountObject, at: time::OffsetDateTime) {
        let at = at.to_offset(time::UtcOffset::UTC);
        self.times.registered_at.get_or_insert(at);
        self.times.last_status_at = Some(at);
        self.times.last_used_at = Some(at);
        self.last_status = Some(account.status.clone());
        self.server_contacts.clone_from(&account.contact);
        self.deactivation = observed_deactivation(self.deactivation, &account.status);
    }
}

/// Explicit registration consent and optional CA-specific inputs.
#[derive(Default)]
pub struct RegistrationOptions {
    /// Account contact URIs; `mailto:` values are validated before network I/O.
    pub contacts: Vec<String>,
    /// Explicit user acceptance of the current terms advertised by the CA directory.
    pub terms_accepted: bool,
    /// Explicitly persist consent to accept future terms URL changes.
    pub auto_accept_terms_updates: bool,
    /// Optional out-of-band CA EAB credentials; key bytes are never persisted.
    pub external_account: Option<ExternalAccountCredentials>,
}

/// Registered account identity returned to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeAccount {
    /// Actual account signing key choice.
    pub key_algorithm: crate::crypto::key_algorithm::KeyAlgorithm,
    /// Persisted local observation times, independent of CLI rendering.
    pub times: AccountTimes,
    /// Stable local identity.
    pub account_id: String,
    /// Exact CA directory used to create or recover this account.
    pub directory_url: AcmeUrl,
    /// Server account URL (`kid`).
    pub account_url: AcmeUrl,
    /// Server account state.
    pub status: aster_acme_core::protocol::AccountStatus,
    /// Server-accepted contact URIs.
    pub contacts: Vec<String>,
    /// Whether this invocation recovered an existing account URL.
    pub recovered: bool,
}

/// Account-level failure. Pending intent remains persisted after uncertain transport errors.
#[derive(Debug, Error)]
pub enum AccountError {
    /// Previous deactivation may have succeeded. Explicit inspection is required before replay.
    #[error("account deactivation is pending reconciliation; do not automatically repeat it")]
    DeactivationUncertain,
    /// Account is not in a known active state suitable for deactivation.
    #[error("account is not active or its status is unsupported")]
    AccountNotActive,
    /// Account key rollover has an uncertain result and requires reconciliation.
    #[error("account key rotation is pending reconciliation")]
    KeyRotationUncertain,
    /// The CA directory does not advertise keyChange in its directory.
    #[error("the CA directory does not advertise the keyChange endpoint")]
    KeyChangeUnavailable,
    /// Adapter storage failure.
    #[error(transparent)]
    Store(#[from] AccountStoreError),
    /// Cryptographic operation failure.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// ACME protocol/transport failure.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// Required terms were not explicitly accepted.
    #[error("explicit acceptance of the CA terms is required: {0}")]
    TermsRequired(AcmeUrl),
    /// EAB is required but no credentials were supplied.
    #[error("CA requires External Account Binding credentials")]
    ExternalAccountRequired,
    /// CA created the account without confirming the supplied EAB.
    #[error("CA did not confirm the supplied External Account Binding")]
    ExternalAccountNotConfirmed,
    /// Contact URI is invalid or unsupported by this client.
    #[error("invalid account contact URI")]
    InvalidContact,
    /// Persisted account metadata does not match the requested CA/key identity.
    #[error("persisted account metadata does not match its directory or key")]
    IdentityMismatch,
    /// Account exists remotely, but the local key-to-account recovery path could not find it.
    #[error("no registered account exists for the supplied key")]
    AccountDoesNotExist,
    /// Server response omitted mandatory account fields.
    #[error("ACME account response is missing required fields")]
    InvalidResponse,
}

impl From<AccountStateError> for AccountError {
    fn from(error: AccountStateError) -> Self {
        match error {
            AccountStateError::NotRegistered => Self::AccountDoesNotExist,
            AccountStateError::NotActive => Self::AccountNotActive,
            AccountStateError::ReconciliationRequired => Self::DeactivationUncertain,
            AccountStateError::KeyRotationUncertain => Self::KeyRotationUncertain,
        }
    }
}

/// Account protocol service. No concrete filesystem or CLI dependency.
pub struct AccountService {
    client: Arc<AcmeClient>,
    store: Arc<dyn AccountStore>,
    clock: Arc<dyn AccountClock>,
}

impl AccountService {
    /// Construct from an already discovered directory and an injected object-safe store.
    #[must_use]
    pub fn new(client: Arc<AcmeClient>, store: Arc<dyn AccountStore>) -> Self {
        Self {
            client,
            store,
            clock: Arc::new(SystemAccountClock),
        }
    }

    /// Use an injected clock for deterministic observation timestamps.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn AccountClock>) -> Self {
        self.clock = clock;
        self
    }
}

mod lifecycle;
mod registration;
mod rotation;

fn validate_contacts(contacts: &[String]) -> Result<(), AccountError> {
    if contacts.len() > 32 {
        return Err(AccountError::InvalidContact);
    }
    for contact in contacts {
        if contact.len() > 2048 || contact.chars().any(char::is_control) {
            return Err(AccountError::InvalidContact);
        }
        let parsed = url::Url::parse(contact).map_err(|_| AccountError::InvalidContact)?;
        let decoded = percent_encoding::percent_decode_str(parsed.path())
            .decode_utf8()
            .map_err(|_| AccountError::InvalidContact)?;
        if decoded.contains(',')
            || decoded.contains(';')
            || decoded.chars().any(char::is_control)
            || decoded.matches('@').count() != 1
        {
            return Err(AccountError::InvalidContact);
        }
        if parsed.scheme() != "mailto"
            || parsed.path().is_empty()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path().contains(',')
            || parsed.path().contains(';')
        {
            return Err(AccountError::InvalidContact);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
