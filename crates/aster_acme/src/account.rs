//! ACME account registration and recovery (RFC 8555 §7.3).
use aster_acme_protocol::url::AcmeUrl;

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    crypto::{AccountSigner, CryptoError, ExternalAccountCredentials},
    transport::{AcmeClient, TransportError, json_payload},
};
use aster_acme_core::{
    account::{
        AccountAction, AccountOperation, AccountRecordState, AccountStateError, DeactivationState,
        KeyRotation, KeyRotationPhase, account_action, observed_deactivation,
    },
    protocol::AccountStatus,
};

use aster_acme_protocol::{
    account::{
        AccountObject, AccountStatusRequest, AccountUpdateRequest, FindAccountRequest,
        NewAccountRequest,
    },
    problem::ACCOUNT_DOES_NOT_EXIST,
};

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
    /// Local protocol stage.
    pub state: AccountRecordState,
}

impl AccountRecord {
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

/// A held account lease. Dropping it releases any backing process lock.
pub trait AccountLease: Send {}
impl<T: Send> AccountLease for T {}

/// Object-safe persistence contract for embedders and CLI adapters.
///
/// Implementations must key records by both exact directory URL and thumbprint, save
/// registration intent before network mutations, redact secrets, and serialize operations
/// through `lock_account`. The lock is scoped to the directory and key identity.
#[async_trait]
pub trait AccountStore: Send + Sync {
    /// Acquire an exclusive account operation lease. Calls wait only as long as the
    /// implementation's documented lock timeout.
    ///
    /// # Errors
    /// Reports lock contention timeout or storage failures.
    async fn lock_account(
        &self,
        directory: &AcmeUrl,
        thumbprint: &str,
    ) -> Result<Box<dyn AccountLease>, AccountStoreError>;

    /// Load metadata for an exact CA directory and key thumbprint.
    ///
    /// # Errors
    /// Reports corrupt or inaccessible persisted records.
    async fn load(
        &self,
        directory: &AcmeUrl,
        thumbprint: &str,
    ) -> Result<Option<AccountRecord>, AccountStoreError>;

    /// Atomically persist metadata for an exact CA directory and key thumbprint.
    ///
    /// # Errors
    /// Reports write, permission, validation, or durability failures.
    async fn save(&self, record: &AccountRecord) -> Result<(), AccountStoreError>;
}

/// Object-safe account key lookup. Implementations may return software or remote signers.
#[async_trait]
pub trait AccountKeyStore: Send + Sync {
    /// Load a CA-scoped named key, creating it durably only when explicitly requested.
    ///
    /// # Errors
    /// Missing keys in read-only mode, corrupt keys, and unavailable signers are errors.
    async fn signer(
        &self,
        directory: &AcmeUrl,
        name: &str,
        create: bool,
    ) -> Result<Arc<dyn AccountSigner>, AccountStoreError>;
}

/// Object-safe durable key rollover adapter. Sessions own the account operation lease.
/// Staged keys must survive cancellation and restart; commits must be idempotent.
#[async_trait]
pub trait AccountRotationStore: Send + Sync {
    /// Open a locked snapshot without generating or replacing any key.
    ///
    /// # Errors
    /// Rejects missing, corrupt, mismatched, or concurrently locked identities.
    async fn rotation(
        &self,
        directory: &AcmeUrl,
    ) -> Result<Box<dyn AccountRotation>, AccountStoreError>;
}

/// One locked rollover transaction, usable by files, databases, or remote signers.
#[async_trait]
pub trait AccountRotation: Send + Sync {
    /// Snapshot captured while acquiring the session lease.
    fn record(&self) -> AccountRecord;
    /// Original signer, retained until local commit finishes.
    fn old_signer(&self) -> Arc<dyn AccountSigner>;
    /// Durably stage or reload the same proposed key. Never silently replace it.
    ///
    /// # Errors
    /// Reports missing staged keys, encoding, or persistence failures.
    async fn stage(&self) -> Result<Arc<dyn AccountSigner>, AccountStoreError>;
    /// Save progress while retaining both keys and the operation lease.
    ///
    /// # Errors
    /// Reports validation and durability failures.
    async fn save(&self, record: &AccountRecord) -> Result<(), AccountStoreError>;
    /// Idempotently install the confirmed new key and metadata before deleting staging.
    /// Blocking writes must retain the lease even when the calling task is cancelled.
    ///
    /// # Errors
    /// Reports incomplete local commit; both keys must remain recoverable on failure.
    async fn commit(&self, record: &AccountRecord) -> Result<(), AccountStoreError>;
}

/// Storage adapter failure without embedding secrets or persisted contents.
#[derive(Debug, Error)]
#[error("account storage failed: {message}")]
pub struct AccountStoreError {
    /// Sanitized diagnostic.
    pub message: String,
}

/// Explicit registration consent and optional CA-specific inputs.
#[derive(Default)]
pub struct RegistrationOptions {
    /// Account contact URIs; `mailto:` values are validated before network I/O.
    pub contacts: Vec<String>,
    /// Explicit user acceptance of the current terms advertised by the CA directory.
    pub terms_accepted: bool,
    /// Optional out-of-band CA EAB credentials; key bytes are never persisted.
    pub external_account: Option<ExternalAccountCredentials>,
}

/// Registered account identity returned to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeAccount {
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
    /// The CA does not advertise keyChange in its directory.
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

    /// Rotate a durable account key under RFC 8555 section 7.3.5.
    /// A previous pending request is reconciled using the new key and original account
    /// URL; failure never authorizes another keyChange POST. No private key enters metadata.
    ///
    /// # Errors
    /// Reports unsupported CA endpoints, inactive accounts, persistence failures, or
    /// uncertain remote outcomes. Rerunning finishes a confirmed interrupted local commit.
    pub async fn rotate_key(
        &self,
        keys: &dyn AccountRotationStore,
    ) -> Result<AccountRecord, AccountError> {
        let session = keys.rotation(self.client.directory_url()).await?;
        let mut record = session.record();
        let action = record
            .action(AccountOperation::RotateKey)
            .map_err(AccountError::from)?;
        if matches!(action, AccountAction::SendKeyChange)
            && self.client.directory().key_change.is_none()
        {
            return Err(AccountError::KeyChangeUnavailable);
        }
        let account_url = record
            .account_url
            .clone()
            .ok_or(AccountError::AccountDoesNotExist)?;
        let old = session.old_signer();
        if record.directory_url != *self.client.directory_url()
            || old.jwk()?.thumbprint()? != record.key_thumbprint
        {
            return Err(AccountError::IdentityMismatch);
        }
        let new = session.stage().await?;
        let new_thumbprint = new.jwk()?.thumbprint()?;
        if new_thumbprint == record.key_thumbprint
            || record
                .key_rotation
                .as_ref()
                .is_some_and(|rotation| rotation.new_thumbprint != new_thumbprint)
        {
            return Err(AccountError::IdentityMismatch);
        }
        match action {
            AccountAction::SendKeyChange => {
                self.send_key_change(session.as_ref(), &mut record, old.as_ref(), new.as_ref())
                    .await?;
            }
            AccountAction::ReconcileKeyChange => {
                let response = self
                    .client
                    .signed(&account_url, new.as_ref(), Some(&account_url), b"")
                    .await
                    .map_err(|_| AccountError::KeyRotationUncertain)?;
                if response.status != reqwest::StatusCode::OK {
                    return Err(AccountError::KeyRotationUncertain);
                }
                let account: AccountObject = serde_json::from_slice(&response.body)
                    .map_err(|_| AccountError::KeyRotationUncertain)?;
                record.observe(&account, self.clock.now());
            }
            AccountAction::FinalizeKeyChange => {}
            AccountAction::LookupExisting
            | AccountAction::Inspect
            | AccountAction::SendDeactivation
            | AccountAction::AlreadyDeactivated
            | AccountAction::Select
            | AccountAction::Update => {
                return Err(AccountError::InvalidResponse);
            }
        }
        record.key_rotation = Some(KeyRotation {
            new_thumbprint: new_thumbprint.clone(),
            phase: KeyRotationPhase::Confirmed,
        });
        session.save(&record).await?;
        session.commit(&record).await?;
        record.key_thumbprint = new_thumbprint;
        record.key_rotation = None;
        Ok(record)
    }

    // The mutation owns durable intent; the caller owns reconciliation and commit.
    async fn send_key_change(
        &self,
        session: &dyn AccountRotation,
        record: &mut AccountRecord,
        old: &dyn AccountSigner,
        new: &dyn AccountSigner,
    ) -> Result<(), AccountError> {
        let account_url = record
            .account_url
            .clone()
            .ok_or(AccountError::AccountDoesNotExist)?;
        let endpoint = self
            .client
            .directory()
            .key_change
            .as_ref()
            .ok_or(AccountError::KeyChangeUnavailable)?;
        let inner =
            crate::crypto::sign_key_change(new, &old.jwk()?, &account_url, endpoint.as_str())?;
        record.key_rotation = Some(KeyRotation {
            new_thumbprint: new.jwk()?.thumbprint()?,
            phase: KeyRotationPhase::Pending,
        });
        session.save(record).await?;
        let response = self
            .client
            .signed(endpoint, old, Some(&account_url), &json_payload(&inner)?)
            .await;
        let response = match response {
            Ok(response) => response,
            Err(
                error @ TransportError::Problem {
                    status: 400 | 409, ..
                },
            ) => {
                // A definitive protocol rejection is distinct from an unknown
                // timeout/5xx result. A later explicit invocation may start over.
                record.key_rotation = None;
                session.save(record).await?;
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };
        if response.status != reqwest::StatusCode::OK {
            return Err(AccountError::InvalidResponse);
        }
        record.times.last_used_at = Some(self.clock.now().to_offset(time::UtcOffset::UTC));
        Ok(())
    }

    /// Replace the complete account contact list under RFC 8555 section 7.3.2.
    /// An empty list clears remote contacts. Local intent is saved before HTTP and
    /// remains distinct from the last CA response if the update fails.
    ///
    /// # Errors
    /// Rejects invalid contacts, inactive identities, storage failures, or CA errors.
    pub async fn update_contacts(
        &self,
        signer: &dyn AccountSigner,
        contacts: Vec<String>,
    ) -> Result<AcmeAccount, AccountError> {
        validate_contacts(&contacts)?;
        let directory = self.client.directory_url();
        let thumbprint = signer.jwk()?.thumbprint()?;
        let _lease = self.store.lock_account(directory, &thumbprint).await?;
        let mut record = self
            .store
            .load(directory, &thumbprint)
            .await?
            .ok_or(AccountError::AccountDoesNotExist)?;
        if record.directory_url != *directory || record.key_thumbprint != thumbprint {
            return Err(AccountError::IdentityMismatch);
        }
        record
            .action(AccountOperation::Update)
            .map_err(AccountError::from)?;
        let account_url = record
            .account_url
            .clone()
            .ok_or(AccountError::AccountDoesNotExist)?;
        record.contacts.clone_from(&contacts);
        self.store.save(&record).await?;
        let payload = json_payload(&AccountUpdateRequest { contact: &contacts })?;
        let response = self
            .client
            .signed(&account_url, signer, Some(&account_url), &payload)
            .await?;
        if response.status != reqwest::StatusCode::OK {
            return Err(AccountError::InvalidResponse);
        }
        let account: AccountObject =
            serde_json::from_slice(&response.body).map_err(|_| AccountError::InvalidResponse)?;
        record.observe(&account, self.clock.now());
        self.store.save(&record).await?;
        Ok(AcmeAccount {
            times: record.times,
            account_id: record.account_id,
            directory_url: directory.clone(),
            account_url,
            status: account.status,
            contacts: account.contact.unwrap_or_default(),
            recovered: false,
        })
    }

    /// Register an account, reuse a registered identity, or recover a pending registration.
    ///
    /// A pending intent always first uses `onlyReturnExisting=true` and the same supplied
    /// signer. If the account does not exist, registration resumes with the pending intent.
    /// The account record is persisted before the first `newAccount` request. A timeout may
    /// leave the server mutation uncertain; this method deliberately keeps that intent.
    ///
    /// # Errors
    /// Reports invalid contacts, consent/EAB requirements, storage, crypto, or ACME failures.
    pub async fn register_or_recover(
        &self,
        signer: &dyn AccountSigner,
        options: RegistrationOptions,
    ) -> Result<AcmeAccount, AccountError> {
        let directory = self.client.directory_url().clone();
        let jwk = signer.jwk()?;
        let thumbprint = jwk.thumbprint()?;
        let _lease = self.store.lock_account(&directory, &thumbprint).await?;
        let mut record = self
            .load_or_prepare(&directory, &thumbprint, &options)
            .await?;
        match record
            .action(AccountOperation::Register)
            .map_err(AccountError::from)?
        {
            AccountAction::Inspect => {
                let account_url = record
                    .account_url
                    .clone()
                    .ok_or(AccountError::InvalidResponse)?;
                let response = self
                    .client
                    .signed(&account_url, signer, Some(&account_url), b"")
                    .await?;
                if response.status != reqwest::StatusCode::OK {
                    return Err(AccountError::InvalidResponse);
                }
                let account: AccountObject = serde_json::from_slice(&response.body)
                    .map_err(|_| AccountError::InvalidResponse)?;
                record.observe(&account, self.clock.now());
                self.store.save(&record).await?;
                return Ok(AcmeAccount {
                    times: record.times,
                    account_id: record.account_id,
                    directory_url: directory,
                    account_url,
                    status: account.status,
                    contacts: account.contact.unwrap_or_default(),
                    recovered: false,
                });
            }
            AccountAction::LookupExisting => {}
            AccountAction::SendDeactivation
            | AccountAction::AlreadyDeactivated
            | AccountAction::Select
            | AccountAction::Update
            | AccountAction::SendKeyChange
            | AccountAction::ReconcileKeyChange
            | AccountAction::FinalizeKeyChange => return Err(AccountError::InvalidResponse),
        }

        let mut recovered = false;
        let response = match self.new_account(signer, &record, &options, true).await {
            Ok(response) => {
                recovered = true;
                response
            }
            Err(AccountError::Transport(error)) if error.is_problem(ACCOUNT_DOES_NOT_EXIST) => {
                self.new_account(signer, &record, &options, false).await?
            }
            Err(error) => return Err(error),
        };
        let account_url = self.client.account_location(&response)?;
        if !matches!(
            response.status,
            reqwest::StatusCode::OK | reqwest::StatusCode::CREATED
        ) {
            return Err(AccountError::InvalidResponse);
        }
        let account: AccountObject =
            serde_json::from_slice(&response.body).map_err(|_| AccountError::InvalidResponse)?;
        record.account_url = Some(account_url.clone());
        record.observe(&account, self.clock.now());
        record.state = AccountRecordState::Registered;
        self.store.save(&record).await?;
        Ok(AcmeAccount {
            times: record.times,
            account_id: record.account_id,
            directory_url: directory,
            account_url,
            status: account.status,
            contacts: account.contact.unwrap_or_default(),
            recovered,
        })
    }

    /// Look up an existing account by key without ever creating one, then persist its identity.
    ///
    /// # Errors
    /// Missing remote account, unavailable storage or invalid server responses are errors.
    pub async fn recover(&self, signer: &dyn AccountSigner) -> Result<AcmeAccount, AccountError> {
        let directory = self.client.directory_url().clone();
        let thumbprint = signer.jwk()?.thumbprint()?;
        let _lease = self.store.lock_account(&directory, &thumbprint).await?;
        let previous = self.store.load(&directory, &thumbprint).await?;
        let mut record = previous.unwrap_or_else(|| AccountRecord {
            user_agent: None,
            times: AccountTimes::default(),
            account_id: account_id(&directory, &thumbprint),
            directory_url: directory.clone(),
            key_thumbprint: thumbprint.clone(),
            account_url: None,
            contacts: Vec::new(),
            server_contacts: None,
            last_status: None,
            deactivation: crate::account::DeactivationState::NotRequested,
            key_rotation: None,
            accepted_terms_url: None,
            state: AccountRecordState::RegistrationPending,
        });
        record
            .action(AccountOperation::Inspect)
            .map_err(AccountError::from)?;
        if record.directory_url != directory || record.key_thumbprint != thumbprint {
            return Err(AccountError::IdentityMismatch);
        }
        let response = self
            .new_account(signer, &record, &RegistrationOptions::default(), true)
            .await?;
        if response.status != reqwest::StatusCode::OK {
            return Err(AccountError::InvalidResponse);
        }
        let account_url = self.client.account_location(&response)?;
        let account: AccountObject =
            serde_json::from_slice(&response.body).map_err(|_| AccountError::InvalidResponse)?;
        record.account_url = Some(account_url.clone());
        record.observe(&account, self.clock.now());
        record.state = AccountRecordState::Registered;
        self.store.save(&record).await?;
        Ok(AcmeAccount {
            times: record.times,
            account_id: record.account_id,
            directory_url: directory,
            account_url,
            status: account.status,
            contacts: account.contact.unwrap_or_default(),
            recovered: true,
        })
    }

    /// Refresh a known account via authenticated POST-as-GET, recovering its URL if absent.
    ///
    /// # Errors
    /// Reports storage, missing account, or network/protocol errors; never creates accounts.
    pub async fn inspect(&self, signer: &dyn AccountSigner) -> Result<AcmeAccount, AccountError> {
        let directory = self.client.directory_url();
        let thumbprint = signer.jwk()?.thumbprint()?;
        {
            let _lease = self.store.lock_account(directory, &thumbprint).await?;
            if let Some(mut record) = self.store.load(directory, &thumbprint).await? {
                record
                    .action(AccountOperation::Inspect)
                    .map_err(AccountError::from)?;
                if record.directory_url != *directory || record.key_thumbprint != thumbprint {
                    return Err(AccountError::IdentityMismatch);
                }
                if let Some(account_url) = record.account_url.clone() {
                    let response = self
                        .client
                        .signed(&account_url, signer, Some(&account_url), b"")
                        .await?;
                    if response.status != reqwest::StatusCode::OK {
                        return Err(AccountError::InvalidResponse);
                    }
                    let account: AccountObject = serde_json::from_slice(&response.body)
                        .map_err(|_| AccountError::InvalidResponse)?;
                    record.observe(&account, self.clock.now());
                    self.store.save(&record).await?;
                    return Ok(AcmeAccount {
                        times: record.times,
                        account_id: record.account_id,
                        directory_url: directory.clone(),
                        account_url,
                        status: account.status,
                        contacts: account.contact.unwrap_or_default(),
                        recovered: false,
                    });
                }
            }
        }
        self.recover(signer).await
    }

    /// Irreversibly deactivate an existing account (RFC 8555 §7.3.6).
    ///
    /// Persist intent before a signed POST containing only status=deactivated. Network
    /// errors and malformed responses retain pending state; repeated calls never replay
    /// an uncertain mutation. A confirmed local deactivation returns without HTTP.
    ///
    /// # Errors
    /// Reports missing/mismatched identity, uncertain intent, non-active status, storage,
    /// cryptography or CA failures. Only HTTP 200 with deactivated status confirms success.
    pub async fn deactivate(
        &self,
        signer: &dyn AccountSigner,
    ) -> Result<AcmeAccount, AccountError> {
        let directory = self.client.directory_url();
        let thumbprint = signer.jwk()?.thumbprint()?;
        let _lease = self.store.lock_account(directory, &thumbprint).await?;
        let mut record = self
            .store
            .load(directory, &thumbprint)
            .await?
            .ok_or(AccountError::AccountDoesNotExist)?;
        if record.directory_url != *directory || record.key_thumbprint != thumbprint {
            return Err(AccountError::IdentityMismatch);
        }
        let account_url = record
            .account_url
            .clone()
            .ok_or(AccountError::AccountDoesNotExist)?;
        match record
            .action(AccountOperation::Deactivate)
            .map_err(AccountError::from)?
        {
            AccountAction::AlreadyDeactivated => {
                return Ok(AcmeAccount {
                    times: record.times,
                    account_id: record.account_id,
                    directory_url: directory.clone(),
                    account_url,
                    status: AccountStatus::Deactivated,
                    contacts: record.server_contacts.unwrap_or_default(),
                    recovered: false,
                });
            }
            AccountAction::SendDeactivation => {}
            AccountAction::LookupExisting
            | AccountAction::Inspect
            | AccountAction::Select
            | AccountAction::Update
            | AccountAction::SendKeyChange
            | AccountAction::ReconcileKeyChange
            | AccountAction::FinalizeKeyChange => {
                return Err(AccountError::InvalidResponse);
            }
        }
        record.deactivation = DeactivationState::Pending;
        self.store.save(&record).await?;
        let response = self
            .client
            .signed(
                &account_url,
                signer,
                Some(&account_url),
                &json_payload(&AccountStatusRequest {
                    status: AccountStatus::Deactivated,
                })?,
            )
            .await?;
        if response.status != reqwest::StatusCode::OK {
            return Err(AccountError::InvalidResponse);
        }
        let account: AccountObject =
            serde_json::from_slice(&response.body).map_err(|_| AccountError::InvalidResponse)?;
        if account.status != AccountStatus::Deactivated {
            return Err(AccountError::InvalidResponse);
        }
        record.observe(&account, self.clock.now());
        self.store.save(&record).await?;
        Ok(AcmeAccount {
            times: record.times,
            account_id: record.account_id,
            directory_url: directory.clone(),
            account_url,
            status: account.status,
            contacts: account.contact.unwrap_or_default(),
            recovered: false,
        })
    }

    async fn load_or_prepare(
        &self,
        directory: &AcmeUrl,
        thumbprint: &str,
        options: &RegistrationOptions,
    ) -> Result<AccountRecord, AccountError> {
        if let Some(mut record) = self.store.load(directory, thumbprint).await? {
            if &record.directory_url != directory || record.key_thumbprint != thumbprint {
                return Err(AccountError::IdentityMismatch);
            }
            record
                .action(AccountOperation::Register)
                .map_err(AccountError::from)?;
            validate_contacts(&options.contacts)?;
            if !options.contacts.is_empty() {
                // Keep local intent even if a CA omits contact in its account response.
                // Updating this input does not update an already registered remote account.
                record.contacts.clone_from(&options.contacts);
                self.store.save(&record).await?;
            }
            match &self.client.directory().meta.terms_of_service {
                // Consent is recorded as the discovered URL, not a reusable boolean:
                // a changed document requires another explicit acceptance by the caller.
                Some(current) if record.accepted_terms_url.as_ref() == Some(current) => {}
                Some(current) if options.terms_accepted => {
                    record.accepted_terms_url = Some(current.clone());
                    self.store.save(&record).await?;
                }
                Some(current) => return Err(AccountError::TermsRequired(current.clone())),
                None => {}
            }
            return Ok(record);
        }
        validate_contacts(&options.contacts)?;
        match &self.client.directory().meta.terms_of_service {
            Some(required) if !options.terms_accepted => {
                return Err(AccountError::TermsRequired(required.clone()));
            }
            Some(_) | None => {}
        }
        if self.client.directory().meta.external_account_required
            && options.external_account.is_none()
        {
            return Err(AccountError::ExternalAccountRequired);
        }
        let record = AccountRecord {
            user_agent: None,
            times: AccountTimes::default(),
            account_id: account_id(directory, thumbprint),
            directory_url: directory.clone(),
            key_thumbprint: thumbprint.to_owned(),
            account_url: None,
            contacts: options.contacts.clone(),
            server_contacts: None,
            last_status: None,
            deactivation: crate::account::DeactivationState::NotRequested,
            key_rotation: None,
            accepted_terms_url: self.client.directory().meta.terms_of_service.clone(),
            state: AccountRecordState::RegistrationPending,
        };
        self.store.save(&record).await?;
        Ok(record)
    }

    async fn new_account(
        &self,
        signer: &dyn AccountSigner,
        record: &AccountRecord,
        options: &RegistrationOptions,
        only_return_existing: bool,
    ) -> Result<crate::transport::AcmeResponse, AccountError> {
        if !only_return_existing {
            match (
                &self.client.directory().meta.terms_of_service,
                &record.accepted_terms_url,
            ) {
                (Some(required), Some(accepted)) if required == accepted => {}
                (Some(required), _) => return Err(AccountError::TermsRequired(required.clone())),
                (None, _) => {}
            }
            if self.client.directory().meta.external_account_required
                && options.external_account.is_none()
            {
                return Err(AccountError::ExternalAccountRequired);
            }
        }
        let binding = match (&options.external_account, only_return_existing) {
            (Some(eab), false) => {
                Some(eab.bind(&signer.jwk()?, self.client.directory().new_account.as_str())?)
            }
            (Some(_), true) | (None, _) => None,
        };
        let body = if only_return_existing {
            json_payload(&FindAccountRequest {
                only_return_existing: true,
            })?
        } else {
            json_payload(&NewAccountRequest {
                contact: (!record.contacts.is_empty()).then_some(record.contacts.as_slice()),
                terms_of_service_agreed: record.accepted_terms_url.as_ref().map(|_| true),
                external_account_binding: binding.as_ref(),
            })?
        };
        let response = self
            .client
            .signed(&self.client.directory().new_account, signer, None, &body)
            .await?;
        if only_return_existing && response.status != reqwest::StatusCode::OK {
            return Err(AccountError::InvalidResponse);
        }
        if response.status == reqwest::StatusCode::CREATED
            && let Some(expected) = &binding
        {
            let account: AccountObject = serde_json::from_slice(&response.body)
                .map_err(|_| AccountError::InvalidResponse)?;
            if account.external_account_binding.as_ref() != Some(expected) {
                return Err(AccountError::ExternalAccountNotConfirmed);
            }
        }
        Ok(response)
    }
}

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

fn account_id(directory: &AcmeUrl, thumbprint: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest as _, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(
        format!("{}\0{thumbprint}", directory.as_str()).as_bytes(),
    ))
}

#[cfg(test)]
mod tests;
