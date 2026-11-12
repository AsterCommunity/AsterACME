//! Object-safe account metadata, signer and key-rotation persistence contracts.
use crate::{account::AccountRecord, crypto::AccountSigner};
use aster_acme_protocol::url::AcmeUrl;
use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;

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

/// Key access intent; creation never replaces a saved identity.
#[derive(Debug, Clone, Copy)]
pub enum KeyAccess {
    /// Load an existing identity without generating material.
    Existing,
    /// Create if absent; an explicit choice must match any already saved key.
    Create(Option<crate::crypto::key_algorithm::KeyAlgorithm>),
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
        access: KeyAccess,
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
    /// None uses the original algorithm for new material, or the actual saved staged
    /// key on recovery. An explicit mismatched choice must fail without replacing it.
    ///
    /// # Errors
    /// Reports missing staged keys, encoding, or persistence failures.
    async fn stage(
        &self,
        algorithm: Option<crate::crypto::key_algorithm::KeyAlgorithm>,
    ) -> Result<Arc<dyn AccountSigner>, AccountStoreError>;

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
