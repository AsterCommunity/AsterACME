//! Minimal locked revocation persistence, independent of certificate issuance.
use crate::{
    issuance::IssueError,
    revocation::{RevocationRecord, RevocationTarget},
};
use async_trait::async_trait;

/// One immutable certificate target and its durable revocation checkpoint.
/// Implementations serialize access and retain their IO leases through cancellation.
#[async_trait]
pub trait RevocationSession: Send + Sync {
    /// Load the exact certificate and CA binding under the execution lease.
    /// # Errors
    /// Rejects missing, corrupt, unsafe or unissued certificate material.
    async fn target(&self) -> Result<RevocationTarget, IssueError>;
    /// Read the latest durable checkpoint; pending is not a confirmed revocation.
    /// # Errors
    /// Reports inaccessible or corrupt checkpoint state.
    async fn revocation(&self) -> Result<RevocationRecord, IssueError>;
    /// Persist a checkpoint without replacing the target, keys or other metadata.
    /// # Errors
    /// Rejects target drift and journal failures before another mutation is sent.
    async fn save_revocation(&self, record: &RevocationRecord) -> Result<(), IssueError>;
}
