//! Local workflow checkpoints, independent of server resource statuses.

use serde::{Deserialize, Serialize};

/// Last persisted issuance phase; failure does not discard this checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuancePhase {
    /// Load or establish the account.
    PreparingAccount,
    /// Create or reconcile an order.
    CreatingOrder,
    /// Complete outstanding authorizations.
    Authorizing,
    /// Wait until the CA accepts finalization.
    AwaitingOrderReady,
    /// Submit or reconcile the CSR.
    Finalizing,
    /// Wait for issuance.
    AwaitingCertificate,
    /// Download and inspect the issued chain.
    Downloading,
    /// Issued certificate has been persisted, independently of cleanup/deployment.
    Completed,
}

/// Whether challenge publication has a durable receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationState {
    /// Intent persisted before the external side effect.
    Planned,
    /// Publication receipt persisted.
    Prepared,
}

/// Cleanup status, independent of issuance success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    /// No owned resource needs removal.
    NotRequired,
    /// Cleanup remains outstanding, including after failure or cancellation.
    Pending,
    /// Owned resources have been removed.
    Completed,
}
