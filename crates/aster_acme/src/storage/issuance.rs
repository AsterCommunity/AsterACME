//! Object-safe certificate persistence sessions and typed inventory queries.
use crate::storage::query::IssueQuery;
use crate::{
    account::AccountRecord,
    issuance::{CertificateName, IssueError, IssueRecord, IssueRequest},
};
use async_trait::async_trait;

/// Locked recoverable generation. Blocking persistence must retain its lease on cancellation.
#[async_trait]
pub trait IssueSession: Send + Sync {
    /// Latest durable snapshot under the generation/certificate lease, including prior calls.
    ///
    /// # Errors
    /// Reports journal, identity and pending persistence failures.
    async fn record(&self) -> Result<IssueRecord, IssueError>;
    /// Persist the next checkpoint before performing an external mutation.
    ///
    /// # Errors
    /// Reports identity, journal and durability failures.
    async fn save(&self, record: &IssueRecord) -> Result<(), IssueError>;
    /// Load the fixed DER CSR; never generate a replacement on read failure.
    ///
    /// # Errors
    /// Missing, unsafe or corrupt CSR is an error.
    async fn csr(&self) -> Result<Vec<u8>, IssueError>;
    /// Read the issued leaf as DER; no private key is exposed to revocation orchestration.
    ///
    /// # Errors
    /// Rejects missing, corrupt or unsafe certificate artifacts.
    async fn certificate_der(&self) -> Result<Vec<u8>, IssueError>;
    /// Persist a validated chain then atomically select this generation. Populate the
    /// returned record's `renewal` with `RenewalPlan::from_certificate` before promotion
    /// so every adapter durably establishes a fallback independently of ARI availability.
    ///
    /// # Errors
    /// Failure must retain the previous `in_use` generation and recoverable checkpoint.
    async fn complete(&self, record: &IssueRecord, chain: &[u8])
    -> Result<IssueRecord, IssueError>;
}

/// Object-safe generation storage contract for files, databases and embedded services.
#[async_trait]
pub trait IssueStore: Send + Sync {
    /// Create a new managed certificate and its first fixed key/CSR generation.
    /// Existing managed names are rejected atomically; this never appends a version.
    ///
    /// # Errors
    /// Rejects unsafe names, storage errors and incomplete local initialization.
    async fn create(
        &self,
        request: &IssueRequest,
        account: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError>;
    /// Prepare another generation using the existing certificate's immutable definition.
    /// This is storage groundwork for renewal, not a CA request or a scheduler.
    ///
    /// # Errors
    /// Rejects missing definitions, changed account bindings and persistence failures.
    async fn renew(
        &self,
        name: &CertificateName,
        account: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError>;
    /// Open one exact generation and acquire an exclusive execution lease.
    ///
    /// # Errors
    /// Rejects missing, mismatched, unsafe or contended generations.
    async fn open(
        &self,
        name: &CertificateName,
        operation_id: &str,
    ) -> Result<Box<dyn IssueSession>, IssueError>;
    /// Open a locked metadata observation session without loading signing/key material.
    /// Execution sessions still use `open` and validate their fixed key/CSR artifacts.
    /// # Errors
    /// Rejects missing identity, inconsistent catalogs and unavailable leases.
    /// Implementations must bound lease acquisition without abandoning started IO.
    async fn open_observation(
        &self,
        name: &CertificateName,
        operation_id: &str,
    ) -> Result<Box<dyn IssueSession>, IssueError>;

    /// Query local snapshots only; never load private keys or contact a CA.
    /// Implementations should apply the filters before materializing unrelated records.
    ///
    /// # Errors
    /// Rejects invalid filters and unsafe, oversized or corrupt matching journals.
    async fn query(&self, query: IssueQuery) -> Result<Vec<IssueRecord>, IssueError>;
}
