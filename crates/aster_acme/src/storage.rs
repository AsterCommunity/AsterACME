//! Runtime-independent persistence contracts for embedders and file/database adapters.
//! Query filters select local snapshots; mutation methods revalidate eligibility under lease.
pub mod account;
pub mod issuance;
pub mod query;
