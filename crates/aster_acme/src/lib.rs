//! High-level ACME services, orchestration, and adapter contracts.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::unreachable,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo
    )
)]

pub mod account;
pub mod challenge;
pub mod crypto;
mod http_client;
pub mod identifier;
pub mod issuance;
pub mod renewal;
mod renewal_calculation;
pub mod revocation;
pub mod solver;
pub mod storage;
pub mod transport;

#[cfg(test)]
mod tests;
