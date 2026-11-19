//! Pure ACME protocol states, durable operation transitions, and renewal decisions.
//!
//! `aster_acme_core` owns deterministic domain rules used by embedded services and the
//! CLI. It has no network, filesystem, signing, async-runtime, or terminal dependencies;
//! adapters persist its outputs and perform external effects at explicit boundaries.

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
pub mod local_name;
pub mod machine;
pub mod protocol;
pub mod renewal;
pub mod revocation;
pub mod workflow;

pub mod caa;
#[cfg(test)]
mod tests;
