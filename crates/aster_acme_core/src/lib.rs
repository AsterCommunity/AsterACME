//! ACME resource states and state machine decisions.
//!
//! This crate must remain independent of async runtimes and external I/O.

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
pub mod machine;
pub mod protocol;
pub mod workflow;

#[cfg(test)]
mod tests;
