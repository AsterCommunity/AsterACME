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

pub mod challenge;
pub mod identifier;
pub mod solver;

#[cfg(test)]
mod tests;
