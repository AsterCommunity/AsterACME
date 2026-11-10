//! Typed RFC 8555 wire contracts; no HTTP, filesystem, runtime or signing operations.

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
pub mod directory;
pub mod jws;
pub mod problem;
pub mod url;

#[cfg(test)]
mod tests;
