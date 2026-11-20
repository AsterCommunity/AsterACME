//! Typed ACME wire contracts for [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555), [RFC 9773](https://datatracker.ietf.org/doc/html/rfc9773), and implemented extensions.
//!
//! Resource URLs remain exact, unknown extension data is retained, and protocol
//! serialization is kept independent of HTTP execution, storage, runtimes, and signing.

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
pub mod order;
pub mod problem;
pub mod renewal;
pub mod revocation;
pub mod url;

#[cfg(test)]
mod tests;
