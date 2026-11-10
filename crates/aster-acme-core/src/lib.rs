//! ACME protocol models and state transition rules.
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
