//! Challenge validation implementations and method-specific readiness checks.

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

#[cfg(any(feature = "dns01", feature = "precheck-caa"))]
mod dns;
#[cfg(feature = "dns01")]
pub mod dns01;
#[cfg(any(feature = "dns01", feature = "precheck-caa"))]
pub mod resolver;

#[cfg(feature = "precheck-caa")]
pub mod caa;
#[cfg(feature = "precheck-dns")]
pub mod txt;
