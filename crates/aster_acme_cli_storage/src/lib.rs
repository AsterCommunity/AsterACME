//! Private local account metadata, process locks and PKCS#8 key files for the CLI.
//!
//! TODO(AsterFs #3/#4): consume published trusted-root file primitives when available.
//! Keep standard-library locks/ordinary IO here; only move missing platform mechanisms.
//! Account/certificate schemas, leases and recovery decisions remain ACME-owned.
//! <https://github.com/AsterCommunity/AsterFs/issues/3>
//! <https://github.com/AsterCommunity/AsterFs/issues/4>

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
pub mod daemon;
pub mod inventory;
pub mod issuance;
pub mod state_file;
pub mod toml_file;
