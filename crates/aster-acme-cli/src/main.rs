//! `AsterACME` command-line interface.
//!
//! Certificate operations are not implemented yet.

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

use clap::Parser;

/// ACME client scaffold. Certificate operations are not implemented yet.
#[derive(Parser)]
#[command(name = "aster-acme", version, about)]
struct Args {}

fn main() {
    let _args = Args::parse();
    eprintln!("AsterACME is not implemented yet. Use --help for project status.");
    std::process::exit(2);
}
