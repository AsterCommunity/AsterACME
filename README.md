# AsterACME

A Rust ACME client for automated certificate issuance and lifecycle management.

> Account registration, listing, recovery, inspection, deactivation, and local removal are implemented, alongside protocol states and solver contracts. Manual DNS-01 certificate issuance, durable recovery and read-only order inspection are implemented and tested against a loopback CA. Automated DNS providers, renewal and revocation remain unimplemented.

## Direction

- ACME protocol support based on [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html).
- Automated DNS-01 validation using reusable DNS provider integrations.
- HTTP-01 validation and certificate renewal, including [ACME Renewal Information (RFC 9773)](https://www.rfc-editor.org/rfc/rfc9773.html).
- An embeddable Rust library and a CLI for certificate automation.

Automatic DNS publication, HTTP/TLS validation, renewal and deployment remain planned capabilities.

## Documentation

- Crate guides: [core](crates/aster_acme_core/README.md), [protocol](crates/aster_acme_protocol/README.md), [client](crates/aster_acme/README.md), [DNS](crates/aster_acme_validation/README.md), [CLI](crates/aster_acme_cli/README.md), [CLI storage](crates/aster_acme_cli_storage/README.md)
- [Account protocol tests and staging evidence (中文)](docs/account-testing.md)
- [Manual DNS issuance tests and limits (中文)](docs/issuance-testing.md)
- [Architecture design (中文)](docs/architecture.md)
- [ACME RFC reference and implementation considerations (中文)](docs/rfc-reference.md)

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

SPDX license expression: `MIT OR Apache-2.0`.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you shall be dual licensed as above, without
any additional terms or conditions.

## Development

Requires stable Rust (currently at least 1.99) and Python 3.11+ for the dependency policy check.

```sh
python3 scripts/check-workspace-deps.py
cargo fmt --all --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run -p aster_acme_cli -- --help
```

All member dependencies must inherit from `[workspace.dependencies]` using
`workspace = true`; versions and features are selected only at the root.
