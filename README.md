# AsterACME

A Rust ACME client for automated certificate issuance and lifecycle management.

> Protocol states, input types, and solver contracts are implemented. Certificate operations are not implemented yet.

## Direction

- ACME protocol support based on [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html).
- Automated DNS-01 validation using reusable DNS provider integrations.
- HTTP-01 validation and certificate renewal, including [ACME Renewal Information (RFC 9773)](https://www.rfc-editor.org/rfc/rfc9773.html).
- An embeddable Rust library and a CLI for certificate automation.

These are planned capabilities, not currently available features.

## Documentation

- Crate guides: [core](crates/aster-acme-core/README.md), [client](crates/aster-acme/README.md), [DNS](crates/aster-acme-dns/README.md), [CLI](crates/aster-acme-cli/README.md)
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
cargo run -p aster-acme-cli -- --help
```

All member dependencies must inherit from `[workspace.dependencies]` using
`workspace = true`; versions and features are selected only at the root.
