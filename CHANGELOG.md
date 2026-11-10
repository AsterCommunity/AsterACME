# Changelog

[中文](CHANGELOG.zh.md)

## [Unreleased]

### Added

- **ACME account management** — Register and recover named accounts, inspect offline or verify with the CA, update contacts, rotate keys with durable reconciliation, deactivate accounts, and remove local managed files. Support public CA presets, custom directories, explicit terms consent, EAB, account-scoped User-Agent, and default selection without overwriting concurrent changes.
- **Manual DNS certificate issuance** — `cert issue` handles orders, SAN/wildcard authorization, manual TXT requirements, optional DNS visibility checks, fixed certificate keys/CSRs, finalization, download, and artifact validation. Resume saved requests by certificate name with explicit request selection for ambiguity. `-y/--yes` skips the TXT confirmation on resume while retaining DNS checks; `--force` skips only the local DNS check. Fresh automated requests first return TXT instructions. `cert list/show` remains read-only unless explicitly refreshing CA observations with `--verify`.
- **Recoverable private storage** — Versioned TOML, AsterFs locks, bounded reads, atomic writes, and immutable key/CSR binding. Readable timestamped certificate versions retain full-chain, leaf, CA-chain, and private-key PEM files behind an atomic `current` link. Failed validation or writes do not replace the selected certificate; unrelated user files are preserved.
- **CLI interaction and automation** — Shared storage/HTTP argument groups, meaningful short options, missing-input guidance, default-no confirmations, compact request selectors, aligned colored details/tables, fixed UTC times, accurate verification markers, typed progress, JSON output, and build/version metadata. The [CLI contract](docs/cli-contract.md) defines confirmation, force, consent, and command scopes.
- **Embeddable protocol layers** — Pure state decisions, typed ACME resources/JWS/problems, exact discovered URLs, ES256/HS256, bounded nonce retries, timeout/cancellation handling, and object-safe signer/store/readiness/observer contracts. Unknown challenge extensions are retained without imposing DNS-01-specific token requirements. Validation implementations are organized by method in `aster_acme_validation`.

### Changed

- **Dependency and TLS ownership** — Forge HTTP/utils/macros use published `=0.1.0-alpha.1` crates, AsterFs uses `=0.1.0`, and base64 uses 0.23.1. Rustls and the shared AWS-LC crypto backend avoid duplicate P-256 stacks. CI rejects native-tls/OpenSSL transport dependencies. Every crate owns its package version; dependency versions, sources, and features remain centralized in the workspace.
- **Release builds** — Optimize the CLI and its dependencies for size with `opt-level="z"`, LTO, and one codegen unit. Keep unwind panics and function symbols while excluding source-level debug information. Panic-hook integration is tracked in [#1](https://github.com/AsterCommunity/AsterACME/issues/1), pending upstream support.
- **Documentation** — Bilingual README and changelog, the project website, crate guides, RFC references, architecture, CLI contracts, and separate local/staging validation records. Automated DNS publication, HTTP/TLS solvers, renewal, ARI, revocation, and deployment remain unimplemented.

[Unreleased]: https://github.com/AsterCommunity/AsterACME/commits/main/
