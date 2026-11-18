# Contributing to AsterACME

## Community Expectations

Please read and follow the [Code of Conduct](CODE_OF_CONDUCT.md) before participating in issues, pull requests, discussions, and review threads.

## Getting Started

Building and testing AsterACME requires Rust; the exact toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml). Tests use temporary directories, loopback listeners, and mocks; real DNS and public CA acceptance are separate and never required for ordinary contributions.

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/<your-github-username>/AsterACME.git
   cd AsterACME
   git remote add upstream https://github.com/AsterCommunity/AsterACME.git
   ```
3. Build and run:
   ```bash
   cargo build --locked
   cargo run -p aster_acme_cli -- version
   ```

## Development Workflow

### AI-Assisted Contributions

AsterCommunity welcomes responsible use of AI-assisted development tools. You may use them to read code, learn the architecture, explore an unfamiliar subsystem, draft an implementation, write tests, or review a change. We consider using these tools to understand the project better a productive part of contributing.

The contributor remains responsible for every submitted change, regardless of which tools helped produce it. Before opening a pull request, you must:

- understand the code you submit and be able to explain its behavior and architectural fit;
- review generated suggestions against the current code, project contracts, and authoritative external specifications instead of accepting them blindly;
- add and run tests that cover the changed behavior, including relevant failure, boundary, recovery, cancellation, concurrency, and protocol compatibility cases;
- verify that the change does not expose credentials, private keys, personal data, proprietary material, or content with incompatible licensing;
- accurately report what was tested, what was not tested, and any remaining limitations;
- address review feedback and maintain the contribution just as you would for code written without AI assistance.

AI assistance does not lower the bar for correctness, security, maintainability, or test coverage. A generated patch without demonstrated understanding and appropriate verification is not ready to merge. The person submitting the pull request—not the tool—is accountable for the result.

### Branch Naming

- `feat/<description>` - New features
- `fix/<description>` - Bug fixes
- `refactor/<description>` - Refactoring
- `docs/<description>` - Documentation

### Commit Messages

Use conventional commits:

```
feat(issuance): support TLS-ALPN-01 challenge solver
fix(storage): keep lease until blocked write completes
refactor(protocol): split order observation types
docs: update DNS provider contract
```

### Before Submitting a PR

```bash
cargo fmt --all --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked

# Repository contract checks
python3 scripts/check-workspace-deps.py
python3 scripts/check-rust-imports.py
python3 scripts/check-dependency-features.py
python3 scripts/check-doc-links.py
```

Replace the full `cargo test --workspace --locked` with a focused target while iterating, for example `cargo test -p aster_acme_cli_storage --locked issuance::deployment`, and run the broader suite when the change crosses crate or protocol boundaries. Documentation changes must pass `python3 scripts/check-doc-links.py`, and `README.md`/`README.zh.md` as well as `CHANGELOG.md`/`CHANGELOG.zh.md` are maintained as paired language files.

## Project Conventions

### Crate Boundaries

The workspace splits responsibilities across crates, and changes are expected to stay inside the owning crate's role:

- `aster_acme_core` — pure decisions, no network, file, or runtime dependencies
- `aster_acme_protocol` — named ACME wire types and encoding
- `aster_acme` — protocol orchestration and domain services
- `aster_acme_cli_storage` — file layout, leases, atomic IO, and typed queries
- `aster_acme_cli` — interaction, output sessions, and process concerns

### Type and Dependency Rules

- Dependency versions and features are defined only in the root workspace; members inherit with `workspace = true`, and only optional dependencies may be toggled by crate features.
- Production code uses no `unsafe` and no `unwrap`/`expect`/`panic` placeholders.
- Implicit `use super::...` imports are not used; imports go through the actual `crate::` owner path.
- No pass-through facades, hidden global registries, or legacy import-path compatibility layers.
- Persistence saves intent before side effects; uncertain remote outcomes are never replayed automatically.
- Private keys and credentials never appear in logs, errors, or public output.

### Output and Interaction

- Human output uses shared output/time/log/table helpers; JSON output is a single structured result with no prompts and no mixed human logs.
- Every business command takes at most one positional argument (`cert deploy show` is the documented exception).
- `--yes` only accepts operation confirmations; it does not select targets, fill missing input, or accept CA terms.

## Architecture

See the [developer documentation](docs/README.md), the [architecture overview](docs/architecture.md), and the [task routing](docs/task-routing.md) for crate ownership, dependency direction, and where a change belongs. Protocol requirements are anchored in the [RFC reference](docs/rfc-reference.md).

## License

By contributing, you agree that your contributions will be licensed under either the Apache License, Version 2.0 or the MIT license, at the recipient's option.
