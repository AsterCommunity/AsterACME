<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/readme/asteracme-on-dark.svg" />
    <img src="assets/readme/asteracme-on-light.svg" alt="AsterACME" width="320" />
  </picture>
</p>

<p align="center">
  An embeddable Rust ACME client and CLI for account management, manual DNS validation, and recoverable certificate issuance.
  <br />
  Explicit protocol states, durable checkpoints, and certificate files you can deploy.
</p>

<p align="center">
  <a href="https://acme.astercosm.com"><img alt="Website" src="https://img.shields.io/badge/website-AsterACME-2563EB?style=for-the-badge"></a>
  <a href="README.zh.md"><img alt="中文 README" src="https://img.shields.io/badge/README-%E4%B8%AD%E6%96%87-E11D48?style=for-the-badge"></a>
  <a href="docs/architecture.md"><img alt="Architecture" src="https://img.shields.io/badge/architecture-overview-0F172A?style=for-the-badge"></a>
  <a href="docs/rfc-reference.md"><img alt="RFC Reference" src="https://img.shields.io/badge/ACME-RFC%208555-059669?style=for-the-badge"></a>
  <a href="CHANGELOG.md"><img alt="Changelog" src="https://img.shields.io/badge/changelog-unreleased-7C3AED?style=for-the-badge"></a>
</p>

<p align="center">
  <a href="https://github.com/AsterCommunity/AsterACME/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/AsterCommunity/AsterACME/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="rust-toolchain.toml"><img alt="Rust 1.99+" src="https://img.shields.io/badge/Rust-1.99%2B-000000?style=flat-square&amp;logo=rust"></a>
  <a href="LICENSE-MIT"><img alt="MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square"></a>
</p>

## What is AsterACME?

AsterACME implements ACME account operations and manual DNS-01 certificate issuance as a Rust library and command-line application. You request a certificate; the library creates the order, tracks authorizations, submits the fixed CSR, downloads the issued chain, and persists the result. The CLI supplies terminal interaction and local storage.

The project is under active development and has not released its ACME packages. Manual issuance and recovery, ARI renewal planning, and account-signed certificate revocation are implemented. Automated DNS providers, HTTP/TLS validation, automatic renewal, daemon scheduling, and deployment hooks remain planned.

## Where it fits

- Request certificates for individual domains, multiple SANs, and wildcard names using manual DNS validation.
- Manage several named accounts, each bound to its own CA and account key.
- Resume saved issuance attempts without regenerating their certificate key or CSR.
- Embed the protocol service in an application with injected storage, signing, readiness, and progress interfaces.
- Use either terminal prompts or explicit arguments and structured JSON in scripts.

An unattended certificate lifecycle still needs automated publication and renewal support, which is not available yet. The in_use private filesystem adapter supports Unix; library consumers can provide other adapters.

## Design focus

- **Protocol ownership** — Typed ACME models live in `aster_acme_protocol`. Resource URLs come from the CA; client code does not construct fixed ACME paths.
- **Explicit decisions** — The pure core returns actions from CA observations and saved submission state. The service owns HTTP, timers, and execution.
- **Recoverable operations** — Mutation intent is durable before submission. Pending responses do not authorize silently creating another order or repeating finalization.
- **Stable artifacts** — Each request has a separate timestamped version. A validated complete artifact set is promoted through an atomic `in_use` link.
- **Shared mechanisms** — Forge HTTP, AsterFs locks, rustls, and AWS-LC provide transport and crypto foundations; application rules remain in ACME.

## Quick start

### Build from source

Use stable Rust 1.99 or newer:

```sh
git clone https://github.com/AsterCommunity/AsterACME.git
cd AsterACME
cargo build --release -p aster_acme_cli --locked
./target/release/aster-acme --help
```

Or install the binary locally from the checkout:

```sh
cargo install --path crates/aster_acme_cli --locked
```

The executable is `aster-acme`; Cargo package names use underscores. The following examples assume the binary is on `PATH`.

### Register an account

```sh
aster-acme account register default \
  --contact admin@example.com \
  --data-dir ./data
```

Review and accept the CA terms when prompted. The default CA is Let's Encrypt production. `--ca` also accepts `zerossl` and `google`; `--ca-directory <URL>` selects a custom directory. EAB credentials are supplied only when required by the selected CA.

```sh
aster-acme account list --data-dir ./data
aster-acme account show default --data-dir ./data
aster-acme account show default --verify --data-dir ./data
aster-acme account switch default --data-dir ./data
```

`show` is offline unless `--verify` is supplied. Registration, key-based recovery, contact updates, key rotation, CA deactivation, and local removal are separate operations. Removing local files does not deactivate the CA account or revoke certificates.

### Account key algorithms

Accounts and certificates independently support the same eight key choices. New accounts default to ECDSA P-256. `account rotate-key` without `-k` retains the existing type, or resumes the saved staged key; an explicit conflicting type is rejected. CA support varies: RFC 8555 requires ES256 and recommends Ed25519; unsupported algorithms are not silently replaced.

```sh
aster-acme account register work -k rsa-3072 --accept-terms
aster-acme account rotate-key work -k ed25519 --yes
aster-acme account show work
```

Account metadata and `list/show` expose the actual key type. Account signing uses ES256/ES384/ES512/EdDSA/RS256 as appropriate; certificate key choices remain independent. ACME packages are unreleased: the account schema now requires `key_algorithm`, without legacy readers or migration.

### Issue a certificate

```sh
aster-acme cert issue \
  -n example-cert \
  -a default \
  -d example.com \
  -d '*.example.com' \
  -c manual_dns \
  --data-dir ./data
```

Publish every requested TXT value, keeping unrelated existing records. Several values can be required at the same owner name. The CLI checks their visibility before asking the CA to validate them. Local DNS visibility is readiness evidence; the CA makes the authorization decision.

If you need to finish later:

```sh
aster-acme cert issue --resume example-cert --data-dir ./data
aster-acme cert list --data-dir ./data
aster-acme cert show example-cert --data-dir ./data
aster-acme cert show example-cert --verify --data-dir ./data
```

Each new issue creates an independent managed certificate. Default names combine the primary domain with a random suffix; collisions retry automatically. Explicit `-n/--name` names must be unused. Stable cert.toml definitions retain domains, account, CA and validation method; subsequent renewal generations stay under that same name. `--resume` continues an existing operation. List/show default to in_use, `list --history` expands versions, and `show --history` or `--operation` selects historical requests. Only in_use has an active renewal schedule.

`cert show` without a name guides terminal selection. Certificate listing and inspection do not advance validation or issuance. Expired requests remain visible but cannot continue validation or finalization.

## Certificate key algorithms

Use `-k/--key-type` with `ecdsa-p256` (default), `ecdsa-p384`, `ecdsa-p521`, `ed25519`, `rsa-2048`, `rsa-3072`, `rsa-4096`, or `rsa-8192`. These are client generation capabilities; CA acceptance varies. The choice is persisted and retained on recovery and renewal generations. Account signing uses the same key-choice enum independently; see the account options below.

## Renewal planning and revocation

After issuance, fetch ARI immediately and persist a random time inside the suggested window. Without usable ARI, schedule renewal after two thirds of the original certificate validity. Persist `Retry-After` query deadlines, retry transient failures with bounded backoff, and retain the previous plan on refresh failure. `cert list/show` display the plan; `show --verify` refreshes due ARI. `cert renew` executes a single due renewal (or --now for early renewal). Batch renewal uses `cert renew --all`: process each managed certificate sequentially, retain manual TXT tasks, continue after per-item failures, and emit one summary. `--all` conflicts with a certificate name. JSON emits one report; failures exit 1 and cancellation exits 130. Periodic wakeups remain future daemon work.

```sh
aster-acme cert renew example-cert
aster-acme cert renew example-cert --now
aster-acme cert renew --all
aster-acme cert renew --all --now --json
aster-acme cert revoke example-cert --reason key-compromise --yes
aster-acme cert remove example-cert --history --yes
aster-acme cert remove example-cert --revoked --yes
aster-acme cert remove example-cert --all --yes
```

Revocation uses the bound issuing account and requires confirmation. Select the exact generation when ambiguous. Local files remain; a timeout is recorded as unconfirmed. `cert remove` defaults to one exact request. `--history` cleans issued non-in_use versions, `--revoked` matches saved revocation confirmations, and `--all` explicitly deletes the whole group. Clearing in_use never promotes an old version. Files not managed by AsterACME are preserved; an otherwise empty certificate directory is removed. No CA request is made. See the [renewal and revocation contract](docs/certificate-lifecycle.md).

## Scripts and confirmation

```sh
# First call returns JSON with status=action_required and the TXT requirements.
aster-acme cert issue -n script-cert -d example.com -c manual_dns --json --data-dir ./data

# After publishing the TXT values, resume without the manual confirmation.
aster-acme cert issue --resume script-cert --yes --json --data-dir ./data
```

An `action_required` result exits successfully but is not an issued certificate; inspect the JSON `status`.

| Option | Contract |
| --- | --- |
| `-y`, `--yes` | Confirm the in_use command's action; on certificate resume, skip the TXT publication question. It does not disable name selection, accept CA terms, or bypass DNS checks. |
| `--accept-terms` | Explicitly accept the selected CA's current terms during registration. |
| `-f`, `--skip-dns-check` | Skip only the local DNS visibility check; CA validation, expiry, and artifact checks still apply. |
| `--json` | Structured output; no prompts, terminal styling, or human progress messages. |
| `--verify` | Explicitly query the CA for an existing resource. Offline reads remain the default. |

First automated/manual-DNS requests expose their fresh TXT instructions even with `--yes` and `--skip-dns-check`; resume after publication. `--yes` never guesses missing inputs. HTTP `--timeout` and foreground `--wait-timeout` are independent of the CA's expiry times. See the [CLI contract](docs/cli-contract.md) for command scopes and short options.

## Data and certificate files

`--data-dir` is the only storage-root override. Without it, the platform configuration directory for `com.astercosm.acme` is used. `config.toml` is initialized automatically; there is no separate `--config` path.

```text
<data-dir>/
├── config.toml
├── .locks/{accounts,certificates}/<name>.lock
├── accounts/<name>/
│   ├── account.toml
│   └── account-key.pk8
└── certs/example-cert/
    ├── cert.toml
    ├── in_use -> 20261111T010851Z-9YowFEL2/
    └── 20261111T010851Z-9YowFEL2/
        ├── operation.toml
        ├── private-key.pk8
        ├── request.der
        ├── material.sha256
        ├── fullchain.pem
        ├── cert.pem
        ├── ca.pem
        └── private-key.pem
```

Deploy from `in_use/fullchain.pem`, `in_use/cert.pem`, `in_use/ca.pem`, and `in_use/private-key.pem`. The PEM and internal DER keys represent the same certificate key, separate from the account key. `ca.pem` contains only the rest of the chain returned by the CA and is empty for a leaf-only response. The client does not append or install roots.

Existing versions remain available when a new request fails. Extra user files are preserved; correctness checks apply to managed records and artifacts. Pre-release formats change directly without compatibility readers or automatic migration.

## Project structure

| Crate | Responsibility |
| --- | --- |
| [`aster_acme_core`](crates/aster_acme_core/README.md) | Pure resource-state and workflow decisions; no network, files, or runtime. |
| [`aster_acme_protocol`](crates/aster_acme_protocol/README.md) | Typed wire resources, requests, problems, JWS envelopes, and CA directories. |
| [`aster_acme`](crates/aster_acme/README.md) | Account and issuance orchestration, signing, transport, identifiers, and adapter contracts. |
| [`aster_acme_validation`](crates/aster_acme_validation/README.md) | Method-specific validation components; currently DNS TXT visibility checks. |
| [`aster_acme_cli_storage`](crates/aster_acme_cli_storage/README.md) | Private files, locks, versioned TOML, fixed key/CSR persistence, and artifact promotion. |
| [`aster_acme_cli`](crates/aster_acme_cli/README.md) | Arguments, interaction, reports, rendering, and process exit behavior. |

Each crate owns its package version. All dependency versions, sources, and features belong to the root `workspace.dependencies`; members inherit them with `workspace = true`.

## Development and validation

Python 3.11+ is required for repository policy checks. The release profile uses size optimization (`opt-level="z"`), LTO, one codegen unit, unwind panics, and stripped debug information while retaining function symbols.

```sh
python3 scripts/check-workspace-deps.py
python3 scripts/check-tls-backend.py
cargo fmt --all --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked
```

Local tests exercise a loopback CA, real signatures, durable storage, restart, cancellation, expiry, and failure boundaries. Routine checks do not contact public CAs. Real staging acceptance is documented separately from local evidence.

- [Website](https://acme.astercosm.com)
- [Architecture](docs/architecture.md)
- [RFC reference](docs/rfc-reference.md)
- [Account tests and staging records](docs/account-testing.md)
- [Issuance tests and limitations](docs/issuance-testing.md)
- [CLI argument contract](docs/cli-contract.md)
- [English changelog](CHANGELOG.md) / [中文更新日志](CHANGELOG.zh.md)

## License

Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Unless explicitly stated otherwise, contributions intentionally submitted for inclusion are dual-licensed under the same terms.

New issuance requires an explicit `-c/--challenge`; there is no default validation method. Recovery and renewal retain the saved implementation. `--yes` accepts all operation confirmations, without selecting inputs or bypassing validation; terms consent remains independent.
