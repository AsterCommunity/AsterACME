# aster_acme_cli

The `aster-acme` command-line application for AsterACME. It manages named CA accounts, certificate issuance and recovery, renewal, revocation, deployment targets, daemon maintenance, DNS provider profiles, and structured JSON output.

## Install

```sh
cargo binstall aster_acme_cli@0.1.0-alpha.2
cargo install aster_acme_cli --version 0.1.0-alpha.2
```

Build from a checkout with Rust 1.99 or newer:

```sh
cargo install --path crates/aster_acme_cli --locked
```

## Commands

```text
aster-acme account register|recover|show|list|default|update|rotate-key|remove [--deactivate]
aster-acme cert issue|list|show|renew|revoke|remove|deploy
aster-acme daemon run-once|run
aster-acme provider backends|add|list|show|update|cleanup|remove
aster-acme version
```

All commands support the shared `--data-dir` and `--json` boundaries. JSON and non-TTY invocations never prompt. Human output uses UTC timestamps, shared status colors, escaped untrusted fields, and one final result. `NO_COLOR` disables ANSI styling.

## Certificate validation

`manual_dns`, `dns_persist`, `dns_provider`, `manual_http`, `webroot`, `standalone`, and `tls_alpn` are supported validation implementations. `dns_provider` uses a named profile with either a native backend such as Cloudflare or an external ADPP executable, and persists frozen routes and per-record receipts. After publication, the CLI waits five seconds for one advisory local TXT check; unknown visibility adds a ten-second grace delay before CA validation. The CA remains authoritative.

Provider profiles are stored under `providers/<name>.toml`. `list` uses the shared compact account/certificate table style; `show` displays the redacted profile and TOML path. Terminal users can select profiles for issuance, show, cleanup, and removal. `update` edits a draft with back navigation, explicit save/cancel, and a full snapshot check against concurrent changes.

## Recovery and safety

The CLI never silently creates a replacement key or order after an uncertain remote result. It preserves operation journals, fixed CSR/key material, provider receipts, cleanup-pending state, deployment checkpoints, and retry deadlines. Cleanup failures do not turn an already issued certificate into a failed issuance.

```sh
cargo test -p aster_acme_cli --locked
```

License: MIT OR Apache-2.0.
