<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/readme/asteracme-on-dark.svg" />
    <img src="assets/readme/asteracme-on-light.svg" alt="AsterACME" width="320" />
  </picture>
</p>

<p align="center">
  An embeddable Rust ACME client and CLI for account management, DNS and HTTP validation, and recoverable certificate issuance.
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

AsterACME manages the certificate lifecycle with saved request state, fixed keys and CSRs, and explicit recovery after interruption. Use the CLI interactively or in scripts, or embed the Rust services with your own storage, signer, and validation adapters.

**Pre-release:** ACME packages are not published yet; local formats and Rust APIs may change. Automated DNS providers are not implemented.

## Capabilities

- Named CA accounts: registration, recovery, contacts, key rotation, and deactivation.
- Single-domain, multi-SAN, and wildcard certificates; independent account and certificate key choices.
- Saved issuance recovery, ARI refresh, foreground single/batch renewal, and unattended maintenance for supported validation methods.
- Multiple deployment targets per certificate, automatic deployment after renewal, and bounded reload commands with stdout/stderr output.
- Interactive input, structured JSON, offline inspection, and optional debug diagnostics.

| Validation | Implementation |
| --- | --- |
| DNS-01 | `manual_dns`: publish TXT records yourself; supports wildcards |
| HTTP-01 | `manual_http`, `webroot`, or temporary `standalone` listener on port 80 |
| TLS-ALPN-01 | Temporary `tls_alpn` listener on port 443 |

## Quick start

Build from the checkout with **Rust 1.99+**:

```sh
git clone https://github.com/AsterCommunity/AsterACME.git
cd AsterACME
cargo install --path crates/aster_acme_cli --locked
```

Register an account, review the CA terms, then request a certificate. The default CA is **Let's Encrypt production**.

```sh
aster-acme account register default --contact admin@example.com
aster-acme cert issue -n example-cert -a default -d example.com -c manual_dns
```

Publish the requested TXT values and confirm. If interrupted, continue the saved request; renewal keeps the saved validation method:

```sh
aster-acme cert issue --resume example-cert
aster-acme cert show example-cert
aster-acme cert renew example-cert
aster-acme cert renew --all
```

`daemon run` stays in the foreground, checks immediately, then starts another maintenance cycle after the configured delay (default 60 seconds). It refreshes ARI suggestions, renews due certificates using `webroot`, `standalone`, or `tls_alpn`, and retries configured deployments. Manual validation methods are skipped. `Ctrl-C` or Unix `SIGTERM` stops it after started work is retained. Use a service manager to start and restart the process; `daemon run-once` remains available for cron.

The resident daemon holds an exclusive lock for its data directory. Set `daemon_interval = 60` in `config.toml` or override it with `daemon run --interval 60`. Human logs use the same timestamped levels as issuance; `--json` streams one JSON object per line.

`renew` runs when due; add `--now` to renew early. Use resident `daemon run` or cron with `daemon run-once` for unattended maintenance using supported validation methods. For other validation methods and script confirmation rules, see the [CLI contract](docs/cli-contract.md).

## Deploy

Configure your service to read from an existing target directory, then bind it to the certificate:

```sh
aster-acme cert deploy add example-cert -n nginx \
  --target /etc/nginx/certs/example \
  --reload-cmd "systemctl reload nginx"
aster-acme cert deploy show example-cert nginx
```

Adding a binding deploys immediately; later successful renewals use it automatically. Files are fully prepared before individual replacements, and reload runs only after publication succeeds. Deployment uses regular files at stable directory paths. Manage bindings, file permissions, exact paths, and retries through [`cert deploy`](docs/cli-contract.md#证书部署).

## Documentation

- [CLI and configuration](docs/cli-contract.md): commands, prompts, JSON, timeouts, and `--debug`.
- [Certificate lifecycle](docs/certificate-lifecycle.md): renewal, ARI, revocation, and removal.
- [Developer guide](docs/README.md): project contract, task routing, architecture, crate ownership, and tests.
- [RFC reference](docs/rfc-reference.md) and [changelog](CHANGELOG.md).

State is stored in the platform directory for `com.astercosm.acme`; use `--data-dir PATH` or `ASTER_ACME_DATA_DIR` to select another root (`--data-dir` takes precedence). `list` and `show` are offline by default. `--json` disables prompts and emits one structured result.

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), at your option. Contributions are dual-licensed under the same terms unless explicitly stated otherwise.
