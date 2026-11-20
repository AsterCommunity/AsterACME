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
  <a href="https://acme.docs.astercosm.com"><img alt="Documentation Site" src="https://img.shields.io/badge/docs-Astro_Starlight-7C3AED?style=for-the-badge&logo=astro&logoColor=white"></a>
  <a href="README.zh.md"><img alt="中文 README" src="https://img.shields.io/badge/README-%E4%B8%AD%E6%96%87-E11D48?style=for-the-badge"></a>
  <a href="developer-docs/architecture.md"><img alt="Architecture" src="https://img.shields.io/badge/architecture-overview-0F172A?style=for-the-badge"></a>
  <a href="developer-docs/rfc-reference.md"><img alt="RFC Reference" src="https://img.shields.io/badge/ACME-RFC%208555-059669?style=for-the-badge"></a>
  <a href="CHANGELOG.md"><img alt="Changelog" src="https://img.shields.io/badge/changelog-unreleased-7C3AED?style=for-the-badge"></a>
</p>

<p align="center">
  <a href="https://github.com/AsterCommunity/AsterACME/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/AsterCommunity/AsterACME/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="rust-toolchain.toml"><img alt="Rust 1.99+" src="https://img.shields.io/badge/Rust-1.99%2B-000000?style=flat-square&amp;logo=rust"></a>
  <a href="LICENSE-MIT"><img alt="MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square"></a>
</p>

AsterACME manages the certificate lifecycle with saved request state, fixed keys and CSRs, and explicit recovery after interruption. Use the CLI interactively or in scripts, or embed the Rust services with your own storage, signer, and validation adapters.

CLI source builds include Cloudflare, Alibaba Cloud DNS, Tencent Cloud DNSPod, and Huawei Cloud DNS by default. Huawei Cloud RRset updates cannot guarantee atomic isolation from external writers. Embedded applications select provider features explicitly. [DNS provider setup](developer-docs/dns-providers.md)

**Available now:** AsterACME `0.1.0-alpha.2` is published on crates.io. This is a pre-release; Rust APIs and local formats may still change. It includes native Cloudflare and ADPP backends behind a unified DNS solver. Live DNS/public-CA acceptance is separate.

## Capabilities

- Named CA accounts: registration, recovery, contacts, key rotation, and deactivation.
- Single-domain, multi-SAN, wildcard, and IP-address (RFC 8738) certificates; independent account and certificate key choices.
- CA certificate profiles (draft-ietf-acme-profiles): discover advertised profiles, set an account default, or select per issuance — Let's Encrypt IP identifiers require the `shortlived` profile.
- Saved issuance recovery, ARI refresh, foreground single/batch renewal, and unattended maintenance for supported validation methods.
- Multiple deployment targets per certificate, automatic deployment after renewal, and bounded reload commands with stdout/stderr output.
- Interactive input, structured JSON, offline inspection, and optional debug diagnostics.

| Validation | Implementation |
| --- | --- |
| DNS-01 | `dns_provider --provider NAME`: native DNS or ADPP automation; `manual_dns`: publish TXT records yourself; supports wildcards |
| DNS-PERSIST-01 (draft -02) | `dns_persist`: provision persistent TXT records manually, then reuse them for renewal; supports wildcards |
| HTTP-01 | `manual_http`, `webroot`, or temporary `standalone` listener on port 80; validates DNS and IP identifiers |
| TLS-ALPN-01 | Temporary `tls_alpn` listener on port 443; validates DNS and IP identifiers |

`dns_persist` requires a CA implementing the [same draft revision](developer-docs/rfc-reference.md#dns-persist-草案实现2026-11-14). Keep its TXT records for renewal. DNS provider writes and public-CA acceptance are separate capabilities.

## Quick start

Install the CLI from Homebrew:

```sh
brew install astercommunity/tap/aster-acme
```

Install the published `0.1.0-alpha.2` CLI from crates.io. `cargo-binstall` uses a matching prebuilt binary when available and otherwise falls back to a Cargo source build:

```sh
cargo binstall aster_acme_cli@0.1.0-alpha.2
```

Without `cargo-binstall`, install the same CLI through Cargo:

```sh
cargo install aster_acme_cli --version 0.1.0-alpha.2
```

Build from the checkout with **Rust 1.99+**:

```sh
git clone https://github.com/AsterCommunity/AsterACME.git
cd AsterACME
cargo install --path crates/aster_acme_cli --locked
```

To embed the library, run the shipped end-to-end example — CA discovery, account registration or reuse, an embedder-owned HTTP-01 webroot solver, resume, and artifacts — against Let's Encrypt **staging** with a temporary data directory:

```sh
cargo run -p aster_acme --example embedded_issuance -- --domain example.com --webroot /srv/www
```

The [example source](crates/aster_acme/examples/embedded_issuance.rs) is the embedding entry point: the `ChallengeSolver` implementation and the `AccountService`/`Workflow` wiring are yours, protocol state and recovery stay in the library.

Run the published container image instead of installing (multi-arch; `latest` tracks stable releases):

```sh
docker run -d --name aster-acme -v aster-acme-config:/data ghcr.io/astercommunity/aster-acme:latest
```

The container runs the maintenance daemon by default; one-off commands run as `docker exec aster-acme cert list`. See [containers](developer-docs/docker.md).

Register an account, review the CA terms, then request a certificate. The default CA is **Let's Encrypt production**.

```sh
aster-acme account register default --contact admin@example.com
aster-acme cert issue -n example-cert -a default -d example.com -c manual_dns
```

For unattended renewal, explicitly delegate future CA terms updates during registration:

```sh
aster-acme account register default --auto-accept-new-terms
```

This also accepts the currently advertised terms. The exact accepted URL remains in the account record; `account show` reports whether the future-update delegation is enabled. `--yes`, JSON mode, and implicit issuance account checks never enable it. A normal `account register` without the flag keeps an existing delegation so routine recovery cannot revoke unattended renewal trust.

Publish the requested TXT values and confirm. If interrupted, continue the saved request; renewal keeps the saved validation method:

```sh
aster-acme cert issue --resume example-cert
aster-acme cert show example-cert
aster-acme cert renew example-cert
aster-acme cert renew --all
```

`daemon run` stays in the foreground, checks immediately, then starts another maintenance cycle after the configured delay (default 60 seconds). It refreshes ARI suggestions, renews due certificates using `webroot`, `standalone`, `tls_alpn`, `dns_provider`, or already provisioned `dns_persist`, and retries configured deployments. Manual validation methods are skipped. `Ctrl-C` or Unix `SIGTERM` stops it after started work is retained. Use a service manager to start and restart the process; `daemon run-once` remains available for cron.

The resident daemon holds an exclusive lock for its data directory. Set `daemon_interval = 60` in `config.toml` or override it with `daemon run --interval 60`. Human logs use the same timestamped levels as issuance; `--json` streams one JSON object per line.

`renew` runs when due; add `--now` to renew early. Use resident `daemon run` or cron with `daemon run-once` for unattended maintenance using supported validation methods. For other validation methods and script confirmation rules, see the [CLI contract](developer-docs/cli-contract.md).

## Certificate-key revocation

```sh
aster-acme cert revoke example-cert --sign-with certificate-key --reason key-compromise --yes
```

Use the selected managed generation's certificate private key without the original ACME account or CSR. The default `--sign-with account` uses the issuing account. Both modes retain local and deployed files and do not rotate keys or reload services. See the [revocation contract](developer-docs/certificate-lifecycle.md#吊销).

## Deploy

Configure your service to read from an existing target directory, then bind it to the certificate:

```sh
aster-acme cert deploy add example-cert -n nginx \
  --target /etc/nginx/certs/example \
  --reload-cmd "systemctl reload nginx"
aster-acme cert deploy show example-cert nginx
```

Adding a binding deploys immediately; later successful renewals use it automatically. Files are fully prepared before individual replacements, and reload runs only after publication succeeds. Deployment uses regular files at stable directory paths. Manage bindings, file permissions, exact paths, and retries through [`cert deploy`](developer-docs/cli-contract.md#证书部署).

## Documentation

The user and operations documentation is published with Astro Starlight at [acme.docs.astercosm.com](https://acme.docs.astercosm.com/).

- [Quick start](https://acme.docs.astercosm.com/start/quick-start/)
- [Installation](https://acme.docs.astercosm.com/start/install/)
- [Choosing a validation method](https://acme.docs.astercosm.com/using/challenges/)
- [Accounts](https://acme.docs.astercosm.com/using/accounts/)
- [Issuance and recovery](https://acme.docs.astercosm.com/using/issuance/)
- [Renewal and ARI](https://acme.docs.astercosm.com/using/renewal/)
- [Deployment and reload](https://acme.docs.astercosm.com/using/deploy/)
- [DNS provider automation](https://acme.docs.astercosm.com/admin/dns-providers/)
- [Resident daemon and cron](https://acme.docs.astercosm.com/admin/daemon/)
- [Running the container](https://acme.docs.astercosm.com/admin/docker/)
- [CLI reference](https://acme.docs.astercosm.com/reference/cli/)
- [Developer guide](developer-docs/README.md): project contract, task routing, architecture, crate ownership, and tests
- [RFC reference](developer-docs/rfc-reference.md) and [changelog](CHANGELOG.md)

State is stored in the platform directory for `com.astercosm.acme`; use `--data-dir PATH` or `ASTER_ACME_DATA_DIR` to select another root (`--data-dir` takes precedence). `list` and `show` are offline by default. `--json` disables prompts and emits one structured result.

## Security

- Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/AsterCommunity/AsterACME/security/advisories/new) or `report@esaps.net` — see [SECURITY.md](SECURITY.md) for the full policy
- Published advisories: [github.com/AsterCommunity/AsterACME/security/advisories](https://github.com/AsterCommunity/AsterACME/security/advisories)

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), at your option. Contributions are dual-licensed under the same terms unless explicitly stated otherwise.

External DNS profile setup, sensitive custom values, CNAME delegation, propagation, and cleanup: [DNS providers](developer-docs/dns-providers.md).
