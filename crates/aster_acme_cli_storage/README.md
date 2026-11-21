# aster_acme_cli_storage

Filesystem adapters for the AsterACME CLI. The crate implements account, certificate, deployment, provider-profile, query, lease, and revocation session boundaries without owning CLI rendering or ACME policy.

The data root contains versioned TOML configuration, account metadata and keys, certificate definitions and generations, provider profiles, deployment checkpoints, and shared process locks. Unix and Windows implementations validate managed paths, permissions, links, reparse points, and ownership before reads or writes.

Writes use bounded reads, explicit leases, intent checkpoints, atomic file replacement, and restart recovery. Unknown schema versions, corruption, unsafe paths, and missing required key material fail closed. Existing user files are preserved. Private keys and provider custom values are never included in reports or logs.

Provider profiles live at `providers/<name>.toml`. The store validates executable paths, zone suffixes, provider schema, custom-value limits, and concurrent updates. Interactive editing belongs to the CLI; this crate only persists the validated profile.

Queries are typed snapshots. Eligibility is rechecked while holding the relevant lease before a write, so stale CLI reads cannot overwrite newer account, certificate, deployment, or retry state.

```sh
cargo test -p aster_acme_cli_storage --locked
```

License: MIT OR Apache-2.0.

Exact-file deployment targets can publish a PKCS#12 bundle alongside PEM artifacts. Storage resolves environment/file password references or a transient interactive override inside the blocking preparation worker; it persists no password values. Bundle bytes use the existing publication pipeline and private-key permissions. Directory targets keep the standard four PEM files. See the [deployment contract](../../developer-docs/cli-contract.md#证书部署).
