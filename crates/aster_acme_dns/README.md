# aster_acme_dns

Protocol-neutral DNS publication contracts shared by external and built-in provider adapters.

`DnsRecord` carries the stable publication ID, challenge owner, frozen CNAME route, final TXT owner, value, and TTL. `PublicationReceipt` records exact provider ownership. `DnsProvider` exposes idempotent `present` and receipt-based `cleanup` operations with per-record results and structured side-effect classification.

`routing` follows bounded CNAME chains and applies label-aware zone restrictions. `propagation::PropagationPolicy` waits five seconds, performs one bounded advisory TXT observation, and adds a ten-second grace delay when local visibility is unknown before CA validation. Local visibility never replaces CA validation. Cancellation and operation deadlines apply to every wait and query.

Credentials, provider profiles, ACME order state, child processes, and vendor clients belong to other crates. The injected `DnsLookup` port is read-only.

```sh
cargo test -p aster_acme_dns --locked
```

License: MIT OR Apache-2.0.
