# aster_acme_dns_adpp

External-process adapter for AsterACME DNS Provider Protocol v1 (`com.astercosm.acme.adpp`).

The adapter sends one bounded JSON request to a configured executable and validates one correlated JSON response. It checks protocol version, request/action identity, exact per-record results, ownership, record IDs, retry hints, and structured errors. `publication_id` is the idempotency identity; `request_id` only correlates one invocation.

Processes run directly with explicit argv and a cleared environment. Stdin, credentials, and child stderr are never logged. Partial successes are returned so callers can checkpoint receipts before handling remaining failures. The adapter does not resolve zones, follow CNAMEs, retry implicitly, or decide propagation policy.

Use `aster_forge_process` for product-neutral lifecycle ownership and `aster_acme_dns` for provider-neutral contracts. Normative protocol: [ADPP RFC](../../developer-docs/rfc/dns-provider-protocol/0001-asteracme-dns-provider-protocol.md).

```sh
cargo test -p aster_acme_dns_adpp --locked
```

License: MIT OR Apache-2.0.
