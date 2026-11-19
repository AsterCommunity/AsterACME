# aster_acme_validation

Optional DNS observations and advisory precheck adapters for AsterACME. This crate does not own ACME method selection, DNS provider mutation, CNAME routing, cleanup, terminal prompts, or certificate storage.

Features are intentionally explicit:

- `dns01` provides injectable TXT visibility for DNS-01 solver integrations.
- `precheck-caa` provides CAA policy observations and system-resolver diagnostics.
- `precheck-dns` provides TXT observations through the shared precheck runner.

The default feature set is empty and does not pull Tokio, tokio-util, Hickory or the ACME client into an embedded application. Callers invoke the runner explicitly, provide an execution deadline and cancellation token, and decide how to present advisory reports. A failed or timed-out local check never authorizes or rejects a CA request by itself.

The crate uses `aster_acme` for solver and precheck contracts. The CLI owns DNS publication data, HTTP/webroot/listener implementations, and provider profile selection.

```sh
cargo check -p aster_acme_validation --locked
cargo test -p aster_acme_validation --locked
```

License: MIT OR Apache-2.0.
