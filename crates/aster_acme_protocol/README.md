# aster_acme_protocol

Typed ACME wire models, independent of HTTP, cryptography, storage, and runtime code.

The crate owns exact resource URLs, directory metadata, account and order wire objects, flattened JWS structures, and RFC 8555 problem documents. URLs are validated and preserved exactly; callers never reconstruct resource paths from a host name. Unknown problem and extension values are retained without inventing protocol behavior.

The crate depends on `aster_acme_core` for shared state enums. Signing, nonce management, retries, persistence, and request orchestration belong to `aster_acme` and its adapters.

```sh
cargo test -p aster_acme_protocol --locked
```

License: MIT OR Apache-2.0.
