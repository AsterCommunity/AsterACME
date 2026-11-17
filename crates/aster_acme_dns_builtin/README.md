# aster_acme_dns_builtin

Provider-owned DNS state machines without network or filesystem access. The embedding crate defaults to **no vendor features**. The CLI selects its own default vendor set.

| Feature | Backend ID | Remote mutation model |
| --- | --- | --- |
| `cloudflare` | `com.astercosm.acme.dns.cloudflare` | Individual TXT objects with publication comments |

From a source checkout, select only the implementation needed by the embedding application:

```toml
[dependencies]
aster_acme_dns_builtin = { path = "../AsterACME/crates/aster_acme_dns_builtin", default-features = false, features = ["cloudflare"] }
```

`cloudflare::{CloudflareBackend, Cloudflare, CloudflareConfig}` are directly constructible. Use `ProviderRegistry::new` with an explicit backend set, or `ProviderRegistry::linked` for linked registration entries. `ProviderRegistry::provider` accepts a `ProviderHost` with an HTTP executor, optional credential-file reader, durable publication storage and an invocation budget. No CLI data directory or global runtime is required by these interfaces.

The `OperationFactory` creates an invocation-local state machine from `ProviderAction` and a saved `RecoveryState`. `advance` emits `ProviderEffect` values; the host runner executes HTTP, saves a checkpoint, reads a selected credential file or waits, then returns the corresponding event. Provider implementations own authentication, pagination, response parsing, reconciliation, ownership and cleanup. They never receive a raw HTTP client or write their own state files. Every mutation requires a freshly acknowledged durable checkpoint.

Cloudflare requires exactly one `api_token` or absolute `token_file`. An optional `zone_id` pins a zone; otherwise it discovers the longest matching zone for the final CNAME target and checkpoints that zone before mutation, retaining it for recovery and cleanup. The official API origin is fixed. `ForgeDnsHttp` executes HTTPS actions, while the embedding host supplies private credential-file reading when `token_file` is selected. API-token configuration works without filesystem access. Publication comments reconcile lost create responses; an uncertain create with no visible owned tag stops instead of replaying POST, while proved rejections are checkpointed before another attempt; pre-existing values are retained, another publication's tagged value is not borrowed, and cleanup verifies the exact record tuple and comment. Zone Read and DNS Edit permissions are required. Cloudflare read/check/delete is not an atomic compare-and-delete against concurrent external editors.

`rrset::ConditionalRrsetFactory` is a shared building block, not an additional supported vendor. Its `RrsetProtocol` adapter must implement a genuine atomic revision precondition, lossless metadata preservation and complete reads. The machine re-reads/re-merges on proved conflicts, preserves unrelated values, and refuses to infer creation ownership from existence after an uncertain write. A concrete vendor must additionally define ownership across same-value publications and external modifications; the building block supplies no cross-data-directory reference-count service.

See [backend ownership](../../docs/design/dns-backends.md), [CLI configuration](../../docs/dns-providers.md), and the local Cloudflare/RRset boundary tests. Source-tree support and mock acceptance do not imply that this new crate is already published or that live DNS/public-CA acceptance has run.
