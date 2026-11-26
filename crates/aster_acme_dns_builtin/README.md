# aster_acme_dns_builtin

Provider-owned DNS state machines without network or filesystem access. The embedding crate defaults to **no vendor features**. The CLI selects its own default vendor set.

| Feature | Backend ID | Remote mutation model |
| --- | --- | --- |
| `cloudflare` | `com.astercosm.acme.dns.cloudflare` | Individual TXT objects with publication comments |
| `aliyun` | `com.astercosm.acme.dns.aliyun` | Individual TXT objects with durable create-response IDs |
| `tencent_cloud` | `com.astercosm.acme.dns.tencent-cloud` | Individual TXT objects with publication remarks |
| `google_cloud_dns` | `com.astercosm.acme.dns.google-cloud-dns` | Atomic changes with exact old-RRset deletion preconditions |
| `huawei_cloud` | `com.astercosm.acme.dns.huawei-cloud` | Best-effort whole RRset writes; no atomic guarantee |

Vendor features automatically enable their shared support: `_http`, `_signed-api` and `_individual-records` are internal capability features defined in `Cargo.toml`. Hosts select vendor features only. Shared HTTP methods live in `aster_acme_dns::operation::HttpMethod`, and `HttpRequest.method` uses that enum without vendor-specific variant gates.

From a source checkout, select only the implementation needed by the embedding application:

```toml
[dependencies]
aster_acme_dns_builtin = { path = "../AsterACME/crates/aster_acme_dns_builtin", default-features = false, features = ["cloudflare"] }
```

`cloudflare::{CloudflareBackend, Cloudflare, CloudflareConfig}` are directly constructible. Use `ProviderRegistry::new` with an explicit backend set, or `ProviderRegistry::linked` for linked registration entries. `ProviderRegistry::provider` accepts a `ProviderHost` with an HTTP executor, optional credential-file reader, durable publication storage and an invocation budget. No CLI data directory or global runtime is required by these interfaces.

The `OperationFactory` creates an invocation-local state machine from `ProviderAction` and a saved `RecoveryState`. `advance` emits `ProviderEffect` values; the host runner executes HTTP, saves a checkpoint, reads a selected credential file or waits, then returns the corresponding event. Provider implementations own authentication, pagination, response parsing, reconciliation, ownership and cleanup. They never receive a raw HTTP client or write their own state files. Every mutation requires a freshly acknowledged durable checkpoint.

Cloudflare requires exactly one `api_token` or absolute `token_file`. An optional `zone_id` pins a zone; otherwise it discovers the longest matching zone for the final CNAME target and checkpoints that zone before mutation, retaining it for recovery and cleanup. The official API origin is fixed. `ForgeDnsHttp` executes HTTPS actions, while the embedding host supplies private credential-file reading when `token_file` is selected. API-token configuration works without filesystem access. Publication comments reconcile lost create responses; an uncertain create with no visible owned tag stops instead of replaying POST, while proved rejections are checkpointed before another attempt; pre-existing values are retained, another publication's tagged value is not borrowed, and cleanup verifies the exact record tuple and comment. Zone Read and DNS Edit permissions are required. Cloudflare read/check/delete is not an atomic compare-and-delete against concurrent external editors.

`provider::vendors::aliyun::AliyunBackend` and `provider::vendors::tencent_cloud::TencentCloudBackend` use the same registry and host. Both discover the zone of the final target and save its identity. Alibaba Cloud DNS needs a saved create-response ID and refuses to borrow an existing value. DNSPod uses its publication remark to recover an uncertain create. Successful receipts include the effective TTL returned by the API.

`rrset::ConditionalRrsetFactory` is a shared building block, not an additional supported vendor. Its `RrsetProtocol` adapter must implement a genuine atomic revision precondition, lossless metadata preservation and complete reads. The machine re-reads/re-merges on proved conflicts, preserves unrelated values, and refuses to infer creation ownership from existence after an uncertain write. A concrete vendor must additionally define ownership across same-value publications and external modifications; the building block supplies no cross-data-directory reference-count service.

See [backend ownership](../../developer-docs/design/dns-backends.md), [CLI configuration](../../developer-docs/dns-providers.md), and the local Cloudflare/RRset boundary tests. Source-tree support and mock acceptance do not imply that this new crate is already published or that live DNS/public-CA acceptance has run.

Huawei Cloud requires `access_key_id` and `access_key_secret`; `project_id` is optional and is discovered through IAM for the selected region when omitted. `region` defaults to `cn-north-4`. The `HuaweiCloudBackend` descriptor reports `best_effort_rrsets`. It discovers and saves the final target zone, signs HWS requests and checkpoints publication/value markers. Cleanup reads the current RRset, removes only the owned value, and retains other values and descriptions. **Concurrent changes between read and PUT/DELETE may be overwritten or deleted.** Local leases cannot isolate cloud console or external clients. Coordinate all writers and prefer a dedicated ACME owner. The conditional RRset primitive retains its stronger contract.

Google Cloud DNS uses a nested `service_account` JSON object with a PKCS#8 RSA key. OAuth tokens are cached only in the factory instance. The final owner selects a public managed zone; changes preserve current unrelated values, TTL and metadata. Identical pre-existing values are rejected. A saved change ID permits read-only reconciliation; a lost submission response without that ID remains unknown and is never replayed or adopted from TXT presence. This backend does not use `ConditionalRrsetFactory`, because exact-value preconditions do not supply a non-reusable revision. Coordinate external writers to avoid indistinguishable delete/recreate (ABA) changes. See the provider guide for configuration and acceptance limits.
