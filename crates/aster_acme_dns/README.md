# aster_acme_dns

Shared DNS publication contracts, CNAME routing and bounded propagation policy.

`backend` defines backend IDs, configuration descriptors and validated immutable provider registries. Metadata and runtime factories come from the same backend object. Statically linked registration uses `linkme`; applications can instead inject explicit backend objects through `ProviderRegistry::new`.

`operation` defines provider actions, HTTP request/response values, versioned recovery facts and execution effects. The common runner holds host-owned publication sessions, persists identity/intention before mutations, enforces invocation budgets and preserves per-record partial outcomes. Embedders inject `HttpExecutor`, optional `CredentialReader`, and `PublicationStore`; the contract does not depend on CLI file layout or install process-global state.

Concrete implementations are provided by `aster_acme_dns_builtin` (one opt-in feature per vendor) and `aster_acme_dns_adpp` (external executable protocol). `aster_acme_dns_http` supplies the Forge host transport. Their operational and ownership boundaries are documented in [DNS backends](../../docs/design/dns-backends.md).
