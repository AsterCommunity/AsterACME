# aster_acme_dns_adpp

`aster_acme_dns_adpp` implements the external-process adapter for AsterACME DNS
Provider Protocol v1. Its protocol identifier is
`com.astercosm.acme.adpp`; the crate name deliberately marks the ADPP-specific
implementation while `aster_acme_dns` remains protocol-neutral.

## Request flow

The adapter serializes one request document to child stdin and reads one JSON
response from stdout. Requests contain the provider profile ID/version and the
`provider_custom` object, plus batched present or cleanup records. `publication_id`
is the retry identity; `request_id` is only for invocation correlation. The
adapter invokes the configured executable directly with argv and clears the
inherited process environment.

Before returning a result, the adapter checks the protocol ID/version,
request/action correlation, exact per-record result set, result status,
provider record ID bounds, and structured error fields. It preserves partial
per-record failures so the caller can save successful receipts before
continuing or reporting failure. Child stderr is bounded and never rendered;
request stdin is never captured or logged.

## Safety and ownership

The adapter does not resolve credentials, interpret provider-specific custom
keys, discover zones, follow CNAMEs, or decide propagation policy. Provider
credentials may be present in `provider_custom`; callers must therefore treat
the request as secret data and must not copy it to an issuance journal or
diagnostic output. Process cancellation and process-tree cleanup are delegated
to `aster_acme_process`.

The workspace integrates these wire types and executable adapter with profile
management and issuance checkpoints. Local automated tests exercise the
protocol and failure boundaries; real DNS/CA staging acceptance remains
separate from this local evidence.

## Wire and adapter API

- `wire::{Request, Response, RequestRecord, RecordResult, WireError}` are the
  versioned JSON types. Protocol version is separate from profile schema version.
- `AdppProvider::new(Executable { program, args, timeout })` creates an adapter;
  its `DnsProvider::present/cleanup` operations accept an injected
  `ProviderExecution` cancellation token and monotonic deadline.
- One call carries 1–100 unique publication IDs; one request/response is at most
  1 MiB. A successful present requires a nonempty record ID of at most 1024 bytes
  plus `created`/`preexisting` ownership. Correlation ID, action, result set,
  stable codes, retry hints, and success/error field combinations are validated.
- Provider errors use an exit-zero JSON response. Nonzero exit status, invalid
  UTF-8/JSON, mismatched correlation, missing response fields, and truncated
  output are host failures with uncertain side effects after process startup.
- The adapter does not retry implicitly. Its caller checkpoints successful
  per-record receipts and rate-limit lower bounds, then chooses when to retry
  the same publication IDs. Messages are bounded and direct custom-value echoes
  are redacted; stderr and input are never rendered.

A provider implementation must durably reconcile the same ID after a crash or
lost response, preserve unrelated TXT values, distinguish genuine pre-existing
records, and prove exact ownership before deletion. If an API has no native
idempotency key, the provider needs durable intent/ownership state or equivalent
record tags. A script that blindly creates a fresh record on every call does
not implement this protocol.

Executable configuration and examples: [DNS providers](../../docs/dns-providers.md).
Normative protocol: [RFC 0001](../../docs/rfc/dns-provider-protocol/0001-asteracme-dns-provider-protocol.md).
The self-hosted process integration fixture in `tests/process.rs` demonstrates
actual stdin/stdout invocation without a shell or public DNS credentials.
