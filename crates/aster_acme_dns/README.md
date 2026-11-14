# aster_acme_dns

`aster_acme_dns` owns protocol-neutral DNS publication data shared by external
and built-in DNS provider adapters. It is the contract between ACME challenge
orchestration and provider-specific DNS mutation.

## Ownership

- `ProviderContext` carries the selected profile ID, profile schema version,
  and opaque provider-specific JSON values. The complete custom map is
  sensitive and must be redacted by callers.
- `DnsRecord` carries the stable publication ID, original challenge owner,
  resolved CNAME chain, final TXT owner, logical TXT value, and requested TTL.
- `PublicationReceipt` identifies the exact provider record and records whether
  the value was created by this operation or existed before it.
- `ProviderError` carries a stable ADPP error code, safe message, retry hint,
  and whether a failed operation may have changed DNS.
- `DnsProvider` defines idempotent present and receipt-based cleanup operations.

## Lifecycle contract

`present` receives every record that must coexist at publication time. An
implementation returns an individual outcome for each publication ID so
successful receipts can be checkpointed even when another record fails. A
`preexisting` value is never owned for cleanup. `cleanup` receives the saved
receipt and exact record tuple; it must not remove an unrelated value or an
entire TXT RRset.

`ProviderExecution` carries the cancellation token and absolute monotonic
deadline for one operation. Provider implementations must bound all DNS API
requests by that scope. AsterACME remains responsible for the ACME challenge
state machine and durable receipt checkpointing.

## Boundaries

This crate does not own ACME order state, provider credentials, command-line
configuration, child processes, or DNS vendor API clients. CNAME routing and
propagation policy are AsterACME-owned DNS orchestration; the provider receives
the already-resolved publication name. Concrete resolver and CLI wiring live
in their own adapters.

## Routing, propagation, and embedding

`routing::DnsLookup` is an injected read-only observation port. `routing::resolve`
normalizes absolute names, follows at most eight CNAME links, rejects loops,
and checks the final owner against optional label-aware allowed-zone suffixes.
An omitted/empty list permits any valid owner; a nonempty list restricts the
final TXT target. A
publication plan is saved before an adapter may mutate DNS. The concrete
Hickory adapter lives in the separate `aster_acme_dns_resolver` crate, so using
this contract does not pull a DNS resolver into an embedded ACME client.

`propagation::PropagationPolicy` waits for every expected logical TXT value at
its original challenge owner. Default interval/wait are 5/120 seconds; caller
cancellation and deadline always apply. API success, local visibility, and CA
validation are three distinct observations. Cleanup uses the saved route and
receipt, never a freshly retargeted CNAME.

`ProviderFailure` distinguishes a provider's stable `ProviderErrorCode` from
host `HostErrorCode` (spawn/cancel/timeout/JSON/correlation/bounds failures).
Each failure retains whether side effects are proven absent or remain unknown.
`ProviderContext` Debug redacts custom values, but serialization intentionally
includes them for the trusted provider's stdin. Applications must not log that
serialization.
