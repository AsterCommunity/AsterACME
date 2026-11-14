# RFC 0001: AsterACME DNS Provider Protocol

- Status: Accepted
- Date: 2026-11-14
- Amended: 2026-11-14 — zone restrictions are optional and default to unrestricted
- Owners: AsterACME maintainers
- Depends on: RFC 8555 §8.4

## Summary

This RFC defines the AsterACME DNS Provider Protocol (ADPP), a machine-readable
process contract between AsterACME and an external DNS provider executable. It
covers DNS-01 publication, recovery, and ownership-aware cleanup. The request
identifies the selected provider profile without sending an ACME account ID.

This is an accepted target contract. It does not claim that ADPP or automatic
DNS publication is implemented in the current checkout. The terms MUST, MUST
NOT, SHOULD, SHOULD NOT, and MAY are normative for future implementations.

## Motivation

DNS-01 automation needs provider-specific APIs, credentials, zone discovery,
record mutation, and cleanup behavior. Embedding every provider in AsterACME
would couple the ACME client to vendor APIs and slow down support for less
common DNS services. An external process lets operators implement providers in
any language and choose whether credential material lives in AsterACME's
protected provider profile or in a provider-owned file, Keychain, or service.

The process boundary still needs a durable contract. A timeout can occur after
the provider changes DNS but before AsterACME receives a response. Multiple
orders can publish values at the same owner. Cleanup must remove only values
created by the completed operation. ADPP therefore specifies stable
idempotency IDs, per-record receipts, and explicit ownership semantics rather
than treating a successful child exit as sufficient evidence.

## Goals and boundaries

ADPP lets an operator connect any DNS service through a program they control,
without adding that service's API client to AsterACME. The executable may be
written in any language. AsterACME owns ACME challenge selection and lifecycle;
the executable owns DNS API communication and DNS-specific record operations.
Credential material may be supplied through `provider_custom` or loaded by the
executable from its own credential source.

The protocol is a one-shot process interface, not a resident daemon, network
service, shell language, or MCP server. Each invocation receives one JSON
request on stdin and returns one JSON response on stdout. AsterACME starts the
configured executable directly and MUST NOT interpolate a shell command.

ADPP does not define ACME wire behavior, DNS provider authentication, DNS zone
discovery, DNSSEC validation, or a guarantee that recursive resolvers can see a
new record. A successful `present` response means the provider accepted and
reconciled the requested publication. The CA remains authoritative for
challenge validation.

## Definitions

- **Challenge owner**: the `_acme-challenge` DNS name derived for the ACME
  identifier, before any CNAME delegation.
- **Publication name**: the TXT owner where the record is actually written
  after AsterACME resolves an allowed CNAME chain.
- **Provider instance**: a named external provider configuration, including
  its executable and provider-side credential/configuration selection.
- **Publication ID**: a stable, opaque identifier for one logical record
  publication within one issuance operation. It is saved before invoking the
  provider and reused after interruption.
- **Provider record ID**: an opaque identifier returned by the provider for
  the exact record it created or observed as pre-existing. It is saved for later cleanup.
- **Provider profile**: a named, versioned AsterACME configuration containing
  the executable, argv, allowed DNS zones, and provider-specific custom values.

`provider_instance_id` is the stable profile name selected for an issuance.
The protocol intentionally omits ACME account identity: `publication_id` is
sufficient for idempotency and cleanup, and the provider has no need to
correlate unrelated operations by ACME account.

## Decisions

### Invocation and framing

The executable path is configured explicitly. AsterACME MUST invoke it without
a shell, provide UTF-8 JSON on stdin, and read exactly one UTF-8 JSON response
from stdout. The response MUST end with a newline. Human diagnostics MAY be
written to stderr; stdout is reserved for the protocol response.

The caller MUST enforce an invocation deadline, bounded request and response
sizes, and bounded stderr capture. On timeout or cancellation it MUST terminate
the child and its owned process group/job before releasing the issuance lease.
ADPP execution MUST use the shared `aster_acme_process` crate, extracted from
the deploy reload process manager. That crate owns process-tree termination,
bounded pipe handling, cancellation, timeout, and child reaping; reload and
ADPP keep separate business result policies. The executable MUST run with a
cleared inherited environment. Provider configuration is supplied only through
the request context. The caller MUST treat invalid JSON, an unsupported
protocol version, unexpected output, or a non-zero exit status as failure.
Output is untrusted input and MUST be validated before it affects ACME state or
cleanup.

Version 1 bounds one request and response to 1 MiB of serialized JSON each,
one request to 100 records, stderr capture to 64 KiB, and provider record IDs
to 1024 UTF-8 bytes without control characters. A request contains 1–100
records with distinct, nonempty opaque ASCII publication IDs (at most 128 bytes;
letters, digits, hyphen and underscore). Request IDs use the same character and
length limits. TXT values in v1 are nonempty DNS-01 strings of at most 255 UTF-8
bytes; optional TTL is 1..=2147483647 seconds. The default per-invocation timeout is 30 seconds, with a
maximum of 300 seconds and the issuance operation deadline taking precedence.
CNAME resolution is limited to 8 links.

The request envelope is:

```json
{
  "protocol": "com.astercosm.acme.adpp",
  "version": 1,
  "request_id": "opaque-request-id",
  "action": "present",
  "context": {
    "provider_instance_id": "dns-prod",
    "provider_profile_version": 1,
    "provider_custom": {
      "credential_profile": "production",
      "zone_id": "zone-123"
    }
  },
  "records": [
    {
      "publication_id": "stable-publication-id",
      "challenge_name": "_acme-challenge.example.com.",
      "cname_chain": [
        "_acme-challenge.example.com.",
        "validation.example.net."
      ],
      "record": {
        "type": "TXT",
        "name": "validation.example.net.",
        "value": "base64url-digest",
        "ttl_seconds": 120
      }
    }
  ]
}
```

`protocol`, `version`, `request_id`, `action`, and `context` are required.
`protocol` MUST equal `com.astercosm.acme.adpp`. Version 1 uses one JSON
document per process invocation, not newline-delimited JSON streams. Unknown
major versions MUST be rejected. Additive fields may be ignored only when
their semantics are explicitly optional.

`request_id` identifies this invocation for diagnostics and correlation; it is
not an idempotency key. Providers MUST use each record's `publication_id` for
idempotency.

### Provider profiles and configuration

The CLI MUST expose an `aster-acme provider` command family to manage named
profiles. The operations are `add`, `list`, `show`, `update`, `remove`, and `cleanup`.
`cleanup` retries terminal pending publication without ACME account keys or CA
requests; it never cleans a nonterminal/unknown CA outcome. A profile contains an absolute executable path, an argv array, a
`provider_profile_version`, an optional list of allowed DNS zone suffixes, and
the `provider_custom` key-value object. Issuance selects a profile with
`--provider <NAME>` and saves its stable `provider_instance_id` in the
certificate definition. Provider selection is valid only with the external
DNS challenge implementation.

The intended command shape is:

```text
aster-acme provider add dns-prod --exec /absolute/path/dns-provider --allow-zone example.net
aster-acme provider list
aster-acme provider show dns-prod
aster-acme provider update dns-prod --exec /absolute/path/dns-provider-v2
aster-acme provider remove dns-prod
aster-acme cert issue -d example.net -c dns_external --provider dns-prod
```

`provider_custom` values are edited through the profile TOML entry or a
protected interactive editor; secret values MUST NOT be accepted as command
line arguments.

`provider_profile_version` is the profile schema version, distinct from ADPP's
wire `version`. Version 1 defines an argv array, allowed DNS zone suffixes, and
a JSON `provider_custom` object. Custom values may change without changing this
schema version. Current profile files are limited to 64 KiB, with at most
32 KiB of serialized custom JSON. TOML custom values must be JSON-compatible
strings, booleans, finite numbers, arrays or tables; null and native TOML
datetime values are not part of this profile schema. Default propagation wait
is 120 seconds with a 5-second interval; profile limits are 1–3600 and 1–60
seconds respectively, both within the operation budget. A saved issuance records the profile ID and schema version;
later runs use the current values for that profile. Profile updates therefore
affect resume, renewal, and pending cleanup invocations. Removing a profile
referenced by a retained certificate or pending cleanup MUST be rejected.

Each profile is stored in its own `<data-dir>/providers/<name>.toml` file.
Because the entire custom object is sensitive, AsterACME MUST create and retain
the profile file with private owner-only access on Unix. On Windows it MUST use
the existing file guards and inherited ACL policy; it does not promise to
install a separate ACL. Operators protect the data directory's inherited ACL. Profile writes MUST use
the existing atomic state-file boundary. Provider profile operations MUST NOT
echo custom values in errors or reports.

`provider_custom` is an arbitrary provider-specific JSON object. Every value
in it MUST be treated as sensitive, even when it appears harmless. It MAY
contain credentials if the operator chooses to store them in AsterACME's
provider profile; it MAY instead contain non-secret selectors or paths when
the provider executable loads credentials from its own files, Keychain, or
another credential store. AsterACME MUST NOT interpret these values. This
means AsterACME persists any secret the operator explicitly puts in
`provider_custom`; it does not claim otherwise.

The complete `provider_custom` object is sent only in the JSON request's
`context`. It MUST NOT be copied into an issuance journal, logs, errors,
terminal output, or JSON command reports. `provider show` and other profile
rendering MUST redact the entire object. The request is sensitive process
input; the shared process manager MUST use pipes and MUST NOT include stdin in
diagnostics or output capture. The child receives no inherited environment.
The configured executable remains trusted code with the AsterACME process
user's filesystem permissions; this protocol is not an OS sandbox.

### Record model

Each `records` entry has this shape:

```json
{
  "publication_id": "stable-publication-id",
  "challenge_name": "_acme-challenge.example.com.",
  "cname_chain": [
    "_acme-challenge.example.com.",
    "validation.example.net."
  ],
  "record": {
    "type": "TXT",
    "name": "validation.example.net.",
    "value": "base64url-digest",
    "ttl_seconds": 120
  }
}
```

Names are absolute DNS names in presentation form with a trailing dot. `value`
is the logical TXT character string without presentation quotes. The provider
MUST publish it as one TXT RDATA value and MUST NOT split it into separate TXT
records. `ttl_seconds` is an optional requested value, not a promise that the
DNS service supports that exact TTL; the provider MAY apply its documented
minimum or default.

The original `challenge_name` is retained for audit and error reporting.
`cname_chain` records the delegation AsterACME resolved. `record.name` is the
final publication name. The provider MUST NOT change the CNAME chain or write
the TXT value at a different name without returning an explicit failure.

An invocation MAY contain multiple records. The provider MUST return an
individual result for every `publication_id`; a single aggregate success flag
is insufficient for partial-success recovery.

### Actions

#### `present`

`present` reconciles each requested TXT value at its exact publication name.
It MUST be idempotent for the same `publication_id` and record tuple. Repeating
the request after a timeout MUST return the same provider record identity or
reconcile the same record, not create an unbounded series of duplicates.

The provider MUST preserve unrelated TXT values at the owner. It MUST NOT
replace or clear an entire TXT RRset to publish one value. If the exact value
already existed before this publication, the provider MUST report that it did
not create the value and MUST NOT later delete that pre-existing value.

The response is:

```json
{
  "protocol": "com.astercosm.acme.adpp",
  "version": 1,
  "request_id": "opaque-request-id",
  "action": "present",
  "results": [
    {
      "publication_id": "stable-publication-id",
      "status": "present",
      "record_id": "provider-record-123",
      "ownership": "created"
    }
  ],
  "error": null
}
```

`status` is `present` only when the requested value is reconciled. `record_id`
is an opaque, bounded string that identifies the exact provider object needed
for cleanup. `ownership` is `created` or `preexisting`. A provider MUST return a
stable receipt for both cases; cleanup of a `preexisting` value is a successful
no-op.

AsterACME MUST durably save each successful result before acknowledging the
corresponding ACME challenge. If saving a receipt fails, it MUST NOT acknowledge
that challenge. The caller MUST save the exact route before invocation and save each receipt
before propagation waiting. The provider MUST persist its own publication
intent and ownership facts (or use equivalent provider-side idempotency tags)
so a lost response can be reconciled. An opaque ID alone does not establish
ownership. Reuse of an ID with a different record tuple MUST fail as
`record_conflict`, never retarget the mutation.

#### `cleanup`

`cleanup` receives the saved publication and provider record IDs. It MUST remove
only the value owned by that publication. It MUST NOT delete a pre-existing
value, another publication's value, or the whole TXT RRset. Repeating cleanup
for a value already absent MUST succeed. If ownership cannot be established,
the provider MUST fail closed and leave the record in place.

```json
{
  "protocol": "com.astercosm.acme.adpp",
  "version": 1,
  "request_id": "opaque-request-id",
  "action": "cleanup",
  "context": {
    "provider_instance_id": "dns-prod",
    "provider_profile_version": 1,
    "provider_custom": {
      "credential_profile": "production",
      "zone_id": "zone-123"
    }
  },
  "records": [
    {
      "publication_id": "stable-publication-id",
      "record_id": "provider-record-123",
      "ownership": "created",
      "challenge_name": "_acme-challenge.example.com.",
      "cname_chain": [
        "_acme-challenge.example.com.",
        "validation.example.net."
      ],
      "record": {
        "type": "TXT",
        "name": "validation.example.net.",
        "value": "base64url-digest",
        "ttl_seconds": 120
      }
    }
  ]
}
```

The cleanup response returns one result per publication ID with status
`removed`, `retained`, or `already_absent`. A failed cleanup remains durable
pending work in AsterACME and MUST be safe to retry. Cancellation and uncertain
ACME outcomes MUST retain DNS records; a successful or terminally invalid ACME
order permits cleanup.

```json
{
  "protocol": "com.astercosm.acme.adpp",
  "version": 1,
  "request_id": "opaque-request-id",
  "action": "cleanup",
  "results": [
    {
      "publication_id": "stable-publication-id",
      "status": "removed"
    }
  ],
  "error": null
}
```

#### Recovery

Recovery uses `present` with the same `publication_id` and saved record tuple
when the provider side effect may have happened but no durable receipt was
observed. Once a receipt is durable, cleanup uses that receipt. AsterACME MUST
NOT invent a new publication ID for a retry of the same saved authorization.

For concurrent operations requesting the same name/value, the provider MUST
coordinate durable claims, create independently owned records when supported,
or reject with `record_conflict`. An active record owned by another ADPP
publication is not an independently pre-existing user record. Cleanup MUST NOT
remove a shared value while another publication still needs it. Provider record
IDs MUST bind the DNS account/zone namespace as well as the exact object;
changing credentials cannot authorize deletion of a colliding ID in another
account.

### CNAME delegation

RFC 8555 §8.4 defines the DNS-01 TXT value and challenge owner; it does not
define this provider protocol or an AsterACME CNAME policy. ADPP therefore
separates challenge derivation from DNS routing:

1. AsterACME derives the challenge owner and expected TXT value from ACME
   challenge material.
2. AsterACME resolves a bounded CNAME chain and applies the operator's allowed
   delegation policy.
3. AsterACME sends the original owner, resolved chain, and final publication
   name to the provider.
4. The provider discovers the authoritative zone and writes the value at the
   supplied final name.

AsterACME MUST detect loops, enforce a finite chain limit, and reject a target
that is not allowed by the configured delegation policy. It MUST NOT create or
rewrite CNAME records as part of challenge publication. A provider MUST NOT
independently follow a different CNAME chain. NS-based delegation and automatic
zone discovery remain provider responsibilities or future extensions; they do
not change the challenge owner.

Zone restrictions are an optional host-side enhancement. An omitted or empty
`allowed_zones` list MUST allow any syntactically valid final publication name.
When the list is nonempty, AsterACME MUST require that name to equal or be below
one of its zone suffixes, matched at DNS-label boundaries. `--allow-zone` opts
into this restriction; `provider update NAME --clear-zones` restores the
unrestricted default. A restriction never grants additional DNS API rights.
The zone list is current profile configuration, not credential material or an
ADPP wire field. There is one interpretation for all profiles: an omitted or
empty list is unrestricted, and a nonempty list enables the optional filter.
No legacy format reader, migration, or old-policy compatibility path is defined.

Propagation waiting is an independent AsterACME DNS policy, not an ADPP action
or provider responsibility. A successful `present` only confirms provider
reconciliation. AsterACME waits for every expected TXT value at the original challenge owner
according to its configured propagation policy before acknowledging the ACME challenge; the CA
still makes the final validation decision.

### Errors and partial results

Every response contains `protocol`, `version`, `request_id`, `action`,
`results`, and `error`. `error` is null when the request was processed. A
request-level error means no record action began. Partial execution is
represented by one result per record; one failure MUST NOT erase successful
results for other records.

The error object is:

```json
{
  "code": "rate_limited",
  "message": "DNS API rate limit reached",
  "side_effect": "none",
  "retry_after_seconds": 30,
  "provider_code": "optional-provider-specific-code"
}
```

`message` MUST be short, sanitized, and free of credentials, secret values,
and raw provider response bodies. `side_effect` is `none` or `unknown`. A
provider MUST report `unknown` when it cannot prove that a failed action had no
effect. A missing response or child process failure is always unknown for
records without a saved success result. AsterACME MUST retry uncertain
publication with the same `publication_id`; it MUST NOT generate a replacement
ID. `retry_after_seconds` is valid only for `rate_limited` and is bounded to
1..=86400. Its retry lower bound MUST be persisted before the invocation ends;
resume MUST NOT call the provider before that time. AsterACME owns retry timing and behavior; provider hints do not
authorize replay of a different publication.

A per-record error appears in that record's result:

```json
{
  "publication_id": "stable-publication-id",
  "status": "error",
  "error": {
    "code": "provider_timeout",
    "message": "DNS API request timed out",
    "side_effect": "unknown"
  }
}
```

A request-level error uses the top-level `error` and an empty `results` array.
It MUST have `side_effect: "none"`, because request-level rejection means no
record operation began. A response MUST NOT contain both a non-null top-level
error and record results.

The stable ADPP v1 provider error codes are:

| Code | Meaning | Required caller behavior |
| --- | --- | --- |
| `invalid_request` | Request schema or field value is invalid | Do not retry unchanged input |
| `unsupported_version` | Provider does not support the ADPP version | Do not retry unchanged input |
| `unsupported_action` | Action is unknown to this provider | Do not retry unchanged input |
| `provider_not_configured` | `provider_instance_id` is not configured | Operator must configure the provider |
| `credentials_unavailable` | Provider could not load its own credentials | Do not acknowledge; operator intervention is required |
| `authentication_failed` | DNS service rejected the credential | Do not retry unchanged credentials |
| `authorization_denied` | Credential lacks the required DNS permission | Do not retry unchanged permissions |
| `zone_not_found` | Provider cannot find an authoritative zone for the publication name | Do not retry unchanged routing/profile |
| `zone_ambiguous` | More than one provider zone matches and selection is not deterministic | Require explicit provider configuration |
| `record_conflict` | The requested name/value conflicts with existing DNS data | Do not overwrite or retry unchanged input |
| `rate_limited` | DNS service throttled the operation | Respect `retry_after_seconds`; reconcile with the same ID |
| `provider_unavailable` | DNS service or provider dependency is temporarily unavailable | Retry only with the same ID and side-effect reconciliation |
| `provider_timeout` | Provider operation timed out | Treat side effect as unknown unless `side_effect` is `none` |
| `record_not_owned` | Cleanup could not prove ownership of the exact record | Fail closed and retain the record |
| `internal_error` | Provider failed without a more specific stable code | Follow `side_effect`; do not invent a new ID |

Errors produced by AsterACME's process adapter are not ADPP provider codes.
They use host-owned diagnostics such as `process_spawn_failed`,
`process_cancelled`, `process_timeout`, `process_exit_nonzero`,
`response_invalid_json`, `response_invalid`, and `response_too_large`.
These errors MUST retain uncertainty for any action that may have reached the
child. The host MUST NOT translate stderr text into a provider error code.

| Host code | Meaning |
| --- | --- |
| `request_invalid` | Caller-supplied request, executable path or invocation limit is invalid; child not started |
| `process_spawn_failed` | Executable could not be started; no DNS side effect |
| `process_cancelled` | Invocation cancelled; no side effect only when not started |
| `process_timeout` | Invocation deadline elapsed; unknown side effect after startup |
| `process_wait_failed` | Host could not observe the immediate child exit |
| `process_input_failed` | Complete request could not be written to the input pipe |
| `process_exit_nonzero` | Child reported an unsuccessful exit, regardless of stdout |
| `response_invalid_json` | Response is not one syntactically valid UTF-8 JSON document |
| `response_invalid` | JSON schema, mandatory fields, correlation, result set, or field semantics are invalid |
| `response_too_large` | Response exceeded the byte limit |


Missing results, duplicate publication IDs, unknown status values, malformed
record IDs, mismatched request IDs/actions, and contradictory top-level and
per-record errors are `response_invalid`. AsterACME MUST preserve already
saved successful receipts and MUST NOT acknowledge records whose publication
is unconfirmed.

### Security considerations

- The configured executable is trusted code with the privileges of the
  AsterACME process. Operators MUST review it and its update source.
- AsterACME MUST NOT pass ACME signing keys to the provider. Provider
  credentials are either loaded by the provider executable or supplied in the
  sensitive `provider_custom` profile object.
- The profile's `provider_custom` object and every ADPP request containing it
  are sensitive. The host MUST redact the complete object and MUST NOT persist
  it in operation journals or reports.
- Provider output is untrusted. It MUST be size-bounded, parsed as structured
  JSON, validated against the request, and escaped before human display.
- stderr and error messages MUST be bounded and MUST NOT be copied into durable
  issuance records without sanitization.
- Provider IDs and publication IDs are opaque identifiers, not authorization
  tokens. Providers MUST verify exact record ownership before deletion.
- CNAME routing can redirect writes to a different DNS zone. AsterACME MUST
  enforce syntactic, loop and depth checks in every mode. Nonempty profile
  zone restrictions MUST be checked before invoking the provider; omitted or
  empty restrictions intentionally allow all valid targets.
- Child processes MUST be bounded by deadline and terminated as an owned
  process group/job on cancellation or timeout through `aster_acme_process`.
- No command may delete a record based only on a matching TXT owner. Cleanup
  requires the saved publication receipt and exact-value ownership.

### Compatibility and versioning

The protocol identifier is `com.astercosm.acme.adpp`. Version 1 is a major
protocol version.
Incompatible request or response changes require a new major version. Additive
optional fields may be introduced only when older implementations can safely
ignore them. Providers MUST reject unsupported major versions rather than
guessing semantics.

The host application version and ADPP version are independent. A provider MAY
return an optional `provider_name` and `provider_version` for diagnostics, but
those values do not alter protocol behavior.

## Alternatives and consequences

| Approach | Assessment |
| --- | --- |
| External executable per DNS provider | Chosen for the first provider integration; operators can add services without changing AsterACME, while the process and durable receipt contracts remain explicit |
| Built-in provider implementations | Remain possible behind a shared DNS provider interface; each provider still needs credential sourcing, record ownership, CNAME routing, and cleanup behavior |
| One generic shell command with positional strings | Rejected: quoting, secrets, partial results, and recovery semantics would vary by shell and provider |
| Resident provider daemon or network service | Deferred: adds service lifecycle, endpoint authentication, and availability concerns without being required for DNS publication |

The crate boundaries are `aster_acme_dns` for DNS names, routing,
provider contracts, and propagation policy; `aster_acme_dns_adpp` for the
external protocol adapter; `aster_acme_dns_resolver` for concrete system DNS
observations; and `aster_acme_process` for shared child-process
management. Built-in provider implementations can live in separate crates and
implement the same DNS provider contract. The CLI owns profile editing and
selects the implementation; the ACME service continues to own challenge
lifecycle and durable publication checkpoints.

The external process is trusted code with the permissions of the AsterACME
process. Operators gain implementation flexibility but must install, configure,
and update the executable. AsterACME stores provider profile data, including
custom values the operator chooses to enter, but does not interpret provider
credentials. The executable owns provider-specific authentication behavior.

## Acceptance gates

Before ADPP is advertised as implemented, the implementation must demonstrate:

1. Exact request/response schema validation for
   `com.astercosm.acme.adpp`, unsupported-version rejection, bounded
   stdin/stdout/stderr, non-zero exit handling, and no shell parsing.
2. Cancellation and deadline handling that terminates the child process tree
   before releasing the issuance lease.
3. Idempotent `present` after a lost response, with a stable `publication_id`
   and durable receipt saved before ACME challenge acknowledgement.
4. Batched partial success recovery without losing successful per-record
   receipts or acknowledging an unconfirmed publication.
5. TXT multi-value preservation, pre-existing-value retention, concurrent
   publication isolation, and cleanup limited to the exact owned record.
6. Cleanup failure persistence and safe retry after process restart; uncertain
   ACME outcomes retain published records.
7. CNAME loop, chain-depth, target-policy, and conflicting-record tests, plus
   a real DNS staging test that confirms publication, CA validation, and
   cleanup independently.
8. Secret redaction and confirmation that no ACME private key enters the
   request, issuance journal, stdout, stderr, or diagnostics. A provider secret
   explicitly stored in `provider_custom` is sent only on stdin and is never
   written to an issuance journal, output, or diagnostic.
9. The deploy reload executor and ADPP adapter use `aster_acme_process` for
   process-tree cleanup, bounded I/O, cancellation, timeout, and reaping; their
   business-level uncertainty and output policies remain separate.

These gates are acceptance criteria, not evidence that the current checkout
passes them.

The accepted v1 decisions are: profile selection uses `aster-acme provider`
and `provider_instance_id`; publication permits all valid domains by default
and optional nonempty allowed-zone lists restrict the final target; propagation waiting is AsterACME policy; pre-existing exact TXT
values are never claimed for cleanup; request and process bounds are fixed
above; provider custom values are sensitive and are passed only in
`context.provider_custom`; provider credentials may either be included there
by explicit operator choice or loaded by the external executable. No host
environment is inherited or forwarded.

## References

- [RFC 8555 §8.4: DNS Challenge](https://www.rfc-editor.org/rfc/rfc8555#section-8.4)
- [RFC 1034 §3.6.2: Aliases and canonical names](https://www.rfc-editor.org/rfc/rfc1034#section-3.6.2)

Acceptance of this RFC is not implementation or interoperability evidence.

## Implementation status

The workspace contains the shared DNS/provider and process crates, ADPP
executable adapter, per-file profile store, CLI profile management, CNAME
routing, propagation policy, and receipt checkpoints. Local tests and loopback
DNS/CA coverage are recorded separately in the [issuance test record](../../issuance-testing.md).
The RFC remains Accepted until the required real-DNS/staging interoperability
acceptance is independently demonstrated. Acceptance is not vendor certification.
