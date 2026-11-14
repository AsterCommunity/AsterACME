# aster_acme_dns_resolver

This crate adapts Hickory to the `aster_acme_dns::routing::DnsLookup` observation
port. It supports read-only CNAME routing and TXT propagation observations;
provider mutation, credentials, ACME acknowledgement and CLI presentation live
in other crates.

`SystemDns::new()` constructs a lazy adapter. Its first observation loads the
operator's system resolver configuration; `with_resolver` injects a configured
resolver for embedding or loopback tests. Initialization and query errors retain
their original source and safe stage description. The adapter does not filter
invalid nameservers, modify system configuration, vendor/patch Hickory, or add
public resolver fallback. An operator must fix an unavailable local DNS setup
before automatic DNS propagation can be observed.

CNAME lookup uses only a target at the queried owner. Confirmed NODATA/NXDOMAIN
is distinct from SERVFAIL or resolver errors. TXT character strings are joined
within one RR only; values at a shared owner remain separate. The system
adapter disables its own cache for publication observations; upstream recursive
positive and negative caches still exist.

The protocol-neutral DNS and ACME libraries do not depend on this crate. The
CLI uses it for external DNS independently of optional advisory prechecks.
Loopback tests exercise an actual UDP DNS response, CNAME owner matching and
TXT chunk/multi-value handling. This is not a DNSSEC validator or a replacement
for CA validation.
