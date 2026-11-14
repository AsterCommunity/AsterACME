# AsterACME RFCs

This directory is the design authority for proposed AsterACME architecture and
protocol contracts. RFCs define target behavior and acceptance criteria; they
do not claim that the current checkout implements that behavior.

## Status vocabulary

- **Proposed**: under maintainer review; implementation must not silently
  invent conflicting behavior.
- **Accepted**: approved as the implementation contract.
- **Implemented**: the accepted contract and its required verification are
  present in the current checkout.
- **Superseded**: replaced by another RFC, which must be linked from the old
  document.

Changing an accepted public protocol, security boundary, or durable identity
requires a new RFC or an explicit amendment with compatibility analysis.
Implementation details may be settled in code and tests when they preserve an
accepted contract.

## Index

| RFC | Status | Subject |
| --- | --- | --- |
| [0001](dns-provider-protocol/0001-asteracme-dns-provider-protocol.md) | Accepted | External DNS provider process protocol, publication receipts, cleanup, and CNAME delegation |

## Evidence

RFC 0001 is an accepted design contract based on the current AsterACME
challenge solver, issuance checkpoint, DNS-01 requirements in RFC 8555 §8.4,
and the maintainer's stated goal of supporting external and future built-in
DNS providers. Acceptance is not implementation or interoperability evidence.
