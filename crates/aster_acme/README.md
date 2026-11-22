# aster_acme

Embeddable ACME orchestration for account management, certificate issuance, recovery, renewal, revocation, challenge publication, and deployment policy.

The crate owns protocol progression and durable operation contracts while callers inject `AcmeClient`, storage sessions, signers, and `ChallengeSolver` implementations. It does not print terminal UI, manage CLI files, run background tasks, or ship vendor DNS clients.

Key modules:

- `account`, `crypto`, and `transport` implement account identity, JWS signing, nonce handling, HTTPS directory discovery, and bounded requests.
- `issuance` persists fixed keys, CSRs, challenge requirements, CA observations, recovery evidence, and cleanup checkpoints.
- `challenge` and `solver` define method capabilities, typed validation material, publication lifecycles, and shutdown boundaries.
- `renewal`, `revocation`, and `maintenance` define ARI plans, retry admission, explicit signing identity, and host-supplied maintenance execution.
- `precheck` is optional and advisory; it never replaces CA validation.

`AccountService::update_contacts` returns `ContactUpdateError` to distinguish no submission, explicit CA rejection, an unconfirmed remote result, and CA acceptance followed by failed local persistence. Callers must retain that evidence and must not automatically replay an unconfirmed update.

DNS provider records use the protocol-neutral contracts in `aster_acme_dns`. The CLI supplies the ADPP executable adapter; embedded applications can provide another solver.

```rust
use aster_acme::{challenge::{ChallengeKind, ChallengePolicy}, identifier::DnsIdentifier};

let method = ChallengePolicy::Require(ChallengeKind::Dns01).select(
    &DnsIdentifier::new("example.com")?,
    &[],
    &[ChallengeKind::Dns01],
)?;
assert_eq!(method, ChallengeKind::Dns01);
# Ok::<(), Box<dyn std::error::Error>>(())
```

```sh
cargo test -p aster_acme --locked
```

License: MIT OR Apache-2.0.
