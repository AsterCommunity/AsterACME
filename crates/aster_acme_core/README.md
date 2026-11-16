# aster_acme_core

Pure ACME state and policy decisions. This crate has no network, filesystem, runtime, DNS, cryptography, or CLI dependencies.

It owns account, order, authorization, challenge, CAA, and local workflow state transitions. Functions return the next action for an observation; callers perform every side effect.

```rust
use aster_acme_core::{machine::{order_action, OrderAction}, protocol::OrderStatus};

assert_eq!(
    order_action(&OrderStatus::Processing, Some(&[]), aster_acme_core::workflow::SubmissionState::NotSubmitted),
    Ok(OrderAction::PollOrder)
);
```

`SubmissionState` distinguishes a saved local intent from a remote CA result, preventing accidental replay of mutations. Unknown wire values remain representable. CAA evaluation is advisory and never performs DNS queries or authorizes a CA request.

```sh
cargo test -p aster_acme_core --locked
```

License: MIT OR Apache-2.0.
