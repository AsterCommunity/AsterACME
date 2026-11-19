//! Invocation-local budgets for read-only reconciliation; never authorizes a write.
use std::time::{Duration, Instant};

pub(in crate::provider) struct ReadRetry {
    remaining: u8,
    interval: Duration,
}

impl ReadRetry {
    pub(in crate::provider) const fn new(remaining: u8, interval: Duration) -> Self {
        Self {
            remaining,
            interval,
        }
    }

    pub(in crate::provider) fn next(&mut self) -> Option<Instant> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(Instant::now() + self.interval)
    }
}
