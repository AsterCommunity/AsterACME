//! Pure renewal-information scheduling decisions; timestamps are Unix seconds.

/// Whether a caller should perform an ARI query, independently of certificate renewal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalAction {
    /// No advertised endpoint or no certificate identifier; retain the fallback.
    Unavailable,
    /// The saved query deadline has not arrived; do not redraw the renewal time.
    Wait,
    /// Initial query or a due refresh.
    Query,
}

/// Decide from persisted observations without performing I/O or consulting a clock.
#[must_use]
pub fn renewal_action(available: bool, next_check: Option<i64>, now: i64) -> RenewalAction {
    match (available, next_check) {
        (false, _) => RenewalAction::Unavailable,
        (true, Some(at)) if at > now => RenewalAction::Wait,
        (true, Some(_) | None) => RenewalAction::Query,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_deadline_and_unavailable_boundaries() {
        assert_eq!(renewal_action(false, None, 0), RenewalAction::Unavailable);
        assert_eq!(
            renewal_action(false, Some(-1), 0),
            RenewalAction::Unavailable
        );
        assert_eq!(renewal_action(true, None, 0), RenewalAction::Query);
        assert_eq!(renewal_action(true, Some(0), 0), RenewalAction::Query);
        assert_eq!(renewal_action(true, Some(-1), 0), RenewalAction::Query);
        assert_eq!(renewal_action(true, Some(1), 0), RenewalAction::Wait);
    }
}
