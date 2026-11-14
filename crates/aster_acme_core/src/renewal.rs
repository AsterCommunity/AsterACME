//! Pure renewal-information scheduling decisions; clocks and I/O remain caller-owned.

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
/// Both times must use the same ordered representation; callers retain their precision.
#[must_use]
pub fn renewal_action<T: Ord + Copy>(
    available: bool,
    next_check: Option<T>,
    now: T,
) -> RenewalAction {
    match (available, next_check) {
        (false, _) => RenewalAction::Unavailable,
        (true, Some(at)) if at > now => RenewalAction::Wait,
        (true, Some(_) | None) => RenewalAction::Query,
    }
}

/// Decision for one explicit renewal invocation; I/O and clocks stay outside core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalDecision {
    NotDue,
    Start,
    Resume,
    RevocationUncertain,
}

/// Delay after a failed issuance attempt, capped at one retry per day.
/// `failure_count` is one-based: the first failure schedules the first retry.
#[must_use]
pub const fn renewal_retry_delay_seconds(failure_count: u32) -> i64 {
    match failure_count {
        0 | 1 => 60,
        2 => 10 * 60,
        3 => 100 * 60,
        _ => 24 * 60 * 60,
    }
}

/// Resume a durable renewal before considering a new one; --now never bypasses an
/// uncertain revocation. Confirmed revoked certificates require an explicit early request.
#[must_use]
pub fn renewal_decision(
    pending: bool,
    revocation: crate::revocation::RevocationState,
    renew_at: i64,
    now: i64,
    immediate: bool,
) -> RenewalDecision {
    use crate::revocation::RevocationState;
    match revocation {
        RevocationState::Pending => RenewalDecision::RevocationUncertain,
        RevocationState::NotRequested | RevocationState::Confirmed if pending => {
            RenewalDecision::Resume
        }
        RevocationState::Confirmed if !immediate => RenewalDecision::NotDue,
        RevocationState::NotRequested | RevocationState::Confirmed
            if immediate || now >= renew_at =>
        {
            RenewalDecision::Start
        }
        RevocationState::NotRequested | RevocationState::Confirmed => RenewalDecision::NotDue,
    }
}

#[cfg(test)]
mod tests {
    use crate::renewal::*;

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
    #[test]
    fn renewal_boundaries_keep_now_dns_and_uncertain_revocation_independent() {
        use crate::revocation::RevocationState;
        assert_eq!(
            renewal_decision(false, RevocationState::NotRequested, 100, 99, false),
            RenewalDecision::NotDue
        );
        assert_eq!(
            renewal_decision(false, RevocationState::NotRequested, 100, 100, false),
            RenewalDecision::Start
        );
        assert_eq!(
            renewal_decision(false, RevocationState::NotRequested, 100, 99, true),
            RenewalDecision::Start
        );
        assert_eq!(
            renewal_decision(true, RevocationState::NotRequested, 100, 99, false),
            RenewalDecision::Resume
        );
        for pending in [false, true] {
            for now in [false, true] {
                assert_eq!(
                    renewal_decision(pending, RevocationState::Pending, 0, 100, now),
                    RenewalDecision::RevocationUncertain
                );
            }
        }
        assert_eq!(
            renewal_decision(false, RevocationState::Confirmed, 0, 100, false),
            RenewalDecision::NotDue
        );
        assert_eq!(
            renewal_decision(false, RevocationState::Confirmed, 0, 100, true),
            RenewalDecision::Start
        );
    }

    #[test]
    fn renewal_retry_schedule_grows_then_caps_at_one_day() {
        assert_eq!(renewal_retry_delay_seconds(0), 60);
        assert_eq!(renewal_retry_delay_seconds(1), 60);
        assert_eq!(renewal_retry_delay_seconds(2), 600);
        assert_eq!(renewal_retry_delay_seconds(3), 6000);
        assert_eq!(renewal_retry_delay_seconds(4), 86400);
        assert_eq!(renewal_retry_delay_seconds(u32::MAX), 86400);
    }
}
