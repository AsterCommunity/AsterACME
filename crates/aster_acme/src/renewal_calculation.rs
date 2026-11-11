//! Local renewal-time calculation independent of ARI transport and persistence.
//!
//! The fallback first derives an intended renewal point from the certificate's
//! actual validity interval, then samples the preceding day. This keeps client
//! renewals distributed while guaranteeing that the selected time precedes the
//! intended point and never precedes the time this local plan is created.

use crate::issuance::IssueError;
use aws_lc_rs::rand;
use time::{Duration, OffsetDateTime};

const SHORT_CERTIFICATE: Duration = Duration::days(10);
const RANDOM_WINDOW: Duration = Duration::days(1);

/// Calculate a randomized fallback time from the leaf certificate validity.
pub(crate) fn fallback_renew_at(
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    issued_at: OffsetDateTime,
) -> Result<OffsetDateTime, IssueError> {
    if issued_at >= not_after {
        return Err(IssueError::InvalidInput(
            "certificate was already expired when its renewal plan was created",
        ));
    }
    let target = renewal_target(not_before, not_after)?;
    if issued_at >= target {
        return Ok(issued_at);
    }
    let window_start = target
        .checked_sub(RANDOM_WINDOW)
        .unwrap_or(not_before)
        .max(not_before)
        .max(issued_at);
    match sample_exclusive(window_start, target)? {
        Some(renew_at) => Ok(renew_at),
        None => Ok(issued_at),
    }
}

fn renewal_target(
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<OffsetDateTime, IssueError> {
    let validity = not_after - not_before;
    if validity <= Duration::ZERO {
        return Err(IssueError::InvalidInput(
            "invalid certificate renewal validity",
        ));
    }
    let elapsed = if validity < SHORT_CERTIFICATE {
        validity.whole_nanoseconds() / 2
    } else {
        validity.whole_nanoseconds() * 2 / 3
    };
    not_before
        .checked_add(Duration::nanoseconds_i128(elapsed))
        .ok_or(IssueError::InvalidInput(
            "certificate renewal time is out of range",
        ))
}

/// Uniformly sample nanosecond precision in `(start, end)` without modulo bias.
fn sample_exclusive(
    start: OffsetDateTime,
    end: OffsetDateTime,
) -> Result<Option<OffsetDateTime>, IssueError> {
    let width = (end - start).whole_nanoseconds();
    if width <= 1 {
        return Ok(None);
    }
    let width = u128::try_from(width - 1)
        .map_err(|_| IssueError::InvalidInput("invalid renewal window"))?;
    let threshold = width.wrapping_neg() % width;
    loop {
        let mut bytes = [0_u8; 16];
        rand::fill(&mut bytes)
            .map_err(|_| IssueError::InvalidInput("renewal randomness unavailable"))?;
        let value = u128::from_be_bytes(bytes);
        if value >= threshold {
            let offset = i128::try_from(value % width)
                .map_err(|_| IssueError::InvalidInput("invalid renewal window"))?;
            return end
                .checked_sub(Duration::nanoseconds_i128(offset + 1))
                .map(Some)
                .ok_or(IssueError::InvalidInput("renewal time is out of range"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(seconds).unwrap()
    }

    #[test]
    fn uses_two_thirds_for_ten_days_or_longer_and_randomizes_the_previous_day() {
        let before = at(0);
        let after = before + Duration::days(90);
        let target = before + Duration::days(60);
        for _ in 0..128 {
            let chosen = fallback_renew_at(before, after, before).unwrap();
            assert!(chosen > target - RANDOM_WINDOW);
            assert!(chosen < target);
            assert!(chosen > before);
            assert!(chosen < after);
        }
    }

    #[test]
    fn uses_half_for_certificates_shorter_than_ten_days() {
        for days in [1_i64, 2, 9] {
            let before = at(1_000);
            let after = before + Duration::days(days);
            let target = before + (after - before) / 2;
            let window_start: OffsetDateTime = target - RANDOM_WINDOW;
            for _ in 0..32 {
                let chosen = fallback_renew_at(before, after, before).unwrap();
                assert!(chosen > window_start.max(before));
                assert!(chosen < target);
                assert!(chosen > before);
                assert!(chosen < after);
            }
        }
    }

    #[test]
    fn exactly_ten_days_uses_two_thirds_and_clamps_window_to_issue_time() {
        let before = at(0);
        let after = before + SHORT_CERTIFICATE;
        let target = before + SHORT_CERTIFICATE * 2 / 3;
        let chosen = fallback_renew_at(before, after, before).unwrap();
        assert!(chosen > before);
        assert!(chosen < target);
    }

    #[test]
    fn random_window_starts_after_plan_creation_even_when_not_before_is_backdated() {
        let before = at(0);
        let after = before + Duration::days(90);
        let issued_at = at(59 * 86400 + 12 * 3600);
        let target = at(60 * 86400);
        for _ in 0..64 {
            let chosen = fallback_renew_at(before, after, issued_at).unwrap();
            assert!(chosen > issued_at);
            assert!(chosen < target);
            assert!(chosen < after);
        }
    }

    #[test]
    fn past_target_schedules_immediately_but_never_after_expiration() {
        let before = at(0);
        let after = before + Duration::days(2);
        let issued_at = at(36 * 3600);
        assert_eq!(
            fallback_renew_at(before, after, issued_at).unwrap(),
            issued_at
        );
        assert!(issued_at < after);
        assert!(fallback_renew_at(before, after, after).is_err());
        assert!(fallback_renew_at(before, after, after + Duration::nanoseconds(1)).is_err());
    }

    #[test]
    fn threshold_switches_at_exactly_ten_days() {
        let before = at(0);
        let threshold = SHORT_CERTIFICATE.whole_nanoseconds();
        let below = before + Duration::nanoseconds_i128(threshold - 1);
        let exact = before + SHORT_CERTIFICATE;
        let above = exact + Duration::nanoseconds(1);
        assert_eq!(
            renewal_target(before, below).unwrap(),
            before + (below - before) / 2
        );
        assert_eq!(
            renewal_target(before, exact).unwrap(),
            before + SHORT_CERTIFICATE * 2 / 3
        );
        assert_eq!(
            renewal_target(before, above).unwrap(),
            before + (above - before) * 2 / 3
        );
    }

    #[test]
    fn rejects_invalid_and_too_short_intervals_without_returning_expired_times() {
        let issued_at = at(0);
        assert!(fallback_renew_at(at(1), at(1), issued_at).is_err());
        assert!(fallback_renew_at(at(2), at(1), issued_at).is_err());
        assert_eq!(
            fallback_renew_at(issued_at, issued_at + Duration::nanoseconds(1), issued_at).unwrap(),
            issued_at
        );
        assert_eq!(
            fallback_renew_at(issued_at, issued_at + Duration::nanoseconds(2), issued_at).unwrap(),
            issued_at
        );
        let short_expiry = issued_at + Duration::days(9);
        let plan_created = issued_at + Duration::days(5);
        assert_eq!(
            fallback_renew_at(issued_at, short_expiry, plan_created).unwrap(),
            plan_created
        );
    }
}
