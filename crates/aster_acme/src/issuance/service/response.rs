//! CA response parsing, retry scheduling and completed snapshots.
use crate::issuance::{IssueError, IssueOutcome, IssueRecord};
use crate::{challenge::PublicationLifetime, identifier::Identifier, transport::AcmeResponse};
use aster_acme_core::protocol::OrderStatus;
use aster_acme_protocol::{order::OrderObject, url::AcmeUrl};
use std::time::Duration;

pub(super) fn parse_order(
    response: &AcmeResponse,
    record: &IssueRecord,
) -> Result<OrderObject, IssueError> {
    let order: OrderObject = serde_json::from_slice(&response.body)
        .map_err(|_| IssueError::InvalidInput("malformed order"))?;
    let expected = record
        .identifiers
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut actual = std::collections::BTreeSet::new();
    for wire in &order.identifiers {
        let identifier = Identifier::try_from(wire.clone())?;
        if !actual.insert(identifier) {
            return Err(IssueError::InvalidInput("duplicate order identifiers"));
        }
    }
    // The order identity is fixed at request time. When the request carries
    // an explicit profile, the CA must echo it (draft-ietf-acme-profiles §4):
    // a missing field means the CA ignored the selection and would issue
    // under its default — rejected instead of silently downgraded. A profile
    // on a request that asked for none is informational.
    if record.profile.is_some() && order.profile.as_ref() != record.profile.as_ref() {
        return Err(IssueError::InvalidInput(
            "CA order omitted or selected a different certificate profile than requested",
        ));
    }
    if expected != actual
        || order.authorizations.len() > 100
        || order
            .authorizations
            .iter()
            .map(AcmeUrl::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != order.authorizations.len()
        || matches!(order.status, OrderStatus::Pending | OrderStatus::Valid)
            && order.expires.is_none()
    {
        return Err(IssueError::InvalidInput(
            "CA order identifiers, authorization URLs or expiry are invalid",
        ));
    }
    if let Some(previous) = &record.order
        && (previous.finalize != order.finalize || previous.authorizations != order.authorizations)
    {
        return Err(IssueError::InvalidInput(
            "order's immutable resource URLs changed",
        ));
    }
    // RFC 9773 section 5 requires the exact submitted predecessor on every order
    // observation. Use durable request identity even if directory capabilities change.
    if let Some(expected) = &record.submitted_replaces
        && order.replaces.as_ref() != Some(expected)
    {
        return Err(IssueError::InvalidInput(
            "CA order omitted or changed the renewal replaces identifier",
        ));
    }
    Ok(order)
}

pub(super) fn schedule(record: &mut IssueRecord, response: &AcmeResponse, fallback: Duration) {
    let retry = crate::transport::retry_after(&response.headers);
    schedule_retry(record, retry.as_ref(), fallback);
}

pub(super) fn schedule_retry(
    record: &mut IssueRecord,
    retry: Option<&crate::transport::RetryAfter>,
    fallback: Duration,
) {
    let now = time::OffsetDateTime::now_utc();
    tracing::debug!(retry_after = ?retry, local_interval_ms = fallback.as_millis(), "Scheduling next CA poll");
    let source = if retry.is_some() {
        crate::issuance::PollWaitSource::RetryAfter
    } else {
        crate::issuance::PollWaitSource::LocalInterval
    };
    let delay = retry
        .map_or(fallback, |hint| match hint {
            crate::transport::RetryAfter::Delay(delay) => *delay,
            crate::transport::RetryAfter::At(at) => at
                .duration_since(std::time::SystemTime::now())
                .unwrap_or(Duration::ZERO),
        })
        .max(Duration::from_millis(100));
    let next = now
        .checked_add(time::Duration::try_from(delay).unwrap_or(time::Duration::MAX))
        .unwrap_or_else(|| time::Date::MAX.midnight().assume_utc());
    if record.next_poll_at.is_none_or(|previous| next >= previous) {
        record.next_poll_at = Some(next);
        record.poll_wait_source = Some(source);
    }
}

pub(super) fn completed(record: IssueRecord) -> IssueOutcome {
    let cleanup = record
        .authorizations
        .iter()
        .filter(|auth| auth.cleanup_pending)
        .filter_map(|auth| auth.validation_requirement.clone())
        .filter(|requirement| {
            requirement.kind().publication_lifetime() == PublicationLifetime::Temporary
        })
        .collect();
    IssueOutcome::Completed {
        record: Box::new(record),
        cleanup,
    }
}
