//! Shared scheduling, operator override and retained-child evidence boundaries.
use crate::issuance::{
    IssueError, IssueRecord, RenewalPredecessor, RenewalRetryState, RequestFailure,
};
use crate::renewal::{
    RenewalPlan, RenewalSource,
    admission::{self, RenewalAdmission},
};
use aster_acme_core::revocation::RevocationState;
use time::{Duration, OffsetDateTime};

fn record() -> IssueRecord {
    let mut record: IssueRecord = serde_json::from_value(serde_json::json!({
        "operation_id":"a".repeat(43), "name":"example", "created_at":"2026-01-01T00:00:00Z",
        "account_name":"default", "account_id":"account", "directory":"https://ca.example/directory",
        "account_url":"https://ca.example/account/1", "account_thumbprint":"thumbprint",
        "key_algorithm":"ecdsa-p256", "identifiers":["example.com"], "solver_id":"manual_dns",
        "solver_config":{}, "challenge":"dns-01", "phase":"completed", "new_order_intent_saved":false,
        "authorizations":[], "finalize_submitted":"not_submitted"
    })).unwrap();
    record.is_in_use = true;
    record.renewal = Some(RenewalPlan {
        certificate_id: None,
        not_before: OffsetDateTime::UNIX_EPOCH,
        not_after: OffsetDateTime::UNIX_EPOCH + Duration::days(90),
        renew_at: OffsetDateTime::UNIX_EPOCH + Duration::nanoseconds(1),
        source: RenewalSource::Fallback,
        suggested_window: None,
        explanation_url: None,
        last_checked_at: None,
        next_check_at: None,
        last_query_failed: false,
    });
    record
}

#[test]
fn exact_due_time_and_only_local_backoff_are_overridable() {
    let mut current = record();
    let now = current.renewal.as_ref().unwrap().renew_at;
    assert_eq!(
        admission::request(&current, &[], false, now - Duration::nanoseconds(1)).unwrap(),
        RenewalAdmission::NotDue
    );
    assert_eq!(
        admission::request(&current, &[], false, now).unwrap(),
        RenewalAdmission::Start
    );
    assert_eq!(
        admission::request(&current, &[], true, now - Duration::nanoseconds(1)).unwrap(),
        RenewalAdmission::Start
    );
    current.renewal_retry = Some(RenewalRetryState {
        failures: 1,
        retry_at: Some(now + Duration::hours(1)),
        ca_retry_at: None,
        blocked_reason: None,
    });
    assert_eq!(
        admission::request(&current, &[], false, now).unwrap(),
        RenewalAdmission::NotDue
    );
    assert!(admission::preparation_failure(&current, false, now).is_none());
    assert_eq!(
        admission::request(&current, &[], true, now).unwrap(),
        RenewalAdmission::Start
    );
    assert!(admission::preparation_failure(&current, true, now).is_some());
    current.renewal_retry.as_mut().unwrap().ca_retry_at = Some(now + Duration::nanoseconds(1));
    for immediate in [false, true] {
        assert!(matches!(
            admission::request(&current, &[], immediate, now),
            Err(IssueError::InvalidInput(
                "CA Retry-After has not elapsed; --now cannot bypass it"
            ))
        ));
        assert!(admission::preparation_failure(&current, immediate, now).is_none());
    }
    current.renewal_retry.as_mut().unwrap().ca_retry_at = Some(now);
    assert!(admission::request(&current, &[], true, now).is_ok());
    current.renewal_retry.as_mut().unwrap().blocked_reason = Some("unknown outcome".into());
    assert!(matches!(
        admission::request(&current, &[], true, now),
        Err(IssueError::Publication(_))
    ));
    assert!(admission::preparation_failure(&current, true, now).is_none());
}

#[test]
fn missing_plans_and_revocation_never_turn_into_storage_failures() {
    let mut current = record();
    let now = OffsetDateTime::UNIX_EPOCH;
    current.revocation.state = RevocationState::Pending;
    assert!(matches!(
        admission::request(&current, &[], true, now),
        Err(IssueError::InvalidInput(
            "certificate revocation is unconfirmed; resolve it before renewing"
        ))
    ));
    current.revocation.state = RevocationState::Confirmed;
    assert_eq!(
        admission::request(&current, &[], false, now).unwrap(),
        RenewalAdmission::NotDue
    );
    assert_eq!(
        admission::request(&current, &[], true, now).unwrap(),
        RenewalAdmission::Start
    );
    assert!(admission::preparation_failure(&current, true, now).is_none());
    current.renewal = None;
    assert!(matches!(
        admission::request(&current, &[], true, now),
        Err(IssueError::InvalidInput(
            "in_use certificate has no renewal plan"
        ))
    ));
}

#[test]
fn retained_children_block_replay_before_parent_retry_checkpoint_and_select_exact_predecessor() {
    let current = record();
    let now = OffsetDateTime::UNIX_EPOCH;
    let previous = RenewalPredecessor {
        operation_id: current.operation_id.clone(),
        certificate_id: None,
        retained_validation: vec![],
    };
    let mut child = current.clone();
    child.phase = aster_acme_core::workflow::IssuancePhase::CreatingOrder;
    child.operation_id = "b".repeat(43);
    child.renewal_of = Some(previous.clone());
    child.is_in_use = false;
    assert_eq!(
        admission::request(&current, &[child.clone()], false, now).unwrap(),
        RenewalAdmission::Resume
    );
    assert_eq!(
        admission::existing(&[child.clone()], Some(&previous), now)
            .unwrap()
            .unwrap()
            .operation_id,
        child.operation_id
    );
    for status in [None, Some(408), Some(429), Some(500)] {
        let mut saved = child.clone();
        saved.new_order_intent_saved = true;
        saved.creation_failure = status.map(|status| RequestFailure {
            status,
            problem: None,
            retry_at: Some(now + Duration::hours(1)),
        });
        let children = [saved];
        let error = admission::existing(&children, Some(&previous), now).unwrap_err();
        match status {
            None => assert!(matches!(error, IssueError::CreationUncertain)),
            Some(429) => assert!(matches!(error, IssueError::Transport(_))),
            Some(_) => assert!(matches!(error, IssueError::MutationUncertain(_))),
        }
    }
    child.finalize_rejection = Some(RequestFailure {
        status: 429,
        problem: None,
        retry_at: Some(now + Duration::nanoseconds(1)),
    });
    assert!(matches!(
        admission::existing(&[child.clone()], Some(&previous), now),
        Err(IssueError::Transport(_))
    ));
    child.finalize_rejection = None;
    assert!(matches!(
        admission::existing(&[child.clone(), child.clone()], Some(&previous), now),
        Err(IssueError::InvalidInput(
            "several unfinished renewals match in_use; select an exact operation"
        ))
    ));
    child.renewal_of.as_mut().unwrap().operation_id = "other".into();
    assert!(
        admission::existing(&[child], Some(&previous), now)
            .unwrap()
            .is_none()
    );
}

#[test]
fn failed_foreground_renewal_evidence_is_classified_by_the_library() {
    let now = OffsetDateTime::UNIX_EPOCH;
    let mut saved = record();
    assert!(saved.renewal_failure(now).is_none());
    saved.renewal_of = Some(RenewalPredecessor {
        operation_id: "predecessor".into(),
        certificate_id: None,
        retained_validation: vec![],
    });
    saved.phase = aster_acme_core::workflow::IssuancePhase::CreatingOrder;
    saved.new_order_intent_saved = true;
    let failure = saved.renewal_failure(now).unwrap();
    assert_eq!(
        failure.blocked_reason.as_deref(),
        Some("newOrder may have been accepted but no Location was saved")
    );

    saved.new_order_intent_saved = false;
    saved.creation_failure = Some(RequestFailure {
        status: 503,
        problem: None,
        retry_at: Some(now + Duration::hours(1)),
    });
    saved.finalize_rejection = Some(RequestFailure {
        status: 400,
        problem: None,
        retry_at: Some(now + Duration::hours(2)),
    });
    saved.poll_wait_source = Some(crate::issuance::PollWaitSource::LocalInterval);
    saved.next_poll_at = Some(now + Duration::hours(3));
    let failure = saved.renewal_failure(now).unwrap();
    assert_eq!(failure.ca_retry_at, Some(now + Duration::hours(2)));
    assert!(failure.blocked_reason.is_some());

    saved.creation_failure = None;
    saved.finalize_rejection = None;
    saved.poll_wait_source = Some(crate::issuance::PollWaitSource::RetryAfter);
    let failure = saved.renewal_failure(now).unwrap();
    assert_eq!(failure.ca_retry_at, saved.next_poll_at);
    saved.phase = aster_acme_core::workflow::IssuancePhase::Completed;
    assert!(saved.renewal_failure(now).is_none());
}
