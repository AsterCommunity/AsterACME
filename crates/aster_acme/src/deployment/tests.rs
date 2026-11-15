//! Deployment policy boundaries, independent of a filesystem or process executor.
use crate::deployment::{DeploymentCheckpoint, DeploymentIntent, DeploymentPhase};
use time::{Duration, OffsetDateTime};

fn state() -> DeploymentCheckpoint {
    DeploymentCheckpoint {
        generation: Some("current".into()),
        pending_generation: None,
        phase: DeploymentPhase::ReloadFailed,
        attempts: 1,
        retry_failures: 0,
        retry_at: None,
        last_error: None,
    }
}

#[test]
fn admission_combines_exact_generation_snapshot_phase_and_nanosecond_deadline() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::nanoseconds(1);
    for phase in [
        DeploymentPhase::Configured,
        DeploymentPhase::Publishing,
        DeploymentPhase::PublishFailed,
        DeploymentPhase::PublicationComplete,
        DeploymentPhase::Reloading,
        DeploymentPhase::ReloadFailed,
        DeploymentPhase::ReloadUncertain,
        DeploymentPhase::Deployed,
    ] {
        let mut checkpoint = state();
        checkpoint.phase = phase;
        checkpoint.retry_at = Some(now);
        let eligible = matches!(
            phase,
            DeploymentPhase::Publishing
                | DeploymentPhase::PublishFailed
                | DeploymentPhase::PublicationComplete
                | DeploymentPhase::ReloadFailed
        );
        assert_eq!(checkpoint.due("current", now), eligible);
        assert!(!checkpoint.due("other", now));
        assert!(!checkpoint.due("current", now - Duration::nanoseconds(1)));
        let retry = DeploymentIntent::Retry {
            generation: "current",
            snapshot: &(),
        };
        assert_eq!(checkpoint.admits("current", retry, true, now), eligible);
        assert!(!checkpoint.admits("current", retry, false, now));
        assert!(checkpoint.admits("current", DeploymentIntent::<()>::Explicit, false, now));
        checkpoint.pending_generation = Some("next".into());
        assert_eq!(checkpoint.due("next", now), !phase.reload_uncertain());
        assert!(!checkpoint.due("next", now - Duration::nanoseconds(1)));
    }
}

#[test]
fn after_issuance_and_pending_intents_preserve_unknown_reload_barriers() {
    let now = OffsetDateTime::UNIX_EPOCH;
    let intent = DeploymentIntent::<()>::AfterIssuance { generation: "next" };
    for phase in [
        DeploymentPhase::Deployed,
        DeploymentPhase::ReloadFailed,
        DeploymentPhase::Reloading,
        DeploymentPhase::ReloadUncertain,
    ] {
        let mut checkpoint = state();
        checkpoint.phase = phase;
        assert_eq!(
            checkpoint.admits("next", intent, true, now),
            !phase.reload_uncertain()
        );
        assert!(!checkpoint.admits("other", intent, true, now));
        assert_eq!(
            checkpoint.pending("next").is_err(),
            phase.reload_uncertain()
        );
        checkpoint.generation = Some("next".into());
        checkpoint.retry_at = Some(now + Duration::nanoseconds(1));
        assert!(!checkpoint.admits("next", intent, true, now));
    }
    let mut checkpoint = state();
    checkpoint.phase = DeploymentPhase::Deployed;
    assert!(checkpoint.is_deployed());
    let already_deployed = checkpoint.pending("current").unwrap();
    assert_eq!(already_deployed, checkpoint);
    assert!(already_deployed.is_deployed());
    let pending = checkpoint.pending("next").unwrap();
    assert!(!pending.is_deployed());
    assert_eq!(pending.generation, checkpoint.generation);
    assert_eq!(pending.pending_generation.as_deref(), Some("next"));
}

#[test]
fn failures_back_off_without_losing_precision_and_overflow_leaves_input_unchanged() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::nanoseconds(123);
    let mut checkpoint = state();
    for (count, seconds) in [(1, 60), (2, 600), (3, 6000), (4, 86400), (5, 86400)] {
        checkpoint = checkpoint
            .failed(DeploymentPhase::ReloadFailed, 2, "failed".into(), now)
            .unwrap();
        assert_eq!(checkpoint.retry_failures, count);
        assert_eq!(checkpoint.retry_at, Some(now + Duration::seconds(seconds)));
    }
    checkpoint.retry_failures = u32::MAX;
    let maximum = checkpoint
        .failed(DeploymentPhase::PublishFailed, 0, "failed".into(), now)
        .unwrap();
    assert_eq!(maximum.retry_failures, u32::MAX);
    let before = checkpoint.clone();
    assert!(
        checkpoint
            .failed(
                DeploymentPhase::PublishFailed,
                0,
                "failed".into(),
                time::PrimitiveDateTime::MAX.assume_utc()
            )
            .is_err()
    );
    assert_eq!(checkpoint, before);
    assert!(
        checkpoint
            .failed(DeploymentPhase::Deployed, 0, "invalid".into(), now)
            .is_err()
    );
    checkpoint.phase = DeploymentPhase::ReloadUncertain;
    assert!(
        checkpoint
            .failed(DeploymentPhase::ReloadFailed, 0, "invalid".into(), now)
            .is_err()
    );
}

#[test]
fn observations_and_configuration_changes_preserve_only_their_owned_state() {
    let now = OffsetDateTime::UNIX_EPOCH;
    let mut checkpoint = state();
    checkpoint.retry_failures = 3;
    checkpoint.retry_at = Some(now);
    checkpoint.pending_generation = Some("next".into());
    let same = checkpoint.observed("current", DeploymentPhase::Publishing, 0, None);
    assert_eq!(same.retry_failures, 3);
    assert_eq!(same.retry_at, Some(now));
    assert!(same.pending_generation.is_none());
    for observed in [
        checkpoint.observed("next", DeploymentPhase::Publishing, 0, None),
        checkpoint.observed("current", DeploymentPhase::Deployed, 1, None),
    ] {
        assert_eq!(observed.retry_failures, 0);
        assert!(observed.retry_at.is_none());
    }
    assert!(checkpoint.schedule(now).is_err());
    checkpoint.phase = DeploymentPhase::PublicationComplete;
    assert_eq!(checkpoint.schedule(now).unwrap().retry_failures, 3);
    let configured = checkpoint.reconfigured();
    assert_eq!(configured.phase, DeploymentPhase::Configured);
    assert!(configured.generation.is_none());
    assert_eq!(configured.retry_at, Some(now));
    for phase in [DeploymentPhase::Reloading, DeploymentPhase::ReloadUncertain] {
        checkpoint.phase = phase;
        assert_eq!(checkpoint.reconfigured(), checkpoint);
    }
}
