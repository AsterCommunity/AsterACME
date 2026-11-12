//! Directory/account/method adaptation is reusable by embedded workflows, not CLI.
use crate::caa::{LookupError, order::*};
use aster_acme_core::caa::{Observation as CaaObservation, Property};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
struct Fake {
    calls: AtomicUsize,
    slow: bool,
}
#[async_trait]
impl Lookup for Fake {
    async fn lookup(&self, _: &str) -> Result<Vec<Property>, LookupError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.slow {
            return std::future::pending().await;
        }
        Ok(vec![Property {
            critical: false,
            tag: "issue".into(),
            value: b"ca.example; accounturi=https://ca.example/account/1; validationmethods=dns-01"
                .to_vec(),
        }])
    }
}
fn record() -> IssueRecord {
    serde_json::from_value(serde_json::json!({"operation_id":"a".repeat(43),"name":"web","created_at":"2026-11-12T00:00:00Z","account_name":"default","account_id":"a".repeat(43),"directory":"https://ca.example/directory","account_url":"https://ca.example/account/1","account_thumbprint":"a".repeat(43),"key_algorithm":"ecdsa-p256","identifiers":["example.com"],"solver_id":"manual_dns","solver_config":{},"challenge":"dns-01","phase":"creating_order","creation_submitted":false,"authorizations":[],"finalize_submitted":"not_submitted"})).unwrap()
}
#[tokio::test]
async fn directory_identity_is_required_and_request_inputs_reach_the_evaluator() {
    let lookup = Fake {
        calls: AtomicUsize::new(0),
        slow: false,
    };
    let checker = OrderCaa::new(&lookup, Runner::default());
    let mut directory = Directory {
        new_nonce: aster_acme_protocol::url::AcmeUrl::new("https://ca.example/nonce").unwrap(),
        new_account: aster_acme_protocol::url::AcmeUrl::new("https://ca.example/account").unwrap(),
        new_order: None,
        key_change: None,
        revoke_cert: None,
        renewal_info: None,
        meta: aster_acme_protocol::directory::DirectoryMeta::default(),
    };
    let execution = ExecutionContext {
        cancellation: tokio_util::sync::CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(5),
    };
    let mut saved = record();
    let report = checker.check(&directory, &saved, &execution).await.unwrap();
    assert!(matches!(
        report.observations[0].result,
        Err(Failure::Unavailable)
    ));
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 0);
    directory.meta.caa_identities = vec!["alternate.example".into(), "ca.example".into()];
    let report = checker.check(&directory, &saved, &execution).await.unwrap();
    assert_eq!(
        report.observations[0].result.as_ref().unwrap().observation,
        CaaObservation::Matches
    );
    saved.challenge = aster_acme::challenge::ChallengeKind::Http01;
    let report = checker.check(&directory, &saved, &execution).await.unwrap();
    assert_eq!(
        report.observations[0].result.as_ref().unwrap().observation,
        CaaObservation::NoMatch
    );
    execution.cancellation.cancel();
    assert!(matches!(
        checker.check(&directory, &saved, &execution).await,
        Err(Error::Interrupted)
    ));
}
