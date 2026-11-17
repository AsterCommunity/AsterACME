//! A broken observation remains one item failure and preserves both causes.
use crate::{
    account::AccountRecord,
    issuance::{CertificateName, IssueError, IssueRecord, IssueRequest, RenewalRetryState},
    maintenance::{Options, Outcome, run_once},
    storage::{
        issuance::{IssueSession, IssueStore},
        query::IssueQuery,
    },
    transport::HttpPool,
};
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_util::sync::CancellationToken;

struct Store;
struct Session {
    record: IssueRecord,
    reads: AtomicUsize,
}
fn record(name: &str) -> IssueRecord {
    let mut record: IssueRecord = serde_json::from_value(serde_json::json!({"operation_id":"a".repeat(43),"name":name,"created_at":"2026-11-12T00:00:00Z","account_name":"default","account_id":"a".repeat(43),"directory":"https://ca.example/directory","account_url":"https://ca.example/account/1","account_thumbprint":"a".repeat(43),"key_algorithm":"ecdsa-p256","identifiers":["example.com"],"solver_id":"manual_dns","solver_config":{},"challenge":"dns-01","phase":"creating_order","new_order_intent_saved":false,"authorizations":[],"finalize_submitted":"not_submitted"})).unwrap();
    record.renewal = Some(crate::renewal::RenewalPlan {
        certificate_id: None,
        not_before: time::OffsetDateTime::UNIX_EPOCH,
        not_after: time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(90),
        renew_at: time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(60),
        source: crate::renewal::RenewalSource::Fallback,
        suggested_window: None,
        explanation_url: None,
        last_checked_at: None,
        next_check_at: Some(time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(1)),
        last_query_failed: false,
    });
    record
}
#[async_trait]
impl IssueSession for Session {
    async fn record(&self) -> Result<IssueRecord, IssueError> {
        if self.record.name.as_str() == "a-broken" {
            let read = self.reads.fetch_add(1, Ordering::SeqCst);
            return Err(IssueError::InvalidInput(if read == 0 {
                "original refresh read failed"
            } else {
                "durable readback failed"
            }));
        }
        Ok(self.record.clone())
    }
    async fn save(&self, _: &IssueRecord) -> Result<(), IssueError> {
        unreachable!()
    }
    async fn csr(&self) -> Result<Vec<u8>, IssueError> {
        unreachable!()
    }
    async fn complete(&self, _: &IssueRecord, _: &[u8]) -> Result<IssueRecord, IssueError> {
        unreachable!()
    }
    async fn record_renewal_failure(
        &self,
        _: crate::renewal::admission::RenewalFailure,
    ) -> Result<RenewalRetryState, IssueError> {
        unreachable!()
    }
}
#[async_trait]
impl IssueStore for Store {
    async fn create(
        &self,
        _: &IssueRequest,
        _: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        unreachable!()
    }
    async fn renew(
        &self,
        _: &CertificateName,
        _: &AccountRecord,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        unreachable!()
    }
    async fn open(
        &self,
        _: &CertificateName,
        _: &str,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        unreachable!()
    }
    async fn open_observation(
        &self,
        name: &CertificateName,
        _: &str,
    ) -> Result<Box<dyn IssueSession>, IssueError> {
        Ok(Box::new(Session {
            record: record(name.as_str()),
            reads: AtomicUsize::new(0),
        }))
    }
    async fn query(&self, _: IssueQuery) -> Result<Vec<IssueRecord>, IssueError> {
        Ok(vec![record("b-healthy"), record("a-broken")])
    }
}
#[tokio::test]
async fn failed_readback_preserves_original_failure_and_later_items_still_run() {
    let report = run_once(
        &Store,
        &HttpPool::default(),
        &Options::default(),
        &CancellationToken::new(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(report.entries.len(), 2);
    assert!(!report.cancelled);
    let broken = &report.entries[0];
    match &broken.outcome {
        Outcome::Failed(IssueError::MaintenanceReadback {
            operation,
            readback,
        }) => {
            assert_eq!(operation.to_string(), "original refresh read failed");
            assert_eq!(readback.to_string(), "durable readback failed");
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert!(broken.renew_at.is_none() && broken.next_check_at.is_none());
    assert!(matches!(report.entries[1].outcome, Outcome::Skipped));
}
