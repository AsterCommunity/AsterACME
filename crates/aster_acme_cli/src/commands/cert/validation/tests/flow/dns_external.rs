//! Frozen-route and durable-receipt acceptance through the real ACME service.
use crate::commands::cert::validation::{
    ValidationMethod,
    dns_external::ExternalDns,
    tests::flow::Fixture,
    tests::{execution, progress},
};
use aster_acme::{
    issuance::{IssueError, IssueExecution, IssueOutcome},
    solver::{ChallengeSolver, ExecutionContext},
};
use aster_acme_dns::{
    CleanupRequest, CleanupResult, CleanupStatus, DnsProvider, DnsRecord, HostErrorCode,
    PresentResult, ProviderContext, ProviderError, ProviderErrorCode, ProviderExecution,
    ProviderFailure, PublicationReceipt, RecordOwnership, SideEffect,
    propagation::PropagationPolicy,
    routing::{DnsLookup, LookupError},
};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Default)]
struct Dns {
    records: Mutex<BTreeMap<String, (DnsRecord, PublicationReceipt)>>,
    route_queries: AtomicUsize,
    writes: AtomicUsize,
    present_calls: AtomicUsize,
    rate_limited: AtomicBool,
    cleanups: AtomicUsize,
    lose_response: AtomicBool,
    fail_cleanup: AtomicBool,
    cancel_after_present: AtomicBool,
    preexisting: AtomicBool,
}
#[async_trait]
impl DnsLookup for Dns {
    async fn cname(&self, name: &str) -> Result<Option<String>, LookupError> {
        self.route_queries.fetch_add(1, Ordering::SeqCst);
        Ok((name == "_acme-challenge.example.com.").then(|| "delegated.validation.net.".into()))
    }
    async fn txt(&self, _: &str) -> Result<Vec<Vec<u8>>, LookupError> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .values()
            .map(|(record, _)| record.value.as_bytes().to_vec())
            .collect())
    }
}
#[async_trait]
impl DnsProvider for Dns {
    async fn present(
        &self,
        _: &ProviderContext,
        records: &[DnsRecord],
        execution: &ProviderExecution,
    ) -> Result<Vec<PresentResult>, ProviderFailure> {
        self.present_calls.fetch_add(1, Ordering::SeqCst);
        if self.rate_limited.load(Ordering::SeqCst) {
            return Err(ProviderError {
                code: ProviderErrorCode::RateLimited,
                message: "throttled".into(),
                side_effect: SideEffect::None,
                retry_after_seconds: Some(60),
                provider_code: None,
            }
            .into());
        }
        let mut remote = self.records.lock().unwrap();
        let mut output = Vec::new();
        for record in records {
            let (_, receipt) = remote
                .entry(record.publication_id.clone())
                .or_insert_with(|| {
                    self.writes.fetch_add(1, Ordering::SeqCst);
                    (
                        record.clone(),
                        PublicationReceipt {
                            record_id: format!("record-{}", record.publication_id),
                            ownership: if self.preexisting.load(Ordering::SeqCst) {
                                RecordOwnership::Preexisting
                            } else {
                                RecordOwnership::Created
                            },
                            record_name: record.name.clone(),
                            cname_chain: record.cname_chain.clone(),
                        },
                    )
                });
            output.push(PresentResult {
                publication_id: record.publication_id.clone(),
                result: Ok(receipt.clone()),
            });
        }
        if self.lose_response.swap(false, Ordering::SeqCst) {
            return Err(ProviderFailure::Host {
                code: HostErrorCode::ProcessTimeout,
                side_effect: SideEffect::Unknown,
            });
        }
        if self.cancel_after_present.load(Ordering::SeqCst) {
            execution.cancellation.cancel();
        }
        Ok(output)
    }
    async fn cleanup(
        &self,
        _: &ProviderContext,
        records: &[CleanupRequest],
        _: &ProviderExecution,
    ) -> Result<Vec<CleanupResult>, ProviderFailure> {
        self.cleanups.fetch_add(1, Ordering::SeqCst);
        let mut remote = self.records.lock().unwrap();
        Ok(records
            .iter()
            .map(|record| {
                if self.fail_cleanup.load(Ordering::SeqCst) {
                    return CleanupResult {
                        publication_id: record.publication_id.clone(),
                        result: Err(ProviderError {
                            code: ProviderErrorCode::ProviderUnavailable,
                            message: "API unavailable".into(),
                            side_effect: SideEffect::None,
                            retry_after_seconds: None,
                            provider_code: None,
                        }),
                    };
                }
                let saved = remote.remove(&record.publication_id);
                assert!(
                    saved
                        .as_ref()
                        .is_none_or(|(_, receipt)| receipt == &record.receipt)
                );
                CleanupResult {
                    publication_id: record.publication_id.clone(),
                    result: Ok(if saved.is_some() {
                        CleanupStatus::Removed
                    } else {
                        CleanupStatus::AlreadyAbsent
                    }),
                }
            })
            .collect())
    }
}
fn solver(dns: Arc<Dns>) -> ExternalDns {
    ExternalDns {
        context: ProviderContext {
            provider_instance_id: "test-provider".into(),
            provider_profile_version: 1,
            provider_custom: BTreeMap::from([(
                "token".into(),
                serde_json::json!("must-not-be-journaled"),
            )]),
        },
        provider: dns.clone(),
        lookup: dns,
        allowed_zones: vec!["validation.net".into()],
        propagation: PropagationPolicy {
            interval: Duration::from_millis(5),
            timeout: Duration::from_secs(1),
        },
        progress: progress(),
    }
}
fn controls() -> IssueExecution {
    IssueExecution {
        context: ExecutionContext {
            deadline: std::time::Instant::now() + Duration::from_secs(10),
            ..execution()
        },
        poll_interval: Duration::from_millis(1),
        max_polls: 30,
    }
}
async fn run(
    fixture: &mut Fixture,
    solver: &dyn ChallengeSolver,
    context: &IssueExecution,
) -> Result<IssueOutcome, IssueError> {
    fixture
        .service
        .run(fixture.session.as_mut().unwrap().as_mut(), solver, context)
        .await
}
#[tokio::test]
async fn lost_present_response_reuses_saved_route_and_id_then_cleans_owned_record() {
    let mut fixture = Fixture::new(ValidationMethod::DnsExternal).await;
    let dns = Arc::new(Dns::default());
    dns.lose_response.store(true, Ordering::SeqCst);
    let solver = solver(dns.clone());
    assert!(run(&mut fixture, &solver, &controls()).await.is_err());
    assert_eq!(fixture.count("/dns-challenge").await, 0);
    let saved = fixture.session.as_ref().unwrap().record().await.unwrap();
    assert!(saved.authorizations[0].publication_plan.is_some());
    assert!(saved.authorizations[0].publication_receipt.is_none());
    let publication_id = saved.authorizations[0].publication_id.clone();
    fixture.reopen().await;
    let IssueOutcome::Completed { record, cleanup } =
        run(&mut fixture, &solver, &controls()).await.unwrap()
    else {
        panic!("issuance did not complete");
    };
    assert_eq!(
        cleanup,
        [] as [aster_acme::issuance::ValidationRequirement; 0]
    );
    assert_eq!(record.authorizations[0].publication_id, publication_id);
    assert_eq!(dns.writes.load(Ordering::SeqCst), 1);
    assert_eq!(dns.route_queries.load(Ordering::SeqCst), 2);
    assert!(dns.records.lock().unwrap().is_empty());
    assert_eq!(fixture.count("/orders/create").await, 1);
    assert_eq!(fixture.count("/dns-challenge").await, 1);
    let journal =
        std::fs::read_to_string(fixture.generation.lock().unwrap().join("operation.toml")).unwrap();
    assert!(!journal.contains("must-not-be-journaled"));
}
#[tokio::test]
async fn cancellation_after_provider_success_persists_receipt_before_waiting() {
    let mut fixture = Fixture::new(ValidationMethod::DnsExternal).await;
    let dns = Arc::new(Dns::default());
    dns.cancel_after_present.store(true, Ordering::SeqCst);
    assert!(
        run(&mut fixture, &solver(dns.clone()), &controls())
            .await
            .is_err()
    );
    let saved = fixture.session.as_ref().unwrap().record().await.unwrap();
    assert!(saved.authorizations[0].publication_receipt.is_some());
    assert!(saved.authorizations[0].cleanup_pending);
    assert_eq!(fixture.count("/dns-challenge").await, 0);
    assert_eq!(dns.cleanups.load(Ordering::SeqCst), 0);
    dns.cancel_after_present.store(false, Ordering::SeqCst);
    fixture.reopen().await;
    assert!(matches!(
        run(&mut fixture, &solver(dns.clone()), &controls())
            .await
            .unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(dns.writes.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn failed_cleanup_retains_certificate_and_retries_without_any_ca_request() {
    let mut fixture = Fixture::new(ValidationMethod::DnsExternal).await;
    let dns = Arc::new(Dns::default());
    dns.fail_cleanup.store(true, Ordering::SeqCst);
    let solver = solver(dns.clone());
    let IssueOutcome::Completed { record, cleanup } =
        run(&mut fixture, &solver, &controls()).await.unwrap()
    else {
        panic!("missing completed certificate");
    };
    assert_eq!(cleanup.len(), 1);
    assert!(record.authorizations[0].cleanup_pending);
    let before = fixture.server.received_requests().await.unwrap().len();
    dns.fail_cleanup.store(false, Ordering::SeqCst);
    let cleaned = aster_acme::issuance::publication::cleanup(
        fixture.session.as_ref().unwrap().as_ref(),
        &solver,
        &execution(),
    )
    .await
    .unwrap();
    assert!(!cleaned.authorizations[0].cleanup_pending);
    assert_eq!(
        before,
        fixture.server.received_requests().await.unwrap().len()
    );
    assert!(dns.records.lock().unwrap().is_empty());
}
#[tokio::test]
async fn preexisting_txt_is_retained_without_calling_provider_cleanup() {
    let mut fixture = Fixture::new(ValidationMethod::DnsExternal).await;
    let dns = Arc::new(Dns::default());
    dns.preexisting.store(true, Ordering::SeqCst);
    let IssueOutcome::Completed { cleanup, .. } =
        run(&mut fixture, &solver(dns.clone()), &controls())
            .await
            .unwrap()
    else {
        panic!("missing completed certificate");
    };
    if !cleanup.is_empty() {
        let result = aster_acme::issuance::publication::cleanup(
            fixture.session.as_ref().unwrap().as_ref(),
            &solver(dns.clone()),
            &execution(),
        )
        .await;
        panic!("preexisting cleanup pending: {result:?}");
    }
    assert_eq!(dns.records.lock().unwrap().len(), 1);
    assert_eq!(dns.cleanups.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn explicit_cleanup_rejects_nonterminal_orders_without_side_effects() {
    let fixture = Fixture::new(ValidationMethod::DnsExternal).await;
    let dns = Arc::new(Dns::default());
    assert!(
        aster_acme::issuance::publication::cleanup(
            fixture.session.as_ref().unwrap().as_ref(),
            &solver(dns.clone()),
            &execution()
        )
        .await
        .is_err()
    );
    assert_eq!(dns.cleanups.load(Ordering::SeqCst), 0);
}

struct FailSave<'a> {
    inner: &'a dyn aster_acme::storage::issuance::IssueSession,
    receipt_stage: bool,
    failed: AtomicBool,
}
#[async_trait]
impl aster_acme::storage::issuance::IssueSession for FailSave<'_> {
    async fn record(&self) -> Result<aster_acme::issuance::IssueRecord, IssueError> {
        self.inner.record().await
    }
    async fn save(&self, record: &aster_acme::issuance::IssueRecord) -> Result<(), IssueError> {
        let reached = record.authorizations.iter().any(|auth| {
            if self.receipt_stage {
                auth.publication_receipt.is_some()
            } else {
                auth.publication_plan.is_some()
            }
        });
        if reached && !self.failed.swap(true, Ordering::SeqCst) {
            return Err(IssueError::InvalidInput(
                "injected durable publication write failure",
            ));
        }
        self.inner.save(record).await
    }
    async fn csr(&self) -> Result<Vec<u8>, IssueError> {
        self.inner.csr().await
    }
    async fn complete(
        &self,
        record: &aster_acme::issuance::IssueRecord,
        chain: &[u8],
    ) -> Result<aster_acme::issuance::IssueRecord, IssueError> {
        self.inner.complete(record, chain).await
    }
    async fn record_renewal_failure(
        &self,
        now: time::OffsetDateTime,
        ca_retry_at: Option<time::OffsetDateTime>,
        blocked_reason: Option<String>,
    ) -> Result<aster_acme::issuance::RenewalRetryState, IssueError> {
        self.inner
            .record_renewal_failure(now, ca_retry_at, blocked_reason)
            .await
    }
}
#[tokio::test]
async fn failed_route_or_receipt_save_never_acknowledges_and_recovery_never_duplicates_dns() {
    for receipt_stage in [false, true] {
        let mut fixture = Fixture::new(ValidationMethod::DnsExternal).await;
        let dns = Arc::new(Dns::default());
        let handler = solver(dns.clone());
        {
            let mut session = FailSave {
                inner: fixture.session.as_ref().unwrap().as_ref(),
                receipt_stage,
                failed: AtomicBool::new(false),
            };
            assert!(
                fixture
                    .service
                    .run(&mut session, &handler, &controls())
                    .await
                    .is_err()
            );
            assert!(session.failed.load(Ordering::SeqCst));
        }
        assert_eq!(fixture.count("/dns-challenge").await, 0);
        assert_eq!(
            dns.writes.load(Ordering::SeqCst),
            usize::from(receipt_stage)
        );
        fixture.reopen().await;
        assert!(matches!(
            run(&mut fixture, &handler, &controls()).await.unwrap(),
            IssueOutcome::Completed { .. }
        ));
        assert_eq!(dns.writes.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.count("/orders/create").await, 1);
    }
}

#[tokio::test]
async fn rate_limit_backoff_is_saved_and_resume_cannot_reinvoke_before_it() {
    let mut fixture = Fixture::new(ValidationMethod::DnsExternal).await;
    let dns = Arc::new(Dns::default());
    dns.rate_limited.store(true, Ordering::SeqCst);
    let solver = solver(dns.clone());
    assert!(run(&mut fixture, &solver, &controls()).await.is_err());
    let saved = fixture.session.as_ref().unwrap().record().await.unwrap();
    assert!(saved.authorizations[0].publication_retry_at.is_some());
    fixture.reopen().await;
    assert!(run(&mut fixture, &solver, &controls()).await.is_err());
    assert_eq!(dns.present_calls.load(Ordering::SeqCst), 1);
    assert_eq!(dns.writes.load(Ordering::SeqCst), 0);
    let mut saved = fixture.session.as_ref().unwrap().record().await.unwrap();
    saved.authorizations[0].publication_retry_at =
        Some(time::OffsetDateTime::now_utc() - time::Duration::seconds(1));
    fixture
        .session
        .as_ref()
        .unwrap()
        .save(&saved)
        .await
        .unwrap();
    dns.rate_limited.store(false, Ordering::SeqCst);
    assert!(matches!(
        run(&mut fixture, &solver, &controls()).await.unwrap(),
        IssueOutcome::Completed { .. }
    ));
}
