//! Real loopback discovery and protocol progression with isolated durable snapshots.
use crate::{
    account::AccountRecord,
    challenge::ChallengeKind,
    crypto::{AccountSigner, key::AccountKey, key_algorithm::KeyAlgorithm},
    issuance::{
        IssueError, IssueExecution, IssueIdentity, IssueOutcome, IssueRecord,
        ValidationRequirement,
        workflow::{Workflow, WorkflowObserver},
    },
    solver::{ChallengeSolver, ExecutionContext},
    storage::issuance::IssueSession,
    transport::{HttpPool, TransportOptions},
};
use aster_acme_protocol::directory::Directory;
use async_trait::async_trait;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct Session(Mutex<IssueRecord>);
#[async_trait]
impl IssueSession for Session {
    async fn record(&self) -> Result<IssueRecord, IssueError> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn save(&self, record: &IssueRecord) -> Result<(), IssueError> {
        *self.0.lock().unwrap() = record.clone();
        Ok(())
    }
    async fn csr(&self) -> Result<Vec<u8>, IssueError> {
        panic!("manual publication must precede finalize")
    }
    async fn certificate_der(&self) -> Result<Vec<u8>, IssueError> {
        panic!("not issued")
    }
    async fn complete(&self, _: &IssueRecord, _: &[u8]) -> Result<IssueRecord, IssueError> {
        panic!("not issued")
    }
    async fn record_renewal_failure(
        &self,
        _: time::OffsetDateTime,
        _: Option<time::OffsetDateTime>,
        _: Option<String>,
    ) -> Result<crate::issuance::RenewalRetryState, IssueError> {
        Err(IssueError::InvalidInput(
            "renewal retry checkpoint not used",
        ))
    }
}
#[derive(Default)]
struct Solver(AtomicUsize);
#[async_trait]
impl ChallengeSolver for Solver {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::Dns01
    }
    async fn ready(
        &self,
        _: &[ValidationRequirement],
        _: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        Ok(false)
    }
    async fn shutdown(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[derive(Default)]
struct Observer {
    stages: Mutex<Vec<&'static str>>,
}
impl crate::issuance::progress::IssueObserver for Observer {
    fn observe(&self, event: &crate::issuance::progress::IssueEvent) {
        if matches!(
            event,
            crate::issuance::progress::IssueEvent::CreatingOrder { .. }
        ) {
            self.stages.lock().unwrap().push("new-order");
        }
    }
}
impl WorkflowObserver for Observer {
    fn discovering(&self) {
        self.stages.lock().unwrap().push("discovering");
    }
    fn discovered(&self, _: &Directory, _: &IssueRecord) {
        self.stages.lock().unwrap().push("discovered");
    }
}
struct Fixture {
    server: MockServer,
    identity: IssueIdentity,
    session: Session,
    observer: Arc<Observer>,
}
impl Fixture {
    async fn new() -> Self {
        let server = MockServer::start().await;
        let url = |suffix: &str| format!("{}{suffix}", server.uri());
        Mock::given(method("GET")).and(path("/directory")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"newNonce":url("/nonce"),"newAccount":url("/account"),"newOrder":url("/create"),"meta":{"caaIdentities":["ca.example"]}}))).mount(&server).await;
        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "fresh"))
            .mount(&server)
            .await;
        let order = serde_json::json!({"status":"pending","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[url("/auth")],"finalize":url("/finalize")});
        Mock::given(method("POST"))
            .and(path("/create"))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("Location", url("/order"))
                    .set_body_json(order.clone()),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/order"))
            .respond_with(ResponseTemplate::new(200).set_body_json(order))
            .mount(&server)
            .await;
        Mock::given(method("POST")).and(path("/auth")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"identifier":{"type":"dns","value":"example.com"},"status":"pending","challenges":[{"type":"dns-01","url":url("/challenge"),"status":"pending","token":"opaque-token-with-enough-entropy"}]}))).mount(&server).await;
        let signer = Arc::new(AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap());
        let thumbprint = signer.jwk().unwrap().thumbprint().unwrap();
        let account: AccountRecord = serde_json::from_value(serde_json::json!({"key_algorithm":"ecdsa-p256","account_id":"a".repeat(43),"directory_url":url("/directory"),"key_thumbprint":thumbprint,"account_url":url("/account/1"),"contacts":[],"server_contacts":null,"last_status":"valid","deactivation":"not_requested","key_rotation":null,"accepted_terms_url":null,"state":"registered"})).unwrap();
        let record: IssueRecord = serde_json::from_value(serde_json::json!({"operation_id":"a".repeat(43),"name":"web","created_at":"2026-11-12T00:00:00Z","account_name":"default","account_id":account.account_id,"directory":url("/directory"),"account_url":url("/account/1"),"account_thumbprint":thumbprint,"key_algorithm":"ecdsa-p256","identifiers":["example.com"],"solver_id":"manual_dns","solver_config":{},"challenge":"dns-01","phase":"creating_order","creation_submitted":false,"authorizations":[],"finalize_submitted":"not_submitted"})).unwrap();
        Self {
            server,
            identity: IssueIdentity { account, signer },
            session: Session(Mutex::new(record)),
            observer: Arc::new(Observer::default()),
        }
    }
    fn identity(&self) -> IssueIdentity {
        IssueIdentity {
            account: self.identity.account.clone(),
            signer: self.identity.signer.clone(),
        }
    }
    fn workflow(&self) -> Workflow {
        Workflow::new(
            HttpPool::default(),
            self.identity.account.directory_url.clone(),
            TransportOptions {
                allow_loopback_http: true,
                ..TransportOptions::default()
            },
        )
        .unwrap()
        .with_observer(self.observer.clone())
    }
    async fn count(&self, target: &str) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == target)
            .count()
    }
}
fn execution() -> IssueExecution {
    IssueExecution {
        max_polls: 5,
        poll_interval: Duration::from_millis(1),
        context: ExecutionContext {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(5),
        },
    }
}
#[tokio::test]
async fn discovers_then_drives_protocol_and_always_shuts_down_without_recreating_on_resume() {
    let mut f = Fixture::new().await;
    let solver = Solver::default();
    assert!(matches!(
        f.workflow()
            .run(f.identity(), &mut f.session, &solver, &execution())
            .await
            .unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    assert_eq!(
        f.observer.stages.lock().unwrap().as_slice(),
        ["discovering", "discovered", "new-order"]
    );
    assert_eq!(solver.0.load(Ordering::SeqCst), 1);
    let before = f.session.record().await.unwrap();
    assert!(before.order_url.is_some());
    assert!(matches!(
        f.workflow()
            .run(f.identity(), &mut f.session, &solver, &execution())
            .await
            .unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    assert_eq!(f.count("/create").await, 1);
    assert_eq!(solver.0.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn uncertain_creation_fails_offline_and_cancelled_expired_inputs_never_discover() {
    for mode in ["uncertain", "cancelled", "expired"] {
        let mut f = Fixture::new().await;
        let solver = Solver::default();
        let mut limits = execution();
        if mode == "uncertain" {
            f.session.0.lock().unwrap().creation_submitted = true;
        }
        if mode == "cancelled" {
            limits.context.cancellation.cancel();
        }
        if mode == "expired" {
            limits.context.deadline = Instant::now();
        }
        assert!(
            f.workflow()
                .run(f.identity(), &mut f.session, &solver, &limits)
                .await
                .is_err()
        );
        assert_eq!(f.count("/directory").await, 0);
        assert_eq!(solver.0.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn discovery_failure_and_deadline_keep_checkpoint_and_shutdown() {
    for status in [500, 200] {
        let mut f = Fixture::new().await;
        let solver = Solver::default();
        let before = serde_json::to_value(f.session.record().await.unwrap()).unwrap();
        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(ResponseTemplate::new(status).set_delay(if status == 200 {
                Duration::from_secs(1)
            } else {
                Duration::ZERO
            }))
            .with_priority(1)
            .mount(&f.server)
            .await;
        let mut limits = execution();
        if status == 200 {
            limits.context.deadline = Instant::now() + Duration::from_millis(30);
        }
        assert!(
            f.workflow()
                .run(f.identity(), &mut f.session, &solver, &limits)
                .await
                .is_err()
        );
        assert_eq!(f.count("/create").await, 0);
        assert_eq!(
            serde_json::to_value(f.session.record().await.unwrap()).unwrap(),
            before
        );
        assert_eq!(solver.0.load(Ordering::SeqCst), 1);
    }
}

#[cfg(feature = "precheck")]
mod advisory;

#[tokio::test]
async fn cancellation_during_discovery_stops_without_submitting_order_and_releases_solver() {
    let mut f = Fixture::new().await;
    let solver = Solver::default();
    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
        .with_priority(1)
        .mount(&f.server)
        .await;
    let workflow = f.workflow();
    let identity = f.identity();
    let execution = execution();
    let server = &f.server;
    let mut running = Box::pin(workflow.run(identity, &mut f.session, &solver, &execution));
    tokio::select! {
        _ = &mut running => panic!("discovery exited before cancellation"),
        () = async {
            tokio::time::timeout(Duration::from_secs(3), async {
                while server.received_requests().await.unwrap().is_empty() { tokio::time::sleep(Duration::from_millis(10)).await; }
            }).await.unwrap();
        } => {},
    }
    execution.context.cancellation.cancel();
    assert!(matches!(running.await, Err(IssueError::Interrupted)));
    assert_eq!(solver.0.load(Ordering::SeqCst), 1);
    assert_eq!(f.count("/create").await, 0);
}
