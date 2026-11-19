//! Real loopback discovery and protocol progression with isolated durable snapshots.
use crate::{
    account::AccountRecord,
    challenge::ChallengeKind,
    crypto::{JwsSigner, key::SoftwareSigningKey, key_algorithm::KeyAlgorithm},
    issuance::{
        IssueError, IssueExecution, IssueIdentity, IssueOutcome, IssueRecord,
        workflow::{Workflow, WorkflowObserver},
    },
    solver::{ChallengeSolver, ExecutionContext, ReadyResult},
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
use tokio_util::sync::CancellationToken;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct Session(Mutex<IssueRecord>, Mutex<Option<Vec<u8>>>);
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
        Ok(b"fixed-csr".to_vec())
    }

    async fn complete(
        &self,
        record: &IssueRecord,
        chain: &[u8],
    ) -> Result<IssueRecord, IssueError> {
        let mut completed = record.clone();
        let now = time::OffsetDateTime::now_utc();
        completed.is_in_use = true;
        completed.renewal = Some(crate::renewal::RenewalPlan {
            certificate_id: Some("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE".into()),
            not_before: now - time::Duration::days(30),
            not_after: now + time::Duration::days(60),
            renew_at: now - time::Duration::seconds(1),
            source: crate::renewal::RenewalSource::Fallback,
            suggested_window: None,
            explanation_url: None,
            last_checked_at: None,
            next_check_at: None,
            last_query_failed: false,
        });
        *self.0.lock().unwrap() = completed.clone();
        *self.1.lock().unwrap() = Some(chain.to_vec());
        Ok(completed)
    }
    async fn record_renewal_failure(
        &self,
        _: crate::renewal::admission::RenewalFailure,
    ) -> Result<crate::issuance::RenewalRetryState, IssueError> {
        Err(IssueError::InvalidInput(
            "renewal retry checkpoint not used",
        ))
    }
}
struct Solver(AtomicUsize, bool);
impl Default for Solver {
    fn default() -> Self {
        Self(AtomicUsize::new(0), false)
    }
}
#[async_trait]
impl ChallengeSolver for Solver {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::Dns01
    }
    async fn ready(
        &self,
        _: &[crate::solver::ChallengePublication],
        _: &ExecutionContext,
    ) -> Result<ReadyResult, IssueError> {
        Ok(ReadyResult {
            ready: self.1,
            ..ReadyResult::default()
        })
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
        Mock::given(method("GET")).and(path("/directory")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"newNonce":url("/nonce"),"newAccount":url("/account"),"newOrder":url("/create"),"keyChange":url("/key-change"),"meta":{"caaIdentities":["ca.example"]}}))).mount(&server).await;
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
        let signer = Arc::new(SoftwareSigningKey::generate(KeyAlgorithm::EcdsaP256).unwrap());
        let thumbprint = signer.jwk().unwrap().thumbprint().unwrap();
        let account: AccountRecord = serde_json::from_value(serde_json::json!({"key_algorithm":"ecdsa-p256","account_id":"a".repeat(43),"directory_url":url("/directory"),"key_thumbprint":thumbprint,"account_url":url("/account/1"),"contacts":[],"server_contacts":null,"last_status":"valid","deactivation":"not_requested","key_rotation":null,"accepted_terms_url":null,"state":"registered"})).unwrap();
        let record: IssueRecord = serde_json::from_value(serde_json::json!({"operation_id":"a".repeat(43),"name":"web","created_at":"2026-11-12T00:00:00Z","account_name":"default","account_id":account.account_id,"directory":url("/directory"),"account_url":url("/account/1"),"account_thumbprint":thumbprint,"key_algorithm":"ecdsa-p256","identifiers":["example.com"],"solver_id":"manual_dns","solver_config":{},"challenge":"dns-01","phase":"creating_order","new_order_intent_saved":false,"authorizations":[],"finalize_submitted":"not_submitted"})).unwrap();
        Self {
            server,
            identity: IssueIdentity { account, signer },
            session: Session(Mutex::new(record), Mutex::new(None)),
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

async fn mount_complete_ca(f: &Fixture) {
    let url = |suffix: &str| format!("{}{suffix}", f.server.uri());
    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce":url("/nonce"),"newAccount":url("/account"),"newOrder":url("/create"),
            "keyChange":url("/key-change"),"renewalInfo":url("/ari")
        })))
        .with_priority(1)
        .mount(&f.server)
        .await;
    let pending = serde_json::json!({
        "status":"pending","expires":"2099-01-01T00:00:00Z",
        "identifiers":[{"type":"dns","value":"example.com"}],
        "authorizations":[],"finalize":url("/finalize")
    });
    let ready = serde_json::json!({
        "status":"ready","expires":"2099-01-01T00:00:00Z",
        "identifiers":[{"type":"dns","value":"example.com"}],
        "authorizations":[],"finalize":url("/finalize")
    });
    let valid = serde_json::json!({
        "status":"valid","expires":"2099-01-01T00:00:00Z",
        "identifiers":[{"type":"dns","value":"example.com"}],
        "authorizations":[],"finalize":url("/finalize"),"certificate":url("/certificate")
    });
    Mock::given(method("POST"))
        .and(path("/create"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("Location", url("/order"))
                .set_body_json(pending),
        )
        .with_priority(1)
        .expect(1)
        .mount(&f.server)
        .await;
    let poll = Arc::new(AtomicUsize::new(0));
    let poll_responses = poll.clone();
    let ready_for_poll = ready.clone();
    let valid_for_poll = valid.clone();
    Mock::given(method("POST"))
        .and(path("/order"))
        .respond_with(move |_request: &wiremock::Request| {
            if poll_responses.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(ready_for_poll.clone())
            } else {
                ResponseTemplate::new(200).set_body_json(valid_for_poll.clone())
            }
        })
        .with_priority(1)
        .expect(2)
        .mount(&f.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/finalize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ready))
        .expect(1)
        .mount(&f.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/certificate"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "Content-Type",
                    "application/pem-certificate-chain; charset=utf-8",
                )
                .set_body_bytes(
                    b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n".to_vec(),
                ),
        )
        .expect(1)
        .mount(&f.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/ari/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .expect(1)
        .mount(&f.server)
        .await;
}

async fn cancel_when_ari_is_requested(server: &MockServer, cancellation: CancellationToken) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.url.path().starts_with("/ari/"))
            {
                cancellation.cancel();
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn finalize_download_and_complete_follow_the_real_http_transport() {
    let mut f = Fixture::new().await;
    mount_complete_ca(&f).await;
    let solver = Solver(AtomicUsize::new(0), true);
    let workflow = f.workflow();
    let identity = f.identity();
    let context = execution();
    let cancellation = context.context.cancellation.clone();
    let server = &f.server;
    let session = &mut f.session;
    let (result, ()) = tokio::join!(
        workflow.run(identity, session, &solver, &context),
        cancel_when_ari_is_requested(server, cancellation)
    );
    assert!(
        result.is_ok(),
        "{:?}; requests: {:?}",
        result.as_ref().err(),
        f.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| (request.method.clone(), request.url.path().to_owned()))
            .collect::<Vec<_>>()
    );
    assert!(matches!(result.unwrap(), IssueOutcome::Completed { .. }));
    assert_eq!(
        f.session.1.lock().unwrap().as_deref(),
        Some(b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n".as_slice())
    );
    assert_eq!(f.count("/finalize").await, 1);
    assert_eq!(f.count("/certificate").await, 1);
    assert_eq!(f.count("/ari/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE").await, 1);
    assert!(
        f.session
            .record()
            .await
            .unwrap()
            .renewal
            .unwrap()
            .next_check_at
            .is_some()
    );
    assert_eq!(solver.0.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn uncertain_creation_fails_offline_and_cancelled_expired_inputs_never_discover() {
    for mode in ["uncertain", "cancelled", "expired"] {
        let mut f = Fixture::new().await;
        let solver = Solver::default();
        let mut limits = execution();
        if mode == "uncertain" {
            f.session.0.lock().unwrap().new_order_intent_saved = true;
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
async fn inspect_honors_caller_cancellation_and_deadline_without_mutations() {
    use crate::issuance::service::IssueService;
    use aster_acme_protocol::url::AcmeUrl;

    for mode in ["cancelled", "expired", "during_query"] {
        let mut f = Fixture::new().await;
        let client = HttpPool::default()
            .discover(
                f.identity.account.directory_url.clone(),
                TransportOptions {
                    allow_loopback_http: true,
                    ..TransportOptions::default()
                },
            )
            .await
            .unwrap();
        let service = IssueService::new(Arc::new(client), f.identity()).unwrap();
        f.session.0.lock().unwrap().order_url =
            Some(AcmeUrl::new(&format!("{}/order", f.server.uri())).unwrap());
        let before = serde_json::to_value(f.session.record().await.unwrap()).unwrap();
        let mut scope = execution().context;
        match mode {
            "cancelled" => scope.cancellation.cancel(),
            "expired" => scope.deadline = Instant::now(),
            "during_query" => {
                Mock::given(method("POST"))
                    .and(path("/order"))
                    .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
                    .with_priority(1)
                    .mount(&f.server)
                    .await;
                scope.deadline = Instant::now() + Duration::from_millis(100);
            }
            _ => unreachable!(),
        }
        let result = service.inspect(&mut f.session, &scope).await;
        assert!(matches!(
            (mode, result),
            ("cancelled", Err(IssueError::Cancelled))
                | ("expired" | "during_query", Err(IssueError::TimedOut))
        ));
        assert_eq!(f.count("/order").await, usize::from(mode == "during_query"));
        assert_eq!(f.count("/create").await, 0);
        assert_eq!(f.count("/finalize").await, 0);
        assert_eq!(
            serde_json::to_value(f.session.record().await.unwrap()).unwrap(),
            before
        );
    }
}

#[tokio::test]
async fn inspect_returns_cancellation_during_ari_query() {
    use crate::{
        issuance::service::IssueService,
        renewal::{RenewalPlan, RenewalSource},
    };
    use aster_acme_protocol::url::AcmeUrl;

    let mut f = Fixture::new().await;
    let url = |suffix: &str| format!("{}{suffix}", f.server.uri());
    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce":url("/nonce"),"newAccount":url("/account"),"newOrder":url("/create"),
            "keyChange":url("/key-change"),"renewalInfo":url("/ari")
        })))
        .with_priority(1)
        .mount(&f.server)
        .await;
    let now = time::OffsetDateTime::now_utc();
    {
        let mut record = f.session.record().await.unwrap();
        record.phase = aster_acme_core::workflow::IssuancePhase::Completed;
        record.is_in_use = true;
        record.order_url = Some(AcmeUrl::new(&url("/order")).unwrap());
        record.renewal = Some(RenewalPlan {
            certificate_id: Some("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE".into()),
            not_before: now - time::Duration::days(30),
            not_after: now + time::Duration::days(60),
            renew_at: now - time::Duration::seconds(1),
            source: RenewalSource::Fallback,
            suggested_window: None,
            explanation_url: None,
            last_checked_at: None,
            next_check_at: None,
            last_query_failed: false,
        });
        f.session.save(&record).await.unwrap();
    }
    Mock::given(method("POST"))
        .and(path("/order"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status":"valid","expires":"2099-01-01T00:00:00Z",
            "identifiers":[{"type":"dns","value":"example.com"}],
            "authorizations":[],"finalize":url("/finalize"),"certificate":url("/certificate")
        })))
        .with_priority(1)
        .mount(&f.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/ari/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&f.server)
        .await;
    let client = HttpPool::default()
        .discover(
            f.identity.account.directory_url.clone(),
            TransportOptions {
                allow_loopback_http: true,
                ..TransportOptions::default()
            },
        )
        .await
        .unwrap();
    let service = IssueService::new(Arc::new(client), f.identity()).unwrap();
    let context = execution().context;
    let cancellation = context.cancellation.clone();
    let server = &f.server;
    let session = &mut f.session;
    let (result, ()) = tokio::join!(service.inspect(session, &context), async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .any(|request| request.url.path().starts_with("/ari/"))
                {
                    cancellation.cancel();
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    });
    assert!(matches!(result, Err(IssueError::Cancelled)));
    assert_eq!(f.count("/ari/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE").await, 1);
    assert_eq!(f.count("/create").await, 0);
    assert_eq!(f.count("/finalize").await, 0);
}

#[tokio::test]
async fn expired_pending_order_can_cleanup_publication_before_finalize_was_submitted() {
    let fixture = Fixture::new().await;
    let mut record = fixture.session.record().await.unwrap();
    record.phase = aster_acme_core::workflow::IssuancePhase::Authorizing;
    record.order = Some(
        serde_json::from_value(serde_json::json!({
            "status":"pending",
            "expires":"2000-01-01T00:00:00Z",
            "identifiers":[{"type":"dns","value":"example.com"}],
            "authorizations":[format!("{}/auth", fixture.server.uri())],
            "finalize":format!("{}/finalize", fixture.server.uri())
        }))
        .unwrap(),
    );
    record.authorizations = serde_json::from_value(serde_json::json!([{
        "url":format!("{}/auth", fixture.server.uri()),
        "resource":{"identifier":{"type":"dns","value":"example.com"},"status":"pending","challenges":[]},
        "challenge_url":null,
        "validation_requirement":{"method":"dns-01","name":"_acme-challenge.example.com","value":"expected"},
        "publication_id":"publication-1",
        "cleanup_pending":true,
        "acknowledgement":"not_submitted"
    }]))
    .unwrap();
    fixture.session.save(&record).await.unwrap();
    let result = crate::issuance::publication::cleanup(
        &fixture.session,
        &Solver::default(),
        &execution().context,
    )
    .await;
    assert!(
        result.is_ok(),
        "expired pending order cleanup was rejected: {result:?}"
    );
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
    assert!(matches!(running.await, Err(IssueError::Cancelled)));
    assert_eq!(solver.0.load(Ordering::SeqCst), 1);
    assert_eq!(f.count("/create").await, 0);
}
