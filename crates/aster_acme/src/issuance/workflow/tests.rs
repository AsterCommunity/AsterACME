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

struct Session(
    Mutex<IssueRecord>,
    Mutex<Option<Vec<u8>>>,
    Vec<u8>,
    std::sync::atomic::AtomicBool,
);
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

    async fn certificate_key(&self) -> Result<Vec<u8>, IssueError> {
        Ok(self.2.clone())
    }

    async fn complete(
        &self,
        record: &IssueRecord,
        chain: &[u8],
    ) -> Result<IssueRecord, IssueError> {
        assert_eq!(
            self.0.lock().unwrap().phase,
            aster_acme_core::workflow::IssuancePhase::Downloading
        );
        if self.3.swap(false, Ordering::SeqCst) {
            return Err(IssueError::InvalidInput("injected completion failure"));
        }
        let mut completed = record.clone();
        let now = time::OffsetDateTime::now_utc();
        completed.is_in_use = true;
        if completed.renewal.is_none() {
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
        }
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
        use crate::issuance::progress::IssueEvent;
        let stage = match event {
            IssueEvent::CreatingOrder { .. } => "new-order",
            IssueEvent::CertificateSaved { .. } => "saved",
            _ => return,
        };
        self.stages.lock().unwrap().push(stage);
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
    /// Leaf and issuing intermediate.
    issued_chain: Vec<u8>,
    /// Second valid chain over the same leaf, advertised via rel="alternate".
    alternate_chain: Vec<u8>,
}

/// PEM leaf signed by the same fixed key the CSR used, so mock CA responses
/// satisfy the download stage's key/identifier validation.
fn certificate_chain(key_der: &[u8], common_name: &'static str) -> Vec<u8> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
    let key = KeyPair::try_from(key_der).unwrap();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.subject_alt_names = vec![SanType::DnsName("example.com".try_into().unwrap())];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(89);
    params.self_signed(&key).unwrap().pem().into_bytes()
}
fn shared_leaf_chains(key_der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    let leaf_key = KeyPair::try_from(key_der).unwrap();
    let ca_params = |name: &str| {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
    };
    let root_key = KeyPair::generate().unwrap();
    let root_params = ca_params("Mock Alternate CA");
    let root = root_params.self_signed(&root_key).unwrap();
    let root_issuer = Issuer::new(root_params, root_key);
    let intermediate_key = KeyPair::generate().unwrap();
    let intermediate_params = ca_params("Mock Default CA");
    let intermediate = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .unwrap();
    let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);
    let leaf = CertificateParams::new(vec!["example.com".into()])
        .unwrap()
        .signed_by(&leaf_key, &intermediate_issuer)
        .unwrap();
    let default = format!("{}{}", leaf.pem(), intermediate.pem());
    let alternate = format!("{default}{}", root.pem());
    (default.into_bytes(), alternate.into_bytes())
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
        let record: IssueRecord = serde_json::from_value(serde_json::json!({"operation_id":"a".repeat(43),"name":"web","created_at":"2026-11-12T00:00:00Z","account_name":"default","account_id":account.account_id,"directory":url("/directory"),"account_url":url("/account/1"),"account_thumbprint":thumbprint,"key_algorithm":"ecdsa-p256","identifiers":["example.com"],"solver_id":"manual_dns","solver_config":{},"challenge":"dns-01","phase":"creating_order","new_order_intent_saved":false,"authorizations":[],"finalize_submitted":"not_submitted","renewal":{"certificate_id":"aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE","not_before":"2026-11-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z","renew_at":"2099-01-01T00:00:00Z","source":"fallback","suggested_window":null,"explanation_url":null,"last_checked_at":null,"next_check_at":"2099-01-01T00:00:00Z","last_query_failed":false}})).unwrap();
        let material = crate::issuance::certificate::generate(
            &[crate::identifier::Identifier::Dns(
                crate::identifier::DnsIdentifier::new("example.com").unwrap(),
            )],
            KeyAlgorithm::EcdsaP256,
        )
        .unwrap();
        let (issued_chain, alternate_chain) = shared_leaf_chains(&material.key);
        Self {
            server,
            identity: IssueIdentity { account, signer },
            session: Session(
                Mutex::new(record),
                Mutex::new(None),
                material.key.to_vec(),
                std::sync::atomic::AtomicBool::new(false),
            ),
            observer: Arc::new(Observer::default()),
            issued_chain,
            alternate_chain,
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
    fn workflow_with_selector(
        &self,
        selector: Arc<dyn crate::issuance::ChainSelector>,
    ) -> Workflow {
        self.workflow().with_chain_selector(selector)
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
    mount_protocol(f).await;
    mount_certificate(f, None, 0).await;
}

/// Response the single alternate URL offers; `None` keeps a single-chain CA.
#[derive(Clone, Copy)]
enum AlternateResponse {
    Valid,
    ServerError,
    WrongCertificate,
    DifferentLeafSameKey,
    TooManyLinks,
}

async fn mount_chain_ca(
    f: &Fixture,
    alternate: AlternateResponse,
    expected_alternate_requests: usize,
) {
    mount_protocol(f).await;
    mount_certificate(f, Some(alternate), expected_alternate_requests).await;
}

async fn mount_protocol(f: &Fixture) {
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
        .expect(2..=3)
        .mount(&f.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/finalize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ready))
        .expect(1)
        .mount(&f.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/ari/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&f.server)
        .await;
}

async fn mount_certificate(
    f: &Fixture,
    alternate: Option<AlternateResponse>,
    expected_alternate_requests: usize,
) {
    let url = |suffix: &str| format!("{}{suffix}", f.server.uri());
    let certificate = ResponseTemplate::new(200)
        .insert_header(
            "Content-Type",
            "application/pem-certificate-chain; charset=utf-8",
        )
        .set_body_bytes(f.issued_chain.clone());
    let certificate = if matches!(alternate, Some(AlternateResponse::TooManyLinks)) {
        let mut certificate = certificate;
        for index in 1..=9 {
            certificate = certificate.append_header(
                "Link",
                format!(
                    r#"<{}>; rel="alternate""#,
                    url(&format!("/acme/alt/{index}"))
                ),
            );
        }
        certificate
    } else if alternate.is_some() {
        certificate.insert_header(
            "Link",
            format!(r#"<{}/acme/alt/1>; rel="alternate""#, url("")),
        )
    } else {
        certificate
    };
    Mock::given(method("POST"))
        .and(path("/certificate"))
        .respond_with(certificate)
        .expect(1)
        .mount(&f.server)
        .await;
    let Some(alternate) = alternate else { return };
    let response = match alternate {
        AlternateResponse::Valid => ResponseTemplate::new(200)
            .insert_header("Content-Type", "application/pem-certificate-chain")
            .set_body_bytes(f.alternate_chain.clone()),
        AlternateResponse::ServerError => ResponseTemplate::new(500),
        AlternateResponse::DifferentLeafSameKey => ResponseTemplate::new(200)
            .insert_header("Content-Type", "application/pem-certificate-chain")
            .set_body_bytes(certificate_chain(&f.session.2, "Different Leaf")),
        AlternateResponse::TooManyLinks => return,
        AlternateResponse::WrongCertificate => {
            use rcgen::KeyPair;
            let wrong_key = KeyPair::generate().unwrap();
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/pem-certificate-chain")
                .set_body_bytes(certificate_chain(
                    wrong_key.serialize_der().as_slice(),
                    "Wrong Leaf",
                ))
        }
    };
    Mock::given(method("POST"))
        .and(path("/acme/alt/1"))
        .respond_with(response)
        .expect(expected_alternate_requests as u64)
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
    // Clear the fixture's undiue plan so this case exercises the real ARI query.
    f.session.0.lock().unwrap().renewal = None;
    let solver = Solver(AtomicUsize::new(0), true);
    let workflow = f.workflow();
    let identity = f.identity();
    let mut context = execution();
    context.context.deadline = Instant::now() + Duration::from_secs(30);
    let cancellation = context.context.cancellation.clone();
    let server = &f.server;
    let session = &mut f.session;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let task = workflow.run(identity, session, &solver, &context);
        tokio::pin!(task);
        tokio::select! {
            result = &mut task => panic!("workflow returned before ARI cancellation: {:?}", result.err()),
            () = cancel_when_ari_is_requested(server, cancellation) => {
                tokio::time::timeout(Duration::from_secs(1), task)
                    .await
                    .expect("workflow must stop promptly after cancellation")
            }
        }
    })
    .await
    .expect("test must finish before the operation deadline");
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
    let IssueOutcome::Completed { record, .. } = result.unwrap() else {
        panic!("workflow did not complete after recording the advisory cancellation");
    };
    // The promoted chain is the validated response body, not raw wire bytes.
    assert_eq!(
        f.session.1.lock().unwrap().as_deref(),
        Some(f.issued_chain.as_slice())
    );
    assert!(record.selected_chain.is_some());
    assert_eq!(
        f.observer
            .stages
            .lock()
            .unwrap()
            .iter()
            .filter(|stage| **stage == "saved")
            .count(),
        1
    );
    assert_eq!(f.count("/finalize").await, 1);
    assert_eq!(f.count("/certificate").await, 1);
    assert_eq!(f.count("/ari/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE").await, 1);
    let persisted = f.session.record().await.unwrap();
    let returned_next_check_at = record.renewal.as_ref().unwrap().next_check_at;
    let persisted_next_check_at = persisted.renewal.as_ref().unwrap().next_check_at;
    assert!(persisted_next_check_at.is_some());
    assert_eq!(returned_next_check_at, persisted_next_check_at);
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
/// One decision per invocation: the selector records what it saw and returns
/// the configured decision, so tests assert the offered candidates exactly.
struct FixedSelector {
    decision: crate::issuance::ChainDecision,
    seen: Mutex<Vec<(bool, String)>>,
    requested: Mutex<Option<String>>,
}
impl crate::issuance::ChainSelector for FixedSelector {
    fn select(
        &self,
        requested: Option<&crate::issuance::ChainName>,
        candidates: &[crate::issuance::ChainCandidate],
        _: &ExecutionContext,
    ) -> Result<crate::issuance::ChainDecision, IssueError> {
        *self.requested.lock().unwrap() = requested.map(|name| name.as_str().to_owned());
        *self.seen.lock().unwrap() = candidates
            .iter()
            .map(|candidate| (candidate.is_default, candidate.identity.dn.clone()))
            .collect();
        Ok(self.decision.clone())
    }
}

const DEFAULT_DN: &str = "CN=Mock Default CA";
const ALTERNATE_DN: &str = "CN=Mock Alternate CA";

async fn run_to_completion(f: &mut Fixture, workflow: Workflow) -> IssueRecord {
    let solver = Solver(AtomicUsize::new(0), true);
    let identity = f.identity();
    let mut context = execution();
    context.context.deadline = Instant::now() + Duration::from_secs(30);
    let outcome = workflow
        .run(identity, &mut f.session, &solver, &context)
        .await
        .unwrap();
    let IssueOutcome::Completed { record, .. } = outcome else {
        panic!("expected a completed issuance");
    };
    *record
}

fn set_selection(f: &Fixture, selection: Option<crate::issuance::ChainSelection>) {
    f.session.0.lock().unwrap().chain_selection = selection;
}

#[tokio::test]
async fn no_preference_and_no_selector_fetches_only_the_default_chain() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::Valid, 0).await;
    let workflow = f.workflow();
    let record = run_to_completion(&mut f, workflow).await;
    assert_eq!(f.count("/certificate").await, 1);
    assert_eq!(f.count("/acme/alt/1").await, 0);
    assert!(record.selected_chain.is_some());
    assert_eq!(record.chain_selection, None);
}

#[tokio::test]
async fn explicit_ca_default_never_downloads_alternates() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::TooManyLinks, 0).await;
    set_selection(&f, Some(crate::issuance::ChainSelection::Default));
    let workflow = f.workflow();
    let record = run_to_completion(&mut f, workflow).await;
    assert_eq!(f.count("/acme/alt/1").await, 0);
    assert_eq!(
        record.chain_selection,
        Some(crate::issuance::ChainSelection::Default)
    );
}

#[tokio::test]
async fn a_preference_matching_the_default_chain_skips_the_fetch() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::Valid, 0).await;
    set_selection(
        &f,
        Some(crate::issuance::ChainSelection::Named {
            chain: crate::issuance::ChainName::new(DEFAULT_DN).unwrap(),
            remember: true,
        }),
    );
    let workflow = f.workflow();
    let record = run_to_completion(&mut f, workflow).await;
    assert_eq!(f.count("/acme/alt/1").await, 0);
    assert_eq!(
        record
            .selected_chain
            .as_ref()
            .map(|chain| chain.dn.as_str()),
        Some(DEFAULT_DN)
    );
}

#[tokio::test]
async fn a_preference_matches_an_alternate_by_common_name_fallback() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::Valid, 1).await;
    set_selection(
        &f,
        Some(crate::issuance::ChainSelection::Named {
            chain: crate::issuance::ChainName::new("mock alternate ca").unwrap(),
            remember: true,
        }),
    );
    let workflow = f.workflow();
    let record = run_to_completion(&mut f, workflow).await;
    assert_eq!(f.count("/acme/alt/1").await, 1);
    assert_eq!(
        record
            .selected_chain
            .as_ref()
            .map(|chain| chain.dn.as_str()),
        Some(ALTERNATE_DN)
    );
}

#[tokio::test]
async fn an_unmatched_preference_without_a_selector_fails_closed_without_reordering() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::Valid, 1).await;
    set_selection(
        &f,
        Some(crate::issuance::ChainSelection::Named {
            chain: crate::issuance::ChainName::new("ISRG Root X9").unwrap(),
            remember: false,
        }),
    );
    let solver = Solver(AtomicUsize::new(0), true);
    let mut context = execution();
    context.context.deadline = Instant::now() + Duration::from_secs(30);
    let error = f
        .workflow()
        .run(f.identity(), &mut f.session, &solver, &context)
        .await
        .err()
        .expect("issuance must fail with ChainUnavailable");
    let IssueError::ChainUnavailable {
        requested,
        available,
    } = error
    else {
        panic!("expected ChainUnavailable, got {error:?}");
    };
    assert_eq!(requested, "ISRG Root X9");
    assert_eq!(available, [DEFAULT_DN, ALTERNATE_DN]);
    // The certificate was issued; the order must not be recreated to retry.
    assert_eq!(f.count("/finalize").await, 1);
    assert_eq!(f.count("/create").await, 1);
    assert!(matches!(
        f.session.0.lock().unwrap().phase,
        aster_acme_core::workflow::IssuancePhase::Downloading
    ));
}

#[tokio::test]
async fn an_unavailable_soft_preference_falls_back_to_the_ca_default() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::Valid, 1).await;
    set_selection(
        &f,
        Some(crate::issuance::ChainSelection::Named {
            chain: crate::issuance::ChainName::new("ISRG Root X9").unwrap(),
            remember: true,
        }),
    );
    let workflow = f.workflow();
    let record = run_to_completion(&mut f, workflow).await;
    assert_eq!(
        record
            .selected_chain
            .as_ref()
            .map(|chain| chain.dn.as_str()),
        Some(DEFAULT_DN)
    );
    assert_eq!(
        record.chain_selection,
        Some(crate::issuance::ChainSelection::Named {
            chain: crate::issuance::ChainName::new("ISRG Root X9").unwrap(),
            remember: true,
        })
    );
}

#[tokio::test]
async fn selector_sees_validated_candidates_and_the_decision_becomes_the_definition() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::Valid, 1).await;
    let selector = Arc::new(FixedSelector {
        decision: crate::issuance::ChainDecision::Selected {
            index: 1,
            remember: true,
        },
        seen: Mutex::new(Vec::new()),
        requested: Mutex::new(None),
    });
    let workflow = f.workflow_with_selector(selector.clone());
    let record = run_to_completion(&mut f, workflow).await;
    assert_eq!(f.count("/acme/alt/1").await, 1);
    assert_eq!(
        *selector.requested.lock().unwrap(),
        None,
        "no explicit preference was in place"
    );
    assert_eq!(
        *selector.seen.lock().unwrap(),
        vec![
            (true, DEFAULT_DN.to_owned()),
            (false, ALTERNATE_DN.to_owned())
        ]
    );
    assert_eq!(
        record
            .selected_chain
            .as_ref()
            .map(|chain| chain.dn.as_str()),
        Some(ALTERNATE_DN)
    );
    // The interactive decision is written back as the inherited definition.
    assert_eq!(
        record.chain_selection,
        Some(crate::issuance::ChainSelection::Named {
            chain: crate::issuance::ChainName::new(ALTERNATE_DN).unwrap(),
            remember: true,
        })
    );
}

#[tokio::test]
async fn selector_default_decision_records_an_explicit_ca_default() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::Valid, 1).await;
    let selector = Arc::new(FixedSelector {
        decision: crate::issuance::ChainDecision::DefaultChain,
        seen: Mutex::new(Vec::new()),
        requested: Mutex::new(None),
    });
    let workflow = f.workflow_with_selector(selector);
    let record = run_to_completion(&mut f, workflow).await;
    assert_eq!(
        record.chain_selection,
        Some(crate::issuance::ChainSelection::Default)
    );
}

#[tokio::test]
async fn selector_abandon_cancels_resumably_after_the_certificate_was_issued() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::Valid, 1).await;
    let selector = Arc::new(FixedSelector {
        decision: crate::issuance::ChainDecision::Abandon,
        seen: Mutex::new(Vec::new()),
        requested: Mutex::new(None),
    });
    let solver = Solver(AtomicUsize::new(0), true);
    let mut context = execution();
    context.context.deadline = Instant::now() + Duration::from_secs(30);
    let error = f
        .workflow_with_selector(selector)
        .run(f.identity(), &mut f.session, &solver, &context)
        .await
        .err()
        .expect("abandoned issuance must fail cancelled");
    assert!(matches!(error, IssueError::Cancelled));
    assert_eq!(f.count("/finalize").await, 1);
    // The checkpoint stays resumable: no promotion, no order recreation.
    assert_eq!(f.count("/certificate").await, 1);
    assert!(f.session.1.lock().unwrap().is_none());
}

#[tokio::test]
async fn failed_alternates_are_dropped_without_endangering_the_default_chain() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::ServerError, 1).await;
    let selector = Arc::new(FixedSelector {
        decision: crate::issuance::ChainDecision::DefaultChain,
        seen: Mutex::new(Vec::new()),
        requested: Mutex::new(None),
    });
    let workflow = f.workflow_with_selector(selector.clone());
    let record = run_to_completion(&mut f, workflow).await;
    assert_eq!(f.count("/acme/alt/1").await, 1);
    // The broken candidate is dropped during fetch; with no valid alternate
    // left there is no choice to offer, so the selector is never consulted.
    assert_eq!(*selector.seen.lock().unwrap(), Vec::new());
    assert_eq!(
        record
            .selected_chain
            .as_ref()
            .map(|chain| chain.dn.as_str()),
        Some(DEFAULT_DN)
    );
}

#[tokio::test]
async fn a_mismatched_alternate_leaf_is_rejected_before_selection() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::WrongCertificate, 1).await;
    let selector = Arc::new(FixedSelector {
        decision: crate::issuance::ChainDecision::Selected {
            index: 1,
            remember: false,
        },
        seen: Mutex::new(Vec::new()),
        requested: Mutex::new(None),
    });
    let workflow = f.workflow_with_selector(selector.clone());
    let record = run_to_completion(&mut f, workflow).await;
    // The hostile leaf is dropped during validation: with no valid alternates
    // left there is no choice to offer, so the selector is never consulted.
    assert_eq!(*selector.seen.lock().unwrap(), Vec::new());
    assert_eq!(
        record
            .selected_chain
            .as_ref()
            .map(|chain| chain.dn.as_str()),
        Some(DEFAULT_DN)
    );
}

#[tokio::test]
async fn an_alternate_with_a_different_leaf_sharing_the_key_is_rejected() {
    let mut f = Fixture::new().await;
    mount_chain_ca(&f, AlternateResponse::DifferentLeafSameKey, 1).await;
    let selector = Arc::new(FixedSelector {
        decision: crate::issuance::ChainDecision::Selected {
            index: 1,
            remember: false,
        },
        seen: Mutex::new(Vec::new()),
        requested: Mutex::new(None),
    });
    let workflow = f.workflow_with_selector(selector.clone());
    let record = run_to_completion(&mut f, workflow).await;
    assert!(selector.seen.lock().unwrap().is_empty());
    assert_eq!(record.selected_chain.unwrap().dn, DEFAULT_DN);
    assert_eq!(f.count("/acme/alt/1").await, 1);
}

#[tokio::test]
async fn completion_failure_leaves_the_issued_order_resumable() {
    let mut f = Fixture::new().await;
    mount_protocol(&f).await;
    Mock::given(method("POST"))
        .and(path("/certificate"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/pem-certificate-chain")
                .set_body_bytes(f.issued_chain.clone()),
        )
        .expect(2)
        .mount(&f.server)
        .await;
    f.session.3.store(true, Ordering::SeqCst);
    let solver = Solver(AtomicUsize::new(0), true);
    let mut context = execution();
    context.context.deadline = Instant::now() + Duration::from_secs(30);
    let error = f
        .workflow()
        .run(f.identity(), &mut f.session, &solver, &context)
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error,
        IssueError::InvalidInput("injected completion failure")
    ));
    let saved = f.session.record().await.unwrap();
    assert_eq!(
        saved.phase,
        aster_acme_core::workflow::IssuancePhase::Downloading
    );
    assert!(saved.selected_chain.is_none());
    assert!(f.session.1.lock().unwrap().is_none());
    assert!(!f.observer.stages.lock().unwrap().contains(&"saved"));
    // Resume reads the same order and downloads its certificate again.
    let workflow = f.workflow();
    let result = run_to_completion(&mut f, workflow).await;
    assert_eq!(result.selected_chain.unwrap().dn, DEFAULT_DN);
    assert_eq!(f.count("/certificate").await, 2);
    assert_eq!(f.count("/create").await, 1);
    assert_eq!(f.count("/finalize").await, 1);
}
