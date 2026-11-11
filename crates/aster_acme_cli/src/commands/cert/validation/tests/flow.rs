//! Loopback CA drives the same ACME service with real manual/webroot CLI adapters.
//! Finalization signs the persisted key; assertions verify no repeated newOrder on resume.
use super::*;
use aster_acme::{
    account::{AccountKeyStore, AccountRecord, AccountStore, KeyAccess},
    identifier::DnsIdentifier,
    issuance::service::IssueService,
    issuance::{IssueExecution, IssueOutcome, IssueRequest, IssueSession, IssueStore},
    transport::{HttpPool, TransportOptions},
};
use aster_acme_cli_storage::{CliAccountStore, issuance::CliIssueStore};
use aster_acme_core::{account::AccountRecordState, protocol::AccountStatus};
use aster_acme_protocol::{jws::FlattenedJws, url::AcmeUrl};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const TOKEN: &str = "opaque-HTTP-token-with-enough-entropy";
struct Fixture {
    temp: tempfile::TempDir,
    server: MockServer,
    store: CliIssueStore,
    account: AccountRecord,
    service: IssueService,
    session: Option<Box<dyn IssueSession>>,
    publication_fault: Arc<AtomicUsize>,
    generation: Arc<Mutex<PathBuf>>,
}

impl Fixture {
    async fn new(implementation: ValidationMethod) -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/arbitrary-directory")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce": format!("{}/nonce",server.uri()), "newAccount": format!("{}/account",server.uri()), "newOrder": format!("{}/orders/create",server.uri())
        }))).mount(&server).await;
        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "fresh_nonce"))
            .mount(&server)
            .await;
        let temp = tempfile::tempdir().unwrap();
        let accounts = Arc::new(
            CliAccountStore::open(temp.path(), "default", Duration::from_secs(1)).unwrap(),
        );
        let directory = AcmeUrl::new(&format!("{}/arbitrary-directory", server.uri())).unwrap();
        let signer = accounts
            .signer(&directory, "default", KeyAccess::Create(None))
            .await
            .unwrap();
        let thumb = signer.jwk().unwrap().thumbprint().unwrap();
        let mut account = accounts.load(&directory, &thumb).await.unwrap().unwrap();
        account.state = AccountRecordState::Registered;
        account.last_status = Some(AccountStatus::Valid);
        account.account_url = Some(AcmeUrl::new(&format!("{}/account/1", server.uri())).unwrap());
        accounts.save(&account).await.unwrap();
        let client = HttpPool::default()
            .discover(
                directory,
                TransportOptions {
                    allow_loopback_http: true,
                    ..TransportOptions::default()
                },
            )
            .await
            .unwrap();
        let service = IssueService::new(
            Arc::new(client),
            aster_acme::issuance::IssueIdentity {
                account: account.clone(),
                signer,
            },
        )
        .unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
        let root = temp.path().join("www");
        std::fs::create_dir(&root).unwrap();
        let request = IssueRequest {
            name: aster_acme::issuance::CertificateName::new("web").unwrap(),
            identifiers: vec![DnsIdentifier::new("example.com").unwrap()],
            key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
            account_name: "default".into(),
            challenge: implementation.kind(),
            solver_id: implementation.id().into(),
            solver_config: configuration(
                implementation,
                if implementation == ValidationMethod::Webroot {
                    Some(root.as_path())
                } else {
                    None
                },
            )
            .unwrap(),
        };
        let session = store.create(&request, &account).await.unwrap();
        let record = session.record().await.unwrap();
        let generation = Arc::new(Mutex::new(
            temp.path().join("certs/web").join(record.generation_name()),
        ));
        let fixture = Self {
            temp,
            server,
            store,
            account,
            service,
            session: Some(session),
            publication_fault: Arc::new(AtomicUsize::new(0)),
            generation,
        };
        fixture.mount().await;
        fixture
    }
    async fn mount(&self) {
        let stage = Arc::new(AtomicUsize::new(0));
        let base = self.server.uri();
        let order = |status: &str| serde_json::json!({"status":status,"expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[format!("{base}/authorize")],"finalize":format!("{base}/finalize"),"certificate":format!("{base}/certificate")});
        let initial = order("pending");
        let reset = stage.clone();
        let location = format!("{base}/order/1");
        Mock::given(method("POST"))
            .and(path("/orders/create"))
            .respond_with(move |_: &wiremock::Request| {
                reset.store(0, Ordering::SeqCst);
                ResponseTemplate::new(201)
                    .insert_header("Replay-Nonce", "created")
                    .insert_header("Location", location.clone())
                    .insert_header("Retry-After", "0")
                    .set_body_json(initial.clone())
            })
            .mount(&self.server)
            .await;
        let pending = order("pending");
        let ready = order("ready");
        let valid = order("valid");
        let current = stage.clone();
        Mock::given(method("POST"))
            .and(path("/order/1"))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200)
                    .insert_header("Replay-Nonce", "queried")
                    .insert_header("Retry-After", "0")
                    .set_body_json(match current.load(Ordering::SeqCst) {
                        0 => pending.clone(),
                        1 => ready.clone(),
                        _ => valid.clone(),
                    })
            })
            .mount(&self.server)
            .await;
        Mock::given(method("POST")).and(path("/authorize")).respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce","authz").set_body_json(serde_json::json!({"identifier":{"type":"dns","value":"example.com"},"status":"pending","expires":"2099-01-01T00:00:00Z","challenges":[
            {"type":"dns-01","url":format!("{base}/wrong-dns"),"status":"pending","token":"another-opaque-token-long-enough"},
            {"type":"http-01","url":format!("{base}/http-challenge"),"status":"pending","token":TOKEN}
        ]}))).mount(&self.server).await;
        let current = stage.clone();
        Mock::given(method("POST")).and(path("/http-challenge")).respond_with(move |request: &wiremock::Request| {
            let jws: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(URL_SAFE_NO_PAD.decode(jws.payload).unwrap(), b"{}");
            current.store(1,Ordering::SeqCst);
            ResponseTemplate::new(200).insert_header("Replay-Nonce","ack").set_body_json(serde_json::json!({"type":"http-01","url":format!("{base}/http-challenge"),"status":"valid","token":TOKEN}))
        }).mount(&self.server).await;
        let current = stage;
        let base = self.server.uri();
        let generation = self.generation.clone();
        Mock::given(method("POST")).and(path("/finalize")).respond_with(move |request: &wiremock::Request| {
            let jws: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
            assert_eq!(URL_SAFE_NO_PAD.decode(payload["csr"].as_str().unwrap()).unwrap(), std::fs::read(generation.lock().unwrap().join("request.der")).unwrap());
            current.store(2,Ordering::SeqCst);
            ResponseTemplate::new(200).insert_header("Replay-Nonce","finalized").insert_header("Retry-After","0").set_body_json(serde_json::json!({"status":"valid","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[format!("{base}/authorize")],"finalize":format!("{base}/finalize"),"certificate":format!("{base}/certificate")}))
        }).mount(&self.server).await;
        let generation = self.generation.clone();
        let fault = self.publication_fault.clone();
        let public_file = self
            .temp
            .path()
            .join(format!("www/.well-known/acme-challenge/{TOKEN}"));
        Mock::given(method("POST"))
            .and(path("/certificate"))
            .respond_with(move |_: &wiremock::Request| {
                if fault.load(Ordering::SeqCst) == 1 {
                    std::fs::write(&public_file, b"changed by user").unwrap();
                }
                let key = rcgen::KeyPair::try_from(
                    std::fs::read(generation.lock().unwrap().join("private-key.pk8"))
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
                let mut params =
                    rcgen::CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
                params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
                params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(89);
                let leaf = params.self_signed(&key).unwrap();
                ResponseTemplate::new(200)
                    .insert_header("Replay-Nonce", "certificate")
                    .insert_header("Content-Type", "application/pem-certificate-chain")
                    .set_body_raw(leaf.pem(), "application/pem-certificate-chain")
            })
            .mount(&self.server)
            .await;
    }
    async fn run(&mut self, yes: bool) -> Result<IssueOutcome, IssueError> {
        let record = self.session.as_ref().unwrap().record().await.unwrap();
        let solver = adapter(&record, false, yes, progress()).unwrap();
        self.service
            .run(
                self.session.as_mut().unwrap().as_mut(),
                solver.as_ref(),
                &IssueExecution {
                    max_polls: 30,
                    context: ExecutionContext {
                        deadline: Instant::now() + Duration::from_secs(10),
                        ..execution()
                    },

                    poll_interval: Duration::from_millis(1),
                },
            )
            .await
    }
    async fn reopen(&mut self) {
        let record = self.session.as_ref().unwrap().record().await.unwrap();
        drop(self.session.take());
        self.session = Some(
            self.store
                .open(&record.name, &record.operation_id)
                .await
                .unwrap(),
        );
    }
    async fn publish_then_cancel(&mut self) {
        let initial = self.session.as_ref().unwrap().record().await.unwrap();
        let solver = CancelAfterPublication(adapter(&initial, false, false, progress()).unwrap());
        let controls = IssueExecution {
            max_polls: 30,
            context: ExecutionContext {
                deadline: Instant::now() + Duration::from_secs(10),
                ..execution()
            },
            poll_interval: Duration::from_millis(1),
        };
        assert!(matches!(
            self.service
                .run(self.session.as_mut().unwrap().as_mut(), &solver, &controls)
                .await,
            Err(IssueError::Interrupted)
        ));
    }
    async fn count(&self, endpoint: &str) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method == "POST" && request.url.path() == endpoint)
            .count()
    }
}

#[tokio::test]
async fn manual_http_yields_public_file_material_then_resumes_without_another_order() {
    let mut fixture = Fixture::new(ValidationMethod::ManualHttp).await;
    let outcome = fixture.run(true).await.unwrap();
    let IssueOutcome::ActionRequired { record: _, records } = outcome else {
        panic!("expected manual work");
    };
    assert_eq!(fixture.count("/http-challenge").await, 0);
    assert_eq!(
        records,
        vec![ValidationRequirement::Http01 {
            url: format!("http://example.com/.well-known/acme-challenge/{TOKEN}"),
            path: format!("/.well-known/acme-challenge/{TOKEN}"),
            content: format!("{TOKEN}.{}", fixture.account.key_thumbprint)
        }]
    );
    fixture.reopen().await;
    let outcome = fixture.run(true).await.unwrap();
    let IssueOutcome::Completed { cleanup, .. } = outcome else {
        panic!("expected completion");
    };
    assert_eq!(cleanup, records);
    assert_eq!(fixture.count("/orders/create").await, 1);
    assert_eq!(fixture.count("/http-challenge").await, 1);
    assert_eq!(fixture.count("/wrong-dns").await, 0);
}

#[tokio::test]
async fn webroot_issues_without_prompt_cleans_only_owned_files_and_preserves_definition_for_renewal()
 {
    let mut fixture = Fixture::new(ValidationMethod::Webroot).await;
    let outcome = fixture.run(false).await.unwrap();
    let IssueOutcome::Completed { record, cleanup } = outcome else {
        panic!("expected completion");
    };
    assert_eq!(cleanup, Vec::<ValidationRequirement>::new());
    assert!(
        record
            .authorizations
            .iter()
            .all(|auth| !auth.cleanup_pending)
    );
    assert!(
        !fixture
            .temp
            .path()
            .join(format!("www/.well-known/acme-challenge/{TOKEN}"))
            .exists()
    );
    let name = record.name.clone();
    let expected = record.solver_config.clone();
    // Release the lease and create a fresh renewal generation from the saved definition.
    drop(fixture.session.take());
    let session = fixture.store.renew(&name, &fixture.account).await.unwrap();
    let renewal = session.record().await.unwrap();
    assert_eq!(renewal.challenge, ChallengeKind::Http01);
    assert_eq!(renewal.solver_id, "webroot");
    assert_eq!(renewal.solver_config, expected);
    assert!(renewal.renewal_of.is_some());
    *fixture.generation.lock().unwrap() = fixture
        .temp
        .path()
        .join("certs/web")
        .join(renewal.generation_name());
    fixture.session = Some(session);
    let outcome = fixture.run(false).await.unwrap();
    assert!(matches!(outcome, IssueOutcome::Completed { .. }));
    assert_eq!(fixture.count("/orders/create").await, 2);
    assert_eq!(fixture.count("/http-challenge").await, 2);
}

#[tokio::test]
async fn mismatched_solver_fails_before_any_order_or_acknowledgement() {
    let mut fixture = Fixture::new(ValidationMethod::ManualHttp).await;
    let context = IssueExecution {
        max_polls: 30,
        context: ExecutionContext {
            deadline: Instant::now() + Duration::from_secs(10),
            ..execution()
        },

        poll_interval: Duration::from_millis(1),
    };
    assert!(
        fixture
            .service
            .run(
                fixture.session.as_mut().unwrap().as_mut(),
                &aster_acme_validation::dns01::visibility::DnsVisibility,
                &context
            )
            .await
            .is_err()
    );
    assert_eq!(fixture.count("/orders/create").await, 0);
}

#[tokio::test]
async fn saved_http_token_changes_are_rejected_before_publication_or_acknowledgement() {
    let mut fixture = Fixture::new(ValidationMethod::ManualHttp).await;
    let outcome = fixture.run(true).await.unwrap();
    let IssueOutcome::ActionRequired { record, .. } = outcome else {
        panic!("expected pending");
    };
    let key = std::fs::read(fixture.generation.lock().unwrap().join("private-key.pk8")).unwrap();
    fixture.reopen().await;
    Mock::given(method("POST")).and(path("/authorize")).respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce","changed").set_body_json(serde_json::json!({
        "identifier":{"type":"dns","value":"example.com"},"status":"pending","expires":"2099-01-01T00:00:00Z",
        "challenges":[{"type":"http-01","url":format!("{}/http-challenge",fixture.server.uri()),"status":"pending","token":"different-opaque-token-long-enough"}]
    }))).with_priority(1).mount(&fixture.server).await;
    assert!(matches!(
        fixture.run(true).await,
        Err(IssueError::InvalidInput("saved challenge material changed"))
    ));
    assert_eq!(fixture.count("/orders/create").await, 1);
    assert_eq!(fixture.count("/http-challenge").await, 0);
    assert_eq!(
        std::fs::read(fixture.generation.lock().unwrap().join("private-key.pk8")).unwrap(),
        key
    );
    let saved = fixture.session.as_ref().unwrap().record().await.unwrap();
    assert_eq!(
        saved.authorizations[0].validation,
        record.authorizations[0].validation
    );
}

#[tokio::test]
async fn webroot_cleanup_failure_preserves_issued_artifacts_and_durable_cleanup_instructions() {
    let mut fixture = Fixture::new(ValidationMethod::Webroot).await;
    fixture.publication_fault.store(1, Ordering::SeqCst);
    let outcome = fixture.run(false).await.unwrap();
    let IssueOutcome::Completed { record, cleanup } = outcome else {
        panic!("expected issued certificate");
    };
    assert_eq!(cleanup.len(), 1);
    assert!(record.authorizations[0].cleanup_pending);
    assert!(
        fixture
            .temp
            .path()
            .join("certs/web/in_use/fullchain.pem")
            .is_file()
    );
    assert_eq!(
        std::fs::read(
            fixture
                .temp
                .path()
                .join(format!("www/.well-known/acme-challenge/{TOKEN}"))
        )
        .unwrap(),
        b"changed by user"
    );
    let saved = fixture.session.as_ref().unwrap().record().await.unwrap();
    assert!(saved.authorizations[0].cleanup_pending && !saved.unfinished());
    fixture.reopen().await;
    assert!(matches!(
        fixture.run(false).await.unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(fixture.count("/orders/create").await, 1);
}

struct CancelAfterPublication(Box<dyn ChallengeSolver>);
#[async_trait::async_trait]
impl ChallengeSolver for CancelAfterPublication {
    fn kind(&self) -> ChallengeKind {
        self.0.kind()
    }
    async fn ready(
        &self,
        requirements: &[ValidationRequirement],
        context: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        let ready = self.0.ready(requirements, context).await?;
        context.cancellation.cancel();
        Ok(ready)
    }
}

#[tokio::test]
async fn cancellation_after_webroot_publication_keeps_owned_files_and_resumes_without_new_order() {
    let mut fixture = Fixture::new(ValidationMethod::Webroot).await;
    let record = fixture.session.as_ref().unwrap().record().await.unwrap();
    let solver = CancelAfterPublication(adapter(&record, false, false, progress()).unwrap());
    let context = IssueExecution {
        max_polls: 30,
        context: ExecutionContext {
            deadline: Instant::now() + Duration::from_secs(10),
            ..execution()
        },
        poll_interval: Duration::from_millis(1),
    };
    assert!(matches!(
        fixture
            .service
            .run(
                fixture.session.as_mut().unwrap().as_mut(),
                &solver,
                &context
            )
            .await,
        Err(IssueError::Interrupted)
    ));
    assert_eq!(fixture.count("/http-challenge").await, 0);
    assert!(
        fixture
            .temp
            .path()
            .join(format!("www/.well-known/acme-challenge/{TOKEN}"))
            .is_file()
    );
    fixture.reopen().await;
    assert!(matches!(
        fixture.run(false).await.unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(fixture.count("/orders/create").await, 1);
    assert!(
        !fixture
            .temp
            .path()
            .join(format!("www/.well-known/acme-challenge/{TOKEN}"))
            .exists()
    );
}

#[tokio::test]
async fn saved_method_and_implementation_configuration_cannot_be_changed_on_open_or_save() {
    #[derive(serde::Serialize)]
    struct Journal<'a> {
        version: u32,
        operation: &'a IssueRecord,
    }
    for change_configuration in [false, true] {
        let mut fixture = Fixture::new(ValidationMethod::Webroot).await;
        let mut record = fixture.session.as_ref().unwrap().record().await.unwrap();
        if change_configuration {
            record.solver_config = configuration(ValidationMethod::ManualHttp, None).unwrap();
        } else {
            record.challenge = ChallengeKind::Dns01;
        }
        assert!(
            fixture
                .session
                .as_ref()
                .unwrap()
                .save(&record)
                .await
                .is_err()
        );
        drop(fixture.session.take());
        // Simulate external journal tampering, not a supported schema migration.

        std::fs::write(
            fixture.generation.lock().unwrap().join("operation.toml"),
            toml::to_string(&Journal {
                version: 1,
                operation: &record,
            })
            .unwrap(),
        )
        .unwrap();
        assert!(
            fixture
                .store
                .open(&record.name, &record.operation_id)
                .await
                .is_err()
        );
        assert_eq!(fixture.count("/orders/create").await, 0);
    }
}

#[tokio::test]
async fn similarity_requires_a_complete_resumable_definition_and_ignores_domain_order() {
    let fixture = Fixture::new(ValidationMethod::Webroot).await;
    let mut record = fixture.session.as_ref().unwrap().record().await.unwrap();
    record
        .identifiers
        .push(DnsIdentifier::new("www.example.com").unwrap());
    let mut request = IssueRequest {
        name: record.name.clone(),
        identifiers: record.identifiers.clone(),
        key_algorithm: record.key_algorithm,
        account_name: record.account_name.clone(),
        challenge: record.challenge,
        solver_id: record.solver_id.clone(),
        solver_config: record.solver_config.clone(),
    };
    request.identifiers.reverse();
    let now = time::OffsetDateTime::now_utc();
    assert!(record.matches_unfinished_request(&request, &fixture.account, now));
    for case in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11] {
        let mut other = record.clone();
        match case {
            0 => other.account_id = "replaced".into(),
            1 => other.account_name = "other".into(),
            2 => other.account_thumbprint = "other".into(),
            3 => other.directory = AcmeUrl::new("https://other.example/directory").unwrap(),
            4 => other.challenge = ChallengeKind::Dns01,
            5 => other.solver_id = "manual_http".into(),
            6 => other.solver_config = configuration(ValidationMethod::ManualHttp, None).unwrap(),
            7 => other.key_algorithm = aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP384,
            8 => other.identifiers.pop().map(|_| ()).unwrap(),
            9 => other.phase = aster_acme_core::workflow::IssuancePhase::Completed,
            10 => {
                other.creation_submitted = true;
                other.order_url = None;
            }
            11 => other.revocation.state = aster_acme_core::revocation::RevocationState::Pending,
            _ => panic!("unknown test case"),
        }
        assert!(
            !other.matches_unfinished_request(&request, &fixture.account, now),
            "case {case}"
        );
    }
}

#[tokio::test]
async fn similar_order_decision_does_not_allocate_a_key_or_contact_a_ca() {
    let mut fixture = Fixture::new(ValidationMethod::ManualHttp).await;
    let outcome = fixture.run(true).await.unwrap();
    let IssueOutcome::ActionRequired { record, .. } = outcome else {
        panic!("expected pending");
    };
    let before = std::fs::read(fixture.generation.lock().unwrap().join("private-key.pk8")).unwrap();
    let requests = fixture.server.received_requests().await.unwrap().len();
    let output = crate::common::session::OutputSession::new(true);
    assert!(super::super::super::similar::choose(vec![*record.clone()], false, &output).is_err());
    let selected = super::super::super::similar::choose(vec![*record], true, &output)
        .unwrap()
        .unwrap();
    assert_eq!(selected.challenge, ChallengeKind::Http01);
    assert_eq!(fixture.store.list().await.unwrap().len(), 1);
    assert_eq!(
        fixture.server.received_requests().await.unwrap().len(),
        requests
    );
    assert_eq!(
        std::fs::read(fixture.generation.lock().unwrap().join("private-key.pk8")).unwrap(),
        before
    );
}

#[tokio::test]
async fn matching_includes_every_unfinished_phase_but_unconfirmed_creation_never_reposts() {
    use aster_acme_core::workflow::IssuancePhase;
    let mut fixture = Fixture::new(ValidationMethod::ManualHttp).await;
    let mut record = fixture.session.as_ref().unwrap().record().await.unwrap();
    let request = IssueRequest {
        name: record.name.clone(),
        identifiers: record.identifiers.clone(),
        key_algorithm: record.key_algorithm,
        account_name: record.account_name.clone(),
        challenge: record.challenge,
        solver_id: record.solver_id.clone(),
        solver_config: record.solver_config.clone(),
    };
    for phase in [
        IssuancePhase::PreparingAccount,
        IssuancePhase::CreatingOrder,
        IssuancePhase::Authorizing,
        IssuancePhase::AwaitingOrderReady,
        IssuancePhase::Finalizing,
        IssuancePhase::AwaitingCertificate,
        IssuancePhase::Downloading,
    ] {
        record.phase = phase;
        assert!(
            record.matches_unfinished_request(
                &request,
                &fixture.account,
                time::OffsetDateTime::now_utc()
            ),
            "{phase:?}"
        );
    }
    record.phase = IssuancePhase::CreatingOrder;
    record.creation_submitted = true;
    record.order_url = None;
    fixture
        .session
        .as_ref()
        .unwrap()
        .save(&record)
        .await
        .unwrap();
    assert!(record.matches_unfinished_request(
        &request,
        &fixture.account,
        time::OffsetDateTime::now_utc()
    ));
    fixture.reopen().await;
    assert!(matches!(
        fixture.run(true).await,
        Err(IssueError::CreationUncertain)
    ));
    assert_eq!(fixture.count("/orders/create").await, 0);
    assert!(
        fixture
            .generation
            .lock()
            .unwrap()
            .join("private-key.pk8")
            .exists()
    );
}

#[tokio::test]
async fn malformed_unoffered_and_expired_http_challenges_never_publish_files_or_acknowledge() {
    for case in 0..4 {
        let mut fixture = Fixture::new(ValidationMethod::Webroot).await;
        let mut challenge = serde_json::json!({"type":"http-01","url":format!("{}/http-challenge",fixture.server.uri()),"status":"pending","token":TOKEN});
        let mut expires = "2099-01-01T00:00:00Z";
        match case {
            0 => challenge["token"] = serde_json::Value::Null,
            1 => challenge["token"] = serde_json::json!("../../invalid"),
            2 => challenge["type"] = serde_json::json!("dns-01"),
            3 => expires = "2000-01-01T00:00:00Z",
            _ => panic!("unknown case"),
        }
        Mock::given(method("POST")).and(path("/authorize")).respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce","malformed").set_body_json(serde_json::json!({"identifier":{"type":"dns","value":"example.com"},"status":"pending","expires":expires,"challenges":[challenge]}))).with_priority(1).mount(&fixture.server).await;
        assert!(fixture.run(false).await.is_err(), "case {case}");
        assert_eq!(fixture.count("/http-challenge").await, 0);
        assert!(!fixture.temp.path().join("www/.well-known").exists());
        assert_eq!(fixture.count("/orders/create").await, 1);
    }
}

#[tokio::test]
async fn expired_invalid_or_csr_rejected_requests_are_not_automatic_recovery_candidates() {
    let fixture = Fixture::new(ValidationMethod::ManualHttp).await;
    let record = fixture.session.as_ref().unwrap().record().await.unwrap();
    let request = IssueRequest {
        name: record.name.clone(),
        identifiers: record.identifiers.clone(),
        key_algorithm: record.key_algorithm,
        account_name: record.account_name.clone(),
        challenge: record.challenge,
        solver_id: record.solver_id.clone(),
        solver_config: record.solver_config.clone(),
    };
    let now = time::OffsetDateTime::now_utc();
    for case in 0..3 {
        let mut other = record.clone();
        if case == 0 {
            other.finalize_rejection = Some(serde_json::from_value(serde_json::json!({"type":"urn:ietf:params:acme:error:badCSR","detail":"rejected","instance":null})).unwrap());
        } else {
            other.order = Some(serde_json::from_value(serde_json::json!({"status":if case == 1 { "invalid" } else { "pending" },"expires":"2000-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[],"finalize":"https://ca.example/finalize"})).unwrap());
        }
        assert!(!other.matches_unfinished_request(&request, &fixture.account, now));
    }
}

#[tokio::test]
async fn poll_budget_is_exact_preserves_checkpoint_and_resume_does_not_create_another_order() {
    let mut fixture = Fixture::new(ValidationMethod::ManualHttp).await;
    assert!(matches!(
        fixture.run(true).await.unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    // Keep the order pending regardless of successful challenge acknowledgement.
    Mock::given(method("POST")).and(path("/order/1")).respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce","pending").insert_header("Retry-After","0").set_body_json(serde_json::json!({"status":"pending","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[format!("{}/authorize",fixture.server.uri())],"finalize":format!("{}/finalize",fixture.server.uri())}))).with_priority(1).mount(&fixture.server).await;
    let before = fixture.count("/order/1").await;
    let solver = adapter(
        &fixture.session.as_ref().unwrap().record().await.unwrap(),
        false,
        true,
        progress(),
    )
    .unwrap();
    let execution = IssueExecution {
        max_polls: 2,
        context: ExecutionContext {
            deadline: Instant::now() + Duration::from_secs(10),
            ..execution()
        },
        poll_interval: Duration::from_millis(1),
    };
    assert!(matches!(
        fixture
            .service
            .run(
                fixture.session.as_mut().unwrap().as_mut(),
                solver.as_ref(),
                &execution
            )
            .await,
        Err(IssueError::PollLimit {
            completed: 2,
            limit: 2
        })
    ));
    assert_eq!(fixture.count("/order/1").await - before, 2);
    assert_eq!(fixture.count("/orders/create").await, 1);
    let record = fixture.session.as_ref().unwrap().record().await.unwrap();
    assert_eq!(
        record.poll_wait_source,
        Some(aster_acme::issuance::PollWaitSource::RetryAfter)
    );
    fixture.reopen().await;
    for invalid in [0, 1001] {
        let execution = IssueExecution {
            max_polls: invalid,
            context: super::execution(),
            poll_interval: Duration::from_millis(1),
        };
        assert!(
            fixture
                .service
                .run(
                    fixture.session.as_mut().unwrap().as_mut(),
                    solver.as_ref(),
                    &execution
                )
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn invalid_order_problem_is_saved_and_recovery_fails_offline_without_more_requests() {
    let mut fixture = Fixture::new(ValidationMethod::ManualHttp).await;
    assert!(matches!(
        fixture.run(true).await.unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    Mock::given(method("POST")).and(path("/order/1")).respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce","invalid").set_body_json(serde_json::json!({
        "status":"invalid","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],
        "authorizations":[format!("{}/authorize",fixture.server.uri())],"finalize":format!("{}/finalize",fixture.server.uri()),
        "error":{"type":"urn:ietf:params:acme:error:unauthorized","detail":"HTTP validation returned 404 for example.com"}
    }))).with_priority(1).mount(&fixture.server).await;
    let error = fixture.run(true).await.err().unwrap();
    assert!(matches!(
        error,
        IssueError::InvalidOrder { problem: Some(_) }
    ));
    let record = fixture.session.as_ref().unwrap().record().await.unwrap();
    assert!(!record.resume_candidate());
    assert_eq!(
        record.failure_problem().unwrap().detail.as_deref(),
        Some("HTTP validation returned 404 for example.com")
    );
    let before = fixture.server.received_requests().await.unwrap().len();
    assert!(matches!(
        record.check_recovery(time::OffsetDateTime::now_utc()),
        Err(IssueError::InvalidOrder { .. })
    ));
    assert!(matches!(
        fixture.run(true).await,
        Err(IssueError::InvalidOrder { .. })
    ));
    assert_eq!(
        fixture.server.received_requests().await.unwrap().len(),
        before
    );
}

#[tokio::test]
async fn invalid_order_without_top_level_error_preserves_challenge_problem() {
    let mut fixture = Fixture::new(ValidationMethod::ManualHttp).await;
    assert!(matches!(
        fixture.run(true).await.unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    Mock::given(method("POST")).and(path("/order/1")).respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce","invalid").set_body_json(serde_json::json!({
        "status":"invalid","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":[format!("{}/authorize",fixture.server.uri())],"finalize":format!("{}/finalize",fixture.server.uri())
    }))).with_priority(1).mount(&fixture.server).await;
    Mock::given(method("POST")).and(path("/authorize")).respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce","invalid_auth").set_body_json(serde_json::json!({
        "identifier":{"type":"dns","value":"example.com"},"status":"invalid","expires":"2099-01-01T00:00:00Z","challenges":[{"type":"http-01","url":format!("{}/http-challenge",fixture.server.uri()),"status":"invalid","token":TOKEN,
        "error":{"type":"urn:ietf:params:acme:error:connection","detail":"Connection refused at port 80"}}]
    }))).with_priority(1).mount(&fixture.server).await;
    let error = fixture.run(true).await.err().unwrap();
    let IssueError::InvalidOrder {
        problem: Some(problem),
    } = error
    else {
        panic!("expected enriched invalid problem");
    };
    assert_eq!(
        problem.detail.as_deref(),
        Some("Connection refused at port 80")
    );
    assert_eq!(fixture.count("/http-challenge").await, 0);
}

#[tokio::test]
async fn invalid_webroot_order_cleans_only_owned_unchanged_files_and_preserves_ca_problem() {
    for scenario in ["owned", "borrowed", "changed", "replaced"] {
        let mut fixture = Fixture::new(ValidationMethod::Webroot).await;
        let target = fixture
            .temp
            .path()
            .join(format!("www/.well-known/acme-challenge/{TOKEN}"));
        if scenario == "borrowed" {
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(
                &target,
                format!("{TOKEN}.{}", fixture.account.key_thumbprint),
            )
            .unwrap();
        }
        let key_path = fixture.generation.lock().unwrap().join("private-key.pk8");
        let key_before = std::fs::read(&key_path).unwrap();
        fixture.publish_then_cancel().await;
        assert!(
            target.is_file(),
            "cancellation must retain published material"
        );
        if scenario == "changed" {
            std::fs::write(&target, b"user changed content").unwrap();
        }
        if scenario == "replaced" {
            let content = std::fs::read(&target).unwrap();
            std::fs::remove_file(&target).unwrap();
            std::fs::write(&target, content).unwrap();
        }
        let public_before = std::fs::read(&target).unwrap();
        fixture.reopen().await;
        Mock::given(method("POST")).and(path("/order/1"))
            .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "invalid").set_body_json(serde_json::json!({
                "status":"invalid","expires":"2099-01-01T00:00:00Z","identifiers":[{"type":"dns","value":"example.com"}],
                "authorizations":[format!("{}/authorize",fixture.server.uri())],"finalize":format!("{}/finalize",fixture.server.uri()),
                "error":{"type":"urn:ietf:params:acme:error:unauthorized","detail":"HTTP validation returned 418"}
            }))).with_priority(1).mount(&fixture.server).await;
        let error = fixture.run(false).await.err().unwrap();
        let IssueError::InvalidOrder {
            problem: Some(problem),
        } = error
        else {
            panic!("expected original invalid order problem");
        };
        assert_eq!(
            problem.detail.as_deref(),
            Some("HTTP validation returned 418")
        );
        let saved = fixture.session.as_ref().unwrap().record().await.unwrap();
        assert!(!saved.resume_candidate());
        assert_eq!(
            saved.authorizations[0].cleanup_pending,
            scenario == "changed"
        );
        if scenario == "owned" {
            assert!(!target.exists());
        } else {
            assert_eq!(std::fs::read(&target).unwrap(), public_before, "{scenario}");
        }
        let receipts = std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".aster-acme-")
            })
            .count();
        assert_eq!(receipts, usize::from(scenario == "changed"));
        assert_eq!(std::fs::read(&key_path).unwrap(), key_before);
        assert!(
            fixture
                .generation
                .lock()
                .unwrap()
                .join("request.der")
                .is_file()
        );
        assert_eq!(fixture.count("/orders/create").await, 1);
        assert_eq!(fixture.count("/http-challenge").await, 0);
    }
}
