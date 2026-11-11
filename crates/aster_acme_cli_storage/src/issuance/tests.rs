//! Loopback CA exercises real journals, fixed CSR and restartable foreground execution.
use super::*;
use aster_acme::account::KeyAccess;
use aster_acme::crypto::key_algorithm::KeyAlgorithm;
use aster_acme::identifier::DnsIdentifier;
use aster_acme::issuance::service::IssueService;
use aster_acme::solver::ChallengeSolver;
use aster_acme::{
    account::{AccountKeyStore, AccountStore},
    issuance::{IssueExecution, IssueIdentity, IssueOutcome, ValidationRequirement},
    solver::ExecutionContext,
    transport::TransportOptions,
};
use aster_acme_core::{account::AccountRecordState, protocol::AccountStatus};
use aster_acme_protocol::{jws::FlattenedJws, url::AcmeUrl};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rcgen::PublicKeyData as _;
use rcgen::{CertificateParams, DistinguishedName, Issuer, KeyPair};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct Fixture {
    temp: tempfile::TempDir,
    server: MockServer,
    store: CliIssueStore,
    account: AccountRecord,
    service: Arc<IssueService>,
}

async fn fixture() -> Fixture {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/directory")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"newNonce":format!("{}/nonce",server.uri()),"newAccount":format!("{}/unused",server.uri()),"newOrder":format!("{}/vendor/create",server.uri())}))).mount(&server).await;
    Mock::given(method("HEAD"))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "fresh"))
        .mount(&server)
        .await;
    let temp = tempfile::tempdir().unwrap();
    let accounts =
        super::super::CliAccountStore::open(temp.path(), "default", Duration::from_secs(1))
            .unwrap();
    let directory = AcmeUrl::new(&format!("{}/directory", server.uri())).unwrap();
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
    let client = aster_acme::transport::HttpPool::default()
        .discover(
            directory,
            TransportOptions {
                allow_loopback_http: true,
                ..TransportOptions::default()
            },
        )
        .await
        .unwrap();
    let store = CliIssueStore::new(temp.path().into(), Duration::from_millis(100));
    let service = Arc::new(
        IssueService::new(
            Arc::new(client),
            IssueIdentity {
                account: account.clone(),
                signer,
            },
        )
        .unwrap(),
    );
    Fixture {
        temp,
        server,
        store,
        account,
        service,
    }
}

fn request() -> IssueRequest {
    IssueRequest {
        challenge: aster_acme::challenge::ChallengeKind::Dns01,
        solver_id: "manual_dns".into(),
        solver_config: serde_json::Value::Object(serde_json::Map::default()),
        key_algorithm: KeyAlgorithm::EcdsaP256,
        name: CertificateName::new("example.com").unwrap(),
        identifiers: vec![
            DnsIdentifier::new("example.com").unwrap(),
            DnsIdentifier::new("*.example.com").unwrap(),
        ],
        account_name: "default".into(),
    }
}

fn execution() -> IssueExecution {
    IssueExecution {
        max_polls: 30,
        context: ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(5),
        },

        poll_interval: Duration::from_millis(100),
    }
}

struct Dns(bool);
#[async_trait]
impl ChallengeSolver for Dns {
    fn kind(&self) -> aster_acme::challenge::ChallengeKind {
        aster_acme::challenge::ChallengeKind::Dns01
    }
    async fn ready(
        &self,
        records: &[ValidationRequirement],
        _execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        assert_eq!(records.len(), 2);
        let ValidationRequirement::Dns01 {
            name: first_name,
            value: first_value,
        } = &records[0]
        else {
            panic!("expected DNS");
        };
        let ValidationRequirement::Dns01 {
            name: second_name,
            value: second_value,
        } = &records[1]
        else {
            panic!("expected DNS");
        };
        assert_eq!(first_name, second_name);
        assert_ne!(first_value, second_value);
        Ok(self.0)
    }
}

fn order(server: &MockServer, status: &str, expires: Option<&str>) -> serde_json::Value {
    serde_json::json!({"status":status,"expires":expires,"identifiers":[{"type":"dns","value":"example.com"},{"type":"dns","value":"*.example.com"}],"authorizations":[format!("{}/auth/0",server.uri()),format!("{}/auth/1",server.uri())],"finalize":format!("{}/finalize/custom",server.uri()),"certificate":format!("{}/certificate",server.uri())})
}

async fn mount_creation(fixture: &Fixture, body: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/vendor/create"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("Replay-Nonce", "created")
                .insert_header("Location", format!("{}/order/custom", fixture.server.uri()))
                .set_body_json(body),
        )
        .expect(1)
        .mount(&fixture.server)
        .await;
}

async fn mount_flow(fixture: &Fixture) -> Arc<AtomicUsize> {
    let stage = Arc::new(AtomicUsize::new(0));
    mount_creation(
        fixture,
        order(&fixture.server, "pending", Some("2099-01-01T00:00:00Z")),
    )
    .await;
    let pending = order(&fixture.server, "pending", Some("2099-01-01T00:00:00Z"));
    let ready = order(&fixture.server, "ready", Some("2099-01-01T00:00:00Z"));
    let valid = order(&fixture.server, "valid", Some("2099-01-01T00:00:00Z"));
    let observed = stage.clone();
    Mock::given(method("POST"))
        .and(path("/order/custom"))
        .respond_with(move |_: &wiremock::Request| {
            let progress = observed.load(Ordering::SeqCst);
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "read")
                .insert_header("Retry-After", "0")
                .set_body_json(if progress >= 3 {
                    valid.clone()
                } else if progress >= 2 {
                    ready.clone()
                } else {
                    pending.clone()
                })
        })
        .mount(&fixture.server)
        .await;
    for index in 0..2 {
        let url = format!("{}/challenge/{index}", fixture.server.uri());
        let observed = stage.clone();
        Mock::given(method("POST")).and(path(format!("/auth/{index}"))).respond_with(move|_:&wiremock::Request|{
            let valid=observed.load(Ordering::SeqCst)>=2;
            ResponseTemplate::new(200).insert_header("Replay-Nonce","auth").set_body_json(serde_json::json!({"identifier":{"type":"dns","value":"example.com"},"wildcard":index==1,"status":if valid{"valid"}else{"pending"},"expires":"2099-01-01T00:00:00Z","challenges":[{"type":"dns-persist-01","url":format!("{url}/persist"),"status":"pending","issuer-domain-names":["letsencrypt.org"]},{"type":"dns-01","url":url,"status":if valid{"valid"}else{"pending"},"token":format!("long-enough-opaque-token-{index}")}]}))
        }).with_priority(10).mount(&fixture.server).await;
        let observed = stage.clone();
        let challenge_url = format!("{}/challenge/{index}", fixture.server.uri());
        Mock::given(method("POST"))
            .and(path(format!("/challenge/{index}")))
            .respond_with(move |request: &wiremock::Request| {
                let jws: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(URL_SAFE_NO_PAD.decode(jws.payload).unwrap(), b"{}");
                observed.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .insert_header("Replay-Nonce", "ack")
                    .insert_header("Retry-After", "0")
                    .set_body_json(serde_json::json!({"type":"dns-01","url":challenge_url,"token":format!("long-enough-opaque-token-{index}"),"status":"processing"}))
            })
            .expect(0..=1)
            .mount(&fixture.server)
            .await;
    }
    stage
}

fn leaf_for(generation: &Path, identifiers: &[DnsIdentifier]) -> String {
    let key = KeyPair::try_from(
        fs::read(generation.join("private-key.pk8"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let mut params = CertificateParams::new(
        identifiers
            .iter()
            .map(DnsIdentifier::value)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    params.distinguished_name = DistinguishedName::new();
    params.use_authority_key_identifier_extension = true;
    let ca_key = KeyPair::generate().unwrap();
    let ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    params.signed_by(&key, &issuer).unwrap().pem()
}

#[tokio::test]
async fn manual_dns_yields_then_resumes_to_validated_certificate_without_recreating_order() {
    let fixture = fixture().await;
    let stage = mount_flow(&fixture).await;
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let initial = session.record().await.unwrap();
    let outcome = fixture
        .service
        .run(session.as_mut(), &Dns(false), &execution())
        .await
        .unwrap();
    let IssueOutcome::ActionRequired { record, records } = outcome else {
        panic!("expected manual action")
    };
    assert_eq!(records.len(), 2);
    assert_eq!(stage.load(Ordering::SeqCst), 0);
    let generation = fixture
        .store
        .slot(&initial.name)
        .join(initial.generation_name());
    let key_before = fs::read(generation.join("private-key.pk8")).unwrap();
    let csr_before = fs::read(generation.join("request.der")).unwrap();
    let chain = leaf_for(&generation, &initial.identifiers);
    Mock::given(method("POST"))
        .and(path("/certificate"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "certificate")
                .insert_header("Content-Type", "application/pem-certificate-chain")
                .set_body_raw(chain.clone(), "application/pem-certificate-chain"),
        )
        .expect(1)
        .mount(&fixture.server)
        .await;
    let valid = order(&fixture.server, "valid", Some("2099-01-01T00:00:00Z"));
    let observed = stage.clone();
    let expected_csr = csr_before.clone();
    Mock::given(method("POST"))
        .and(path("/finalize/custom"))
        .respond_with(move |request: &wiremock::Request| {
            let outer: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
            let payload: serde_json::Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(outer.payload).unwrap()).unwrap();
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(payload["csr"].as_str().unwrap())
                    .unwrap(),
                expected_csr
            );
            observed.store(3, Ordering::SeqCst);
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "finalized")
                .insert_header("Retry-After", "0")
                .set_body_json(valid.clone())
        })
        .expect(1)
        .mount(&fixture.server)
        .await;
    drop(session);
    let restarted = CliIssueStore::new(fixture.temp.path().into(), Duration::from_secs(1));
    let mut session = restarted
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
    let outcome = fixture
        .service
        .run(session.as_mut(), &Dns(true), &execution())
        .await
        .unwrap();
    assert!(matches!(outcome, IssueOutcome::Completed { .. }));
    assert_eq!(
        fs::read(generation.join("private-key.pk8")).unwrap(),
        key_before
    );
    assert_eq!(
        fs::read(generation.join("request.der")).unwrap(),
        csr_before
    );
    assert_eq!(
        fs::read_to_string(generation.join("fullchain.pem")).unwrap(),
        chain
    );
    assert_eq!(
        selection(&fixture.store.slot(&initial.name))
            .unwrap()
            .cert
            .in_use,
        Some(initial.operation_id)
    );
    let saved = restarted.list().await.unwrap();
    assert_eq!(saved.len(), 1);
    assert!(matches!(saved[0].phase, IssuancePhase::Completed));
    assert!(saved[0].certificate_not_after.is_some());
}

#[tokio::test]
async fn expired_order_is_retained_and_force_cannot_advance_it() {
    let fixture = fixture().await;
    let expired = order(&fixture.server, "pending", Some("2000-01-01T00:00:00Z"));
    mount_creation(&fixture, expired.clone()).await;
    Mock::given(method("POST"))
        .and(path("/order/custom"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "expired")
                .set_body_json(expired),
        )
        .mount(&fixture.server)
        .await;
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let execution = execution();
    assert!(matches!(
        fixture
            .service
            .run(session.as_mut(), &Dns(true), &execution)
            .await,
        Err(IssueError::Expired)
    ));
    assert!(
        !fixture
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path().starts_with("/challenge"))
    );
}

#[tokio::test]
async fn unknown_creation_outcome_is_never_reposted_and_material_survives() {
    let fixture = fixture().await;
    Mock::given(method("POST"))
        .and(path("/vendor/create"))
        .respond_with(ResponseTemplate::new(201).set_delay(Duration::from_secs(3)))
        .expect(1)
        .mount(&fixture.server)
        .await;
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let initial = session.record().await.unwrap();
    let mut execution = execution();
    execution.context.deadline = Instant::now() + Duration::from_secs(1);
    assert!(
        fixture
            .service
            .run(session.as_mut(), &Dns(false), &execution)
            .await
            .is_err()
    );
    drop(session);
    let mut session = fixture
        .store
        .open(&initial.name, &initial.operation_id)
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .service
            .run(session.as_mut(), &Dns(false), &super::tests::execution())
            .await,
        Err(IssueError::CreationUncertain)
    ));
    assert!(session.csr().await.is_ok());
}

#[tokio::test]
async fn names_generations_locks_and_material_tampering_have_explicit_boundaries() {
    for value in ["", "..", "../escape", "a/b", "A.com", "*.a.*", "a\\b"] {
        assert!(CertificateName::new(value).is_err());
    }
    let fixture = fixture().await;
    let first = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let record = first.record().await.unwrap();
    assert!(
        fixture
            .store
            .open(&record.name, &record.operation_id)
            .await
            .is_err()
    );
    drop(first);
    let second = fixture
        .store
        .renew(&request().name, &fixture.account)
        .await
        .unwrap();
    assert_ne!(
        record.operation_id,
        second.record().await.unwrap().operation_id
    );
    drop(second);
    assert_eq!(fixture.store.list().await.unwrap().len(), 2);
    let path = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name())
        .join("request.der");
    atomic_write(&path, b"changed").unwrap();
    assert!(
        fixture
            .store
            .open(&record.name, &record.operation_id)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn malformed_order_and_wrong_identifier_keep_location_but_never_notify_challenges() {
    for case in 0..4 {
        let fixture = fixture().await;
        let mut body = order(&fixture.server, "pending", Some("2099-01-01T00:00:00Z"));
        match case {
            0 => body["expires"] = serde_json::Value::Null,
            1 => body["identifiers"][0]["value"] = serde_json::json!("attacker.example"),
            2 => {
                body["authorizations"] = serde_json::json!([
                    format!("{}/auth/0", fixture.server.uri()),
                    format!("{}/auth/0", fixture.server.uri())
                ]);
            }
            3 => body["expires"] = serde_json::json!("not-rfc3339"),
            _ => unreachable!(),
        }
        mount_creation(&fixture, body).await;
        let mut session = fixture
            .store
            .create(&request(), &fixture.account)
            .await
            .unwrap();
        assert!(
            fixture
                .service
                .run(session.as_mut(), &Dns(true), &execution())
                .await
                .is_err()
        );
        let saved = fixture.store.list().await.unwrap().remove(0);
        assert!(saved.order_url.is_some());
        assert!(saved.creation_submitted);
        assert!(
            !fixture
                .server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.url.path().starts_with("/challenge"))
        );
    }
}

#[tokio::test]
async fn failed_artifact_checks_never_replace_in_use_certificate() {
    let fixture = fixture().await;
    let first = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let mut record = first.record().await.unwrap();
    let generation = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name());
    let chain = leaf_for(&generation, &record.identifiers);
    record.phase = IssuancePhase::Completed;
    first.complete(&record, chain.as_bytes()).await.unwrap();
    drop(first);
    let in_use = selection(&fixture.store.slot(&record.name))
        .unwrap()
        .cert
        .in_use;
    let second = fixture
        .store
        .renew(&request().name, &fixture.account)
        .await
        .unwrap();
    let mut new = second.record().await.unwrap();
    new.phase = IssuancePhase::Completed;
    assert!(second.complete(&new, chain.as_bytes()).await.is_err());
    assert!(second.complete(&new, b"invalid PEM").await.is_err());
    let other = leaf_for(
        &fixture.store.slot(&new.name).join(new.generation_name()),
        &[DnsIdentifier::new("other.example").unwrap()],
    );
    assert!(second.complete(&new, other.as_bytes()).await.is_err());
    assert_eq!(
        selection(&fixture.store.slot(&new.name))
            .unwrap()
            .cert
            .in_use,
        in_use
    );
    assert!(
        !fixture
            .store
            .slot(&new.name)
            .join(new.generation_name())
            .join("fullchain.pem")
            .exists()
    );
}

#[tokio::test]
async fn cancellation_and_pending_finalization_never_replay_a_mutation() {
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let mut record = session.record().await.unwrap();
    record.creation_submitted = true;
    record.order_url =
        Some(AcmeUrl::new(&format!("{}/order/custom", fixture.server.uri())).unwrap());
    record.order = Some(
        serde_json::from_value(order(
            &fixture.server,
            "ready",
            Some("2099-01-01T00:00:00Z"),
        ))
        .unwrap(),
    );
    record.finalize_submitted = SubmissionState::Submitted;
    session.save(&record).await.unwrap();
    drop(session);
    Mock::given(method("POST"))
        .and(path("/order/custom"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "ready")
                .insert_header("Retry-After", "1")
                .set_body_json(order(
                    &fixture.server,
                    "ready",
                    Some("2099-01-01T00:00:00Z"),
                )),
        )
        .mount(&fixture.server)
        .await;
    let mut session = fixture
        .store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
    let mut execution = execution();
    execution.context.deadline = Instant::now() + Duration::from_millis(250);
    assert!(matches!(
        fixture
            .service
            .run(session.as_mut(), &Dns(true), &execution)
            .await,
        Err(IssueError::Interrupted)
    ));
    assert!(
        !fixture
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path().starts_with("/finalize"))
    );
    execution.context.cancellation.cancel();
    assert!(matches!(
        fixture
            .service
            .run(session.as_mut(), &Dns(true), &execution)
            .await,
        Err(IssueError::Interrupted)
    ));
}

#[tokio::test]
async fn expired_authorization_stops_before_dns_publication_or_notification() {
    let fixture = fixture().await;
    mount_flow(&fixture).await;
    let url = format!("{}/challenge/0", fixture.server.uri());
    Mock::given(method("POST")).and(path("/auth/0")).respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce","expired_auth").set_body_json(serde_json::json!({"identifier":{"type":"dns","value":"example.com"},"status":"pending","expires":"2000-01-01T00:00:00Z","challenges":[{"type":"dns-01","url":url,"status":"pending","token":"long-enough-opaque-token-0"}]}))).with_priority(1).mount(&fixture.server).await;
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .service
            .run(session.as_mut(), &Dns(true), &execution())
            .await,
        Err(IssueError::Expired)
    ));
    assert!(
        !fixture
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path().starts_with("/challenge"))
    );
}

#[tokio::test]
async fn bad_nonce_resigns_the_same_new_order_without_creating_a_second_generation() {
    let fixture = fixture().await;
    Mock::given(method("POST"))
        .and(path("/vendor/create"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("Replay-Nonce", "replacement")
                .set_body_json(serde_json::json!({"type":"urn:ietf:params:acme:error:badNonce"})),
        )
        .with_priority(1)
        .up_to_n_times(1)
        .expect(1)
        .mount(&fixture.server)
        .await;
    mount_flow(&fixture).await;
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .service
            .run(session.as_mut(), &Dns(false), &execution())
            .await
            .unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    let requests = fixture.server.received_requests().await.unwrap();
    let posts = requests
        .iter()
        .filter(|request| request.url.path() == "/vendor/create")
        .collect::<Vec<_>>();
    assert_eq!(posts.len(), 2);
    let first: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
    let second: FlattenedJws = serde_json::from_slice(&posts[1].body).unwrap();
    assert_eq!(first.payload, second.payload);
    assert_ne!(first.signature, second.signature);
    assert_eq!(fixture.store.list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn order_inspection_only_observes_and_preserves_pending_publication_state() {
    let fixture = fixture().await;
    mount_flow(&fixture).await;
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let IssueOutcome::ActionRequired { record, .. } = fixture
        .service
        .run(session.as_mut(), &Dns(false), &execution())
        .await
        .unwrap()
    else {
        panic!("expected manual action")
    };
    drop(session);
    let mut session = fixture
        .store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
    let observed = fixture.service.inspect(session.as_mut()).await.unwrap();
    assert_eq!(observed.operation_id, record.operation_id);
    assert_eq!(observed.finalize_submitted, SubmissionState::NotSubmitted);
    for authorization in &observed.authorizations {
        assert_eq!(authorization.acknowledgement, SubmissionState::NotSubmitted);
        assert!(authorization.validation.is_some());
    }
    assert!(
        !fixture
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path().starts_with("/challenge")
                || request.url.path().starts_with("/finalize"))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn unsafe_material_and_unknown_journal_versions_fail_without_replacing_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let record = session.record().await.unwrap();
    drop(session);
    let generation = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name());
    let key = generation.join("private-key.pk8");
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let csr = generation.join("request.der");
    let backup = fs::read(&csr).unwrap();
    fs::remove_file(&csr).unwrap();
    let target = fixture.temp.path().join("external");
    atomic_write(&target, &backup).unwrap();
    symlink(&target, &csr).unwrap();
    assert!(
        fixture
            .store
            .open(&record.name, &record.operation_id)
            .await
            .is_err()
    );
    assert_eq!(fs::read(&target).unwrap(), backup);
    fs::remove_file(&csr).unwrap();
    atomic_write(&csr, &backup).unwrap();
    let journal = generation.join("operation.toml");
    let text = fs::read_to_string(&journal)
        .unwrap()
        .replacen("version = 1", "version = 99", 1);
    atomic_write(&journal, text.as_bytes()).unwrap();
    assert!(fixture.store.list().await.is_err());
    assert_eq!(fs::read_to_string(&journal).unwrap(), text);
}

#[tokio::test]
async fn reusing_one_embedded_session_reads_its_latest_checkpoint_instead_of_recreating_order() {
    let fixture = fixture().await;
    mount_flow(&fixture).await;
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let first = fixture
        .service
        .run(session.as_mut(), &Dns(false), &execution())
        .await
        .unwrap();
    let second = fixture
        .service
        .run(session.as_mut(), &Dns(false), &execution())
        .await
        .unwrap();
    let (
        IssueOutcome::ActionRequired {
            record: first,
            records: first_txt,
        },
        IssueOutcome::ActionRequired {
            record: second,
            records: second_txt,
        },
    ) = (first, second)
    else {
        panic!("expected manual publication checkpoints");
    };
    assert_eq!(first.operation_id, second.operation_id);
    assert_eq!(first_txt, second_txt);
    assert_eq!(fixture.store.list().await.unwrap().len(), 1);
    assert_eq!(
        fixture
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == "/vendor/create")
            .count(),
        1
    );
}

struct DelayedPublication(std::sync::atomic::AtomicBool);
#[async_trait]
impl ChallengeSolver for DelayedPublication {
    fn kind(&self) -> aster_acme::challenge::ChallengeKind {
        aster_acme::challenge::ChallengeKind::Dns01
    }
    async fn ready(
        &self,
        _records: &[ValidationRequirement],
        _execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        self.0.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(2100)).await;
        Ok(true)
    }
}

#[tokio::test]
async fn expiry_during_manual_publication_is_rechecked_before_ca_notification() {
    let fixture = fixture().await;
    mount_flow(&fixture).await;
    let pending = order(&fixture.server, "pending", Some("2099-01-01T00:00:00Z"));
    Mock::given(method("POST"))
        .and(path("/order/custom"))
        .respond_with(move |_: &wiremock::Request| {
            let mut pending = pending.clone();
            pending["expires"] = serde_json::json!(
                (time::OffsetDateTime::now_utc() + time::Duration::seconds(2))
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap()
            );
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "before_publication")
                .set_body_json(pending.clone())
        })
        .with_priority(1)
        .mount(&fixture.server)
        .await;
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let dns = DelayedPublication(std::sync::atomic::AtomicBool::new(false));
    let execution = execution();
    assert!(matches!(
        fixture
            .service
            .run(session.as_mut(), &dns, &execution)
            .await,
        Err(IssueError::Expired)
    ));
    assert!(dns.0.load(Ordering::SeqCst));
    assert!(
        !fixture
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path().starts_with("/challenge"))
    );
}

#[tokio::test]
async fn selected_dns01_requires_its_own_valid_token_even_when_extensions_are_ignored() {
    for token in [
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!(17)),
        Some(serde_json::json!("short")),
        Some(serde_json::json!("not-a-valid-token-with-padding=")),
    ] {
        let fixture = fixture().await;
        mount_flow(&fixture).await;
        let mut resource = serde_json::json!({"identifier":{"type":"dns","value":"example.com"},"status":"pending","expires":"2099-01-01T00:00:00Z","challenges":[
            {"type":"dns-persist-01","url":format!("{}/persist",fixture.server.uri()),"status":"pending","issuer-domain-names":["letsencrypt.org"]},
            {"type":"dns-01","url":format!("{}/challenge/0",fixture.server.uri()),"status":"pending"}
        ]});
        if let Some(token) = token {
            resource["challenges"][1]["token"] = token;
        }
        Mock::given(method("POST"))
            .and(path("/auth/0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Replay-Nonce", "malformed_selected")
                    .set_body_json(resource),
            )
            .with_priority(1)
            .mount(&fixture.server)
            .await;
        let mut session = fixture
            .store
            .create(&request(), &fixture.account)
            .await
            .unwrap();
        assert!(
            fixture
                .service
                .run(session.as_mut(), &Dns(true), &execution())
                .await
                .is_err()
        );
        assert!(
            !fixture
                .server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.url.path().starts_with("/challenge")
                    || request.url.path() == "/persist")
        );
    }
}

#[derive(Default)]
struct Events(std::sync::Mutex<Vec<aster_acme::issuance::progress::IssueEvent>>);
impl aster_acme::issuance::progress::IssueObserver for Events {
    fn observe(&self, event: &aster_acme::issuance::progress::IssueEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

#[tokio::test]
async fn issuance_reports_typed_progress_in_order_without_private_or_txt_material() {
    use aster_acme::issuance::progress::IssueEvent;
    let mut fixture = fixture().await;
    mount_flow(&fixture).await;
    let events = Arc::new(Events::default());
    fixture.service = Arc::new(
        Arc::try_unwrap(fixture.service)
            .ok()
            .unwrap()
            .with_observer(events.clone()),
    );
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let IssueOutcome::ActionRequired { records, .. } = fixture
        .service
        .run(session.as_mut(), &Dns(false), &execution())
        .await
        .unwrap()
    else {
        panic!("expected publication action");
    };
    let observed = events.0.lock().unwrap();
    assert!(matches!(observed[0], IssueEvent::CreatingOrder { .. }));
    assert!(matches!(observed[1], IssueEvent::OrderCreated { .. }));
    assert!(observed.iter().any(|event| matches!(
        event,
        IssueEvent::OrderObserved {
            status: aster_acme_core::protocol::OrderStatus::Pending
        }
    )));
    assert!(matches!(
        observed.last().unwrap(),
        IssueEvent::PublicationRequired { count: 2, .. }
    ));
    let formatted = format!("{observed:?}");
    for requirement in records {
        if let ValidationRequirement::Dns01 { value, .. } = requirement {
            assert!(!formatted.contains(&value));
        }
    }
    assert!(!observed.iter().any(|event| matches!(
        event,
        IssueEvent::ValidationSubmitted { .. }
            | IssueEvent::Finalizing
            | IssueEvent::CertificateSaved
    )));
}

#[tokio::test]
async fn catalog_ignores_finder_files_at_both_levels_without_hiding_broken_generations() {
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let record = session.record().await.unwrap();
    drop(session);
    let catalog = fixture.temp.path().join("certs");
    let generations = fixture.store.slot(&record.name);
    for path in [
        catalog.join(".DS_Store"),
        catalog.join("README.txt"),
        generations.join(".DS_Store"),
        generations.join("notes.txt"),
    ] {
        fs::write(path, b"finder metadata, not a certificate journal").unwrap();
    }
    let records = fixture.store.list().await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].operation_id, record.operation_id);
    let opened = fixture
        .store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
    assert_eq!(opened.record().await.unwrap().name, record.name);
    drop(opened);
    let extra = generations.join("x".repeat(43));
    fs::create_dir(&extra).unwrap();
    fs::create_dir(catalog.join("My Notes")).unwrap();
    assert_eq!(fixture.store.list().await.unwrap().len(), 1);
    atomic_write(&extra.join("operation.toml"), b"broken managed journal").unwrap();
    assert!(fixture.store.list().await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn catalog_ignores_unmanaged_links_but_rejects_managed_marker_links() {
    use std::os::unix::fs::symlink;
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let record = session.record().await.unwrap();
    drop(session);
    let target = fixture.temp.path().join("external-file");
    fs::write(&target, b"untouched").unwrap();
    let root_link = fixture.temp.path().join("certs/.DS_Store");
    symlink(&target, &root_link).unwrap();
    assert_eq!(fixture.store.list().await.unwrap().len(), 1);
    fs::remove_file(&root_link).unwrap();
    let generation_link = fixture.store.slot(&record.name).join(".DS_Store");
    symlink(&target, &generation_link).unwrap();
    assert_eq!(fixture.store.list().await.unwrap().len(), 1);
    let journal = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name())
        .join("operation.toml");
    fs::remove_file(&journal).unwrap();
    symlink(&target, &journal).unwrap();
    assert!(fixture.store.list().await.is_err());
    assert_eq!(fs::read(&target).unwrap(), b"untouched");
}

#[tokio::test]
async fn complete_persists_leaf_ca_fullchain_and_same_pem_key_before_promoting() {
    use rcgen::{BasicConstraints, IsCa};
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let mut record = session.record().await.unwrap();
    let generation = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name());
    let der = fs::read(generation.join("private-key.pk8")).unwrap();
    let key = KeyPair::try_from(der.as_slice()).unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf = CertificateParams::new(
        record
            .identifiers
            .iter()
            .map(DnsIdentifier::value)
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .signed_by(&key, &issuer)
    .unwrap();
    let chain = format!("{}{}", leaf.pem(), ca.pem());
    record.phase = IssuancePhase::Completed;
    session.complete(&record, chain.as_bytes()).await.unwrap();
    assert_eq!(
        fs::read_to_string(generation.join("fullchain.pem")).unwrap(),
        chain
    );
    assert_eq!(
        fs::read_to_string(generation.join("cert.pem")).unwrap(),
        leaf.pem()
    );
    assert_eq!(
        fs::read_to_string(generation.join("ca.pem")).unwrap(),
        ca.pem()
    );
    let pem_key =
        zeroize::Zeroizing::new(fs::read_to_string(generation.join("private-key.pem")).unwrap());
    let restored = KeyPair::from_pem(&pem_key).unwrap();
    assert_eq!(restored.der_bytes(), key.der_bytes());
    assert_eq!(fs::read(generation.join("private-key.pk8")).unwrap(), der);
    assert_eq!(
        selection(&fixture.store.slot(&record.name))
            .unwrap()
            .cert
            .in_use,
        Some(record.operation_id)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["fullchain.pem", "cert.pem", "ca.pem", "private-key.pem"] {
            assert_eq!(
                fs::metadata(generation.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}

#[tokio::test]
async fn leaf_only_exports_empty_ca_and_failed_artifact_write_keeps_previous_in_use() {
    let fixture = fixture().await;
    let first = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let mut record = first.record().await.unwrap();
    let generation = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name());
    let chain = leaf_for(&generation, &record.identifiers);
    record.phase = IssuancePhase::Completed;
    first.complete(&record, chain.as_bytes()).await.unwrap();
    drop(first);
    assert_eq!(
        fs::read(generation.join("ca.pem")).unwrap(),
        Vec::<u8>::new()
    );
    let second = fixture
        .store
        .renew(&request().name, &fixture.account)
        .await
        .unwrap();
    let mut next = second.record().await.unwrap();
    next.phase = IssuancePhase::Completed;
    let folder = fixture.store.slot(&next.name).join(next.generation_name());
    let next_chain = leaf_for(&folder, &next.identifiers);
    fs::create_dir(folder.join("ca.pem")).unwrap();
    assert!(second.complete(&next, next_chain.as_bytes()).await.is_err());
    assert_eq!(
        selection(&fixture.store.slot(&record.name))
            .unwrap()
            .cert
            .in_use,
        Some(record.operation_id)
    );
    assert!(!matches!(
        second.record().await.unwrap().phase,
        IssuancePhase::Completed
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn in_use_link_atomically_selects_readable_generations_and_preserves_history() {
    use std::os::unix::fs::symlink;
    let fixture = fixture().await;
    let mut ids = Vec::new();
    let mut generations = Vec::new();
    for index in 0..2 {
        let session = match index {
            0 => fixture
                .store
                .create(&request(), &fixture.account)
                .await
                .unwrap(),
            _ => fixture
                .store
                .renew(&request().name, &fixture.account)
                .await
                .unwrap(),
        };
        let mut record = session.record().await.unwrap();
        let slot = fixture.store.slot(&record.name);
        let generation = slot.join(record.generation_name());
        let directory_name = record.generation_name();
        assert_eq!(directory_name.len(), 25);
        assert_eq!(directory_name.as_bytes()[8], b'T');
        assert_eq!(directory_name.as_bytes()[15], b'Z');
        let chain = leaf_for(&generation, &record.identifiers);
        record.phase = IssuancePhase::Completed;
        // Exercise restart after temporary symlink creation but before atomic promotion.
        symlink(
            record.generation_name(),
            slot.join(format!(".in_use-{}", record.operation_id)),
        )
        .unwrap();
        session.complete(&record, chain.as_bytes()).await.unwrap();
        assert_eq!(
            selected_view(&slot),
            PathBuf::from(record.generation_name())
        );
        assert_eq!(
            fs::read_to_string(slot.join("in_use/fullchain.pem")).unwrap(),
            chain
        );
        assert_eq!(
            fs::read(slot.join("in_use/private-key.pem")).unwrap(),
            fs::read(generation.join("private-key.pem")).unwrap()
        );
        ids.push(record.operation_id.clone());
        generations.push(generation);
    }
    assert_ne!(generations[0], generations[1]);
    assert!(generations[0].join("cert.pem").exists());
    let records = fixture.store.list().await.unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| ids.contains(&record.operation_id))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn in_use_promotion_refuses_foreign_targets_and_keeps_user_entries() {
    use std::os::unix::fs::symlink;
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let mut record = session.record().await.unwrap();
    let slot = fixture.store.slot(&record.name);
    let chain = leaf_for(&slot.join(record.generation_name()), &record.identifiers);
    record.phase = IssuancePhase::Completed;
    fs::write(slot.join("in_use"), b"user file").unwrap();
    assert!(session.complete(&record, chain.as_bytes()).await.is_err());
    assert_eq!(fs::read(slot.join("in_use")).unwrap(), b"user file");
    fs::remove_file(slot.join("in_use")).unwrap();
    symlink("../outside", slot.join("in_use")).unwrap();
    assert!(session.complete(&record, chain.as_bytes()).await.is_err());
    assert_eq!(
        fs::read_link(slot.join("in_use")).unwrap(),
        PathBuf::from("../outside")
    );
    fs::remove_file(slot.join("in_use")).unwrap();
    let pending = slot.join(format!(".in_use-{}", record.operation_id));
    fs::write(&pending, b"retain").unwrap();
    assert!(session.complete(&record, chain.as_bytes()).await.is_err());
    assert_eq!(fs::read(&pending).unwrap(), b"retain");
    assert!(selection(&slot).unwrap().cert.in_use.is_none());
}

#[tokio::test]
async fn renewal_fallback_and_ari_selection_survive_reopen_without_new_get_or_key_changes() {
    use aster_acme::renewal::{RenewalService, RenewalSource};
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let mut record = session.record().await.unwrap();
    let generation = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name());
    let key_bytes = fs::read(generation.join("private-key.pk8")).unwrap();
    let leaf = leaf_for(&generation, &record.identifiers);
    record.phase = IssuancePhase::Completed;
    let saved = session.complete(&record, leaf.as_bytes()).await.unwrap();
    let fallback = saved.renewal.as_ref().unwrap();
    assert_eq!(fallback.source, RenewalSource::Fallback);
    assert_eq!(
        fallback.renew_at,
        fallback.not_before + (fallback.not_after - fallback.not_before) * 2 / 3
    );
    let id = fallback.certificate_id.as_ref().unwrap();
    Mock::given(method("GET")).and(path("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce":format!("{}/nonce",fixture.server.uri()),"newAccount":format!("{}/unused",fixture.server.uri()),
            "renewalInfo":format!("{}/vendor/renewal",fixture.server.uri())
        }))).with_priority(1).mount(&fixture.server).await;
    let now = time::OffsetDateTime::now_utc();
    let info = aster_acme_protocol::renewal::RenewalInfo {
        suggested_window: aster_acme_protocol::renewal::SuggestedWindow {
            start: now + time::Duration::days(1),
            end: now + time::Duration::days(2),
        },
        explanation_url: None,
    };
    Mock::given(method("GET"))
        .and(path(format!("/vendor/renewal/{id}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Retry-After", "21600")
                .set_body_json(info),
        )
        .expect(1)
        .mount(&fixture.server)
        .await;
    let client = aster_acme::transport::HttpPool::default()
        .discover(
            record.directory.clone(),
            TransportOptions {
                allow_loopback_http: true,
                ..TransportOptions::default()
            },
        )
        .await
        .unwrap();
    let service = RenewalService::new(Arc::new(client));
    drop(session);
    let mut reopened = fixture
        .store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
    assert_eq!(
        reopened.record().await.unwrap().renewal.unwrap().renew_at,
        fallback.renew_at
    );
    let refreshed = service
        .refresh(reopened.as_mut(), &execution().context)
        .await
        .unwrap();
    let ari = refreshed.renewal.unwrap();
    assert_eq!(ari.source, RenewalSource::Ari);
    drop(reopened);
    let mut reopened = fixture
        .store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
    let durable = service
        .refresh(reopened.as_mut(), &execution().context)
        .await
        .unwrap()
        .renewal
        .unwrap();
    assert_eq!(durable.renew_at, ari.renew_at);
    assert_eq!(durable.next_check_at, ari.next_check_at);
    assert_eq!(
        fs::read(generation.join("private-key.pk8")).unwrap(),
        key_bytes
    );
    let text = fs::read_to_string(generation.join("operation.toml")).unwrap();
    assert!(text.contains("[operation.renewal]"));
    assert!(text.contains("source = \"ari\""));
}

#[tokio::test]
async fn confirmed_revocation_is_durable_preserves_in_use_and_suppresses_renewal_queries() {
    use aster_acme::revocation::RevocationService;
    use aster_acme_core::revocation::RevocationState;
    use aster_acme_protocol::revocation::RevocationReason;
    let fixture = fixture().await;
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let mut record = session.record().await.unwrap();
    let slot = fixture.store.slot(&record.name);
    let generation = slot.join(record.generation_name());
    let chain = leaf_for(&generation, &record.identifiers);
    record.phase = IssuancePhase::Completed;
    let record = session.complete(&record, chain.as_bytes()).await.unwrap();
    let key_before = fs::read(generation.join("private-key.pk8")).unwrap();
    Mock::given(method("GET")).and(path("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce":format!("{}/nonce",fixture.server.uri()),"newAccount":format!("{}/unused",fixture.server.uri()),
            "revokeCert":format!("{}/vendor/revoke",fixture.server.uri()),"renewalInfo":format!("{}/ari",fixture.server.uri())
        }))).with_priority(1).mount(&fixture.server).await;
    Mock::given(method("POST"))
        .and(path("/vendor/revoke"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "revoked"))
        .expect(1)
        .mount(&fixture.server)
        .await;
    let client = Arc::new(
        aster_acme::transport::HttpPool::default()
            .discover(
                record.directory.clone(),
                TransportOptions {
                    allow_loopback_http: true,
                    ..TransportOptions::default()
                },
            )
            .await
            .unwrap(),
    );
    let accounts =
        super::super::CliAccountStore::open(fixture.temp.path(), "default", Duration::from_secs(1))
            .unwrap();
    let signer = accounts
        .signer(&record.directory, "default", KeyAccess::Existing)
        .await
        .unwrap();
    let service = RevocationService::new(
        client.clone(),
        IssueIdentity {
            account: fixture.account.clone(),
            signer,
        },
    );
    service
        .revoke(session.as_mut(), Some(RevocationReason::Superseded))
        .await
        .unwrap();
    drop(session);
    let mut reopened = fixture
        .store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
    let durable = reopened.record().await.unwrap();
    assert_eq!(durable.revocation.state, RevocationState::Confirmed);
    assert_eq!(
        durable.revocation.reason,
        Some(RevocationReason::Superseded)
    );
    assert!(durable.revocation.confirmed_at.is_some());
    service.revoke(reopened.as_mut(), None).await.unwrap();
    aster_acme::renewal::RenewalService::new(client)
        .refresh(reopened.as_mut(), &execution().context)
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(generation.join("fullchain.pem")).unwrap(),
        chain
    );
    assert_eq!(
        fs::read(generation.join("private-key.pk8")).unwrap(),
        key_before
    );
    assert_eq!(
        selected_view(&slot),
        PathBuf::from(record.generation_name())
    );
    let calls = fixture.server.received_requests().await.unwrap();
    assert!(
        calls
            .iter()
            .all(|request| !request.url.path().starts_with("/ari/"))
    );
    assert!(
        fixture
            .service
            .run(reopened.as_mut(), &Dns(true), &execution())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn certificate_removal_deletes_all_generations_keeps_lock_and_account_without_http() {
    use crate::state_file::tests::file_identity;
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let mut record = session.record().await.unwrap();
    let slot = fixture.store.slot(&record.name);
    let generation = slot.join(record.generation_name());
    let chain = leaf_for(&generation, &record.identifiers);
    record.phase = IssuancePhase::Completed;
    session.complete(&record, chain.as_bytes()).await.unwrap();
    drop(session);
    let other = fixture
        .store
        .renew(&request().name, &fixture.account)
        .await
        .unwrap();
    let other_record = other.record().await.unwrap();
    drop(other);
    let lock_path = toml_file::object_lock(
        &fixture.store.root,
        toml_file::ObjectKind::Certificate,
        record.name.as_str(),
    )
    .unwrap();
    let inode = file_identity(&lock_path);
    let account_path = fixture.temp.path().join("accounts/default/account.toml");
    let account_before = fs::read(&account_path).unwrap();
    let removal = fixture
        .store
        .prepare_removal(&record.name, removal::RemovalScope::All)
        .await
        .unwrap();
    assert_eq!(removal.generations(), 2);
    assert_eq!(removal.name(), &record.name);
    removal.remove().await.unwrap();
    assert_eq!(fixture.store.list().await.unwrap().len(), 0);
    assert!(!generation.exists());
    assert!(!slot.join(other_record.generation_name()).exists());
    assert!(!slot.join("in_use").exists());
    assert!(!slot.join("cert.toml").exists());
    assert!(!slot.join(".removing").exists());
    assert_eq!(file_identity(&lock_path), inode);
    assert_eq!(fs::read(account_path).unwrap(), account_before);
    assert_eq!(fixture.server.received_requests().await.unwrap().len(), 1);
    // Retaining the lock carrier permits a later explicit fresh issuance.
    let new = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    assert_ne!(
        new.record().await.unwrap().operation_id,
        record.operation_id
    );
}

#[cfg(unix)]
#[tokio::test]
async fn certificate_removal_preserves_extra_content_in_place_and_never_follows_unknown_links() {
    use std::os::unix::fs::symlink;
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let record = session.record().await.unwrap();
    drop(session);
    let slot = fixture.store.slot(&record.name);
    let generation = slot.join(record.generation_name());
    fs::write(slot.join("notes.txt"), "keep root").unwrap();
    fs::write(generation.join("notes.txt"), "keep generation").unwrap();
    fs::create_dir(slot.join("user-data")).unwrap();
    let external = fixture.temp.path().join("external.txt");
    fs::write(&external, "untouched").unwrap();
    symlink(&external, generation.join("user-link")).unwrap();
    fixture
        .store
        .prepare_removal(&record.name, removal::RemovalScope::All)
        .await
        .unwrap()
        .remove()
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(slot.join("notes.txt")).unwrap(),
        "keep root"
    );
    assert_eq!(
        fs::read_to_string(generation.join("notes.txt")).unwrap(),
        "keep generation"
    );
    assert!(slot.join("user-data").is_dir());
    assert_eq!(
        fs::read_link(generation.join("user-link")).unwrap(),
        external
    );
    assert_eq!(fs::read_to_string(external).unwrap(), "untouched");
    assert!(!generation.join("operation.toml").exists());
    assert!(!generation.join("private-key.pk8").exists());
    assert_eq!(fixture.store.list().await.unwrap().len(), 0);
}

#[tokio::test]
async fn removal_drop_missing_target_and_lock_contention_leave_saved_material_unchanged() {
    let fixture = fixture().await;
    let missing = CertificateName::new("missing.example").unwrap();
    assert!(
        fixture
            .store
            .prepare_removal(&missing, removal::RemovalScope::All)
            .await
            .is_err()
    );
    assert!(!fixture.store.slot(&missing).exists());
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let record = session.record().await.unwrap();
    let generation = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name());
    let key = fs::read(generation.join("private-key.pk8")).unwrap();
    assert!(
        fixture
            .store
            .prepare_removal(&record.name, removal::RemovalScope::All)
            .await
            .is_err()
    );
    drop(session);
    let removal = fixture
        .store
        .prepare_removal(&record.name, removal::RemovalScope::All)
        .await
        .unwrap();
    assert!(
        fixture
            .store
            .open(&record.name, &record.operation_id)
            .await
            .is_err()
    );
    drop(removal); // Rejected/cancelled confirmation only releases the lease.
    assert_eq!(fs::read(generation.join("private-key.pk8")).unwrap(), key);
    assert_eq!(fixture.store.list().await.unwrap().len(), 1);
    fixture
        .store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn removal_rejects_unsafe_managed_files_links_and_interrupted_markers_before_deleting() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for case in 0..6 {
        let fixture = fixture().await;
        let session = fixture
            .store
            .create(&request(), &fixture.account)
            .await
            .unwrap();
        let record = session.record().await.unwrap();
        drop(session);
        let slot = fixture.store.slot(&record.name);
        let generation = slot.join(record.generation_name());
        let key = generation.join("private-key.pk8");
        let metadata = fs::read(slot.join("cert.toml")).unwrap();
        let external = fixture.temp.path().join("outside");
        fs::write(&external, "keep").unwrap();
        match case {
            0 => {
                fs::remove_file(&key).unwrap();
                symlink(&external, &key).unwrap();
            }
            1 => fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap(),
            2 => {
                fs::remove_file(&key).unwrap();
                fs::create_dir(&key).unwrap();
            }
            3 => symlink(&external, slot.join("in_use")).unwrap(),
            4 => fs::write(slot.join("in_use"), "user owned").unwrap(),
            5 => fs::create_dir(slot.join(".removing")).unwrap(),
            _ => unreachable!(),
        }
        assert!(
            fixture
                .store
                .prepare_removal(&record.name, removal::RemovalScope::All)
                .await
                .is_err()
        );
        assert_eq!(fs::read(slot.join("cert.toml")).unwrap(), metadata);
        assert_eq!(fs::read_to_string(&external).unwrap(), "keep");
        assert!(generation.join("operation.toml").is_file());
        if case == 5 {
            assert!(
                fixture
                    .store
                    .create(&request(), &fixture.account)
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test]
async fn removal_can_delete_corrupt_key_bytes_without_generating_or_decoding_a_key() {
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let record = session.record().await.unwrap();
    drop(session);
    let generation = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name());
    fs::write(
        generation.join("private-key.pk8"),
        b"corrupt but safely owned",
    )
    .unwrap();
    fixture
        .store
        .prepare_removal(&record.name, removal::RemovalScope::All)
        .await
        .unwrap()
        .remove()
        .await
        .unwrap();
    assert!(!generation.exists());
}

#[tokio::test]
async fn removal_cleanup_failure_retains_marker_and_blocks_reusing_leftover_generations() {
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let record = session.record().await.unwrap();
    drop(session);
    let slot = fixture.store.slot(&record.name);
    let key = slot.join(record.generation_name()).join("private-key.pk8");
    let removal = fixture
        .store
        .prepare_removal(&record.name, removal::RemovalScope::All)
        .await
        .unwrap();
    // Inject a filesystem change after preflight; deletion must fail without recursion.
    fs::remove_file(&key).unwrap();
    fs::create_dir(&key).unwrap();
    fs::write(key.join("user.txt"), "retain").unwrap();
    assert!(removal.remove().await.is_err());
    assert!(slot.join(".removing").is_dir());
    assert_eq!(fs::read_to_string(key.join("user.txt")).unwrap(), "retain");
    assert!(
        fixture
            .store
            .create(&request(), &fixture.account)
            .await
            .is_err()
    );
}

async fn completed_generation(fixture: &Fixture) -> IssueRecord {
    let session = if fixture.store.list().await.unwrap().is_empty() {
        fixture
            .store
            .create(&request(), &fixture.account)
            .await
            .unwrap()
    } else {
        fixture
            .store
            .renew(&request().name, &fixture.account)
            .await
            .unwrap()
    };
    let mut record = session.record().await.unwrap();
    let generation = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name());
    let chain = leaf_for(&generation, &record.identifiers);
    record.phase = IssuancePhase::Completed;
    session.complete(&record, chain.as_bytes()).await.unwrap()
}

#[cfg(unix)]
#[tokio::test]
async fn single_historical_removal_preserves_in_use_unfinished_requests_and_other_links() {
    use removal::RemovalScope;
    use std::os::unix::fs::symlink;
    let fixture = fixture().await;
    let old = completed_generation(&fixture).await;
    let in_use = completed_generation(&fixture).await;
    let pending = fixture
        .store
        .renew(&request().name, &fixture.account)
        .await
        .unwrap();
    let pending_record = pending.record().await.unwrap();
    drop(pending);
    let slot = fixture.store.slot(&old.name);
    let in_use_link = selected_view(&slot);
    let config = fs::read(slot.join("cert.toml")).unwrap();
    let in_use_temp = slot.join(format!(".in_use-{}", in_use.operation_id));
    let old_temp = slot.join(format!(".in_use-{}", old.operation_id));
    symlink(in_use.generation_name(), &in_use_temp).unwrap();
    symlink(old.generation_name(), &old_temp).unwrap();
    let removal = fixture
        .store
        .prepare_removal(&old.name, RemovalScope::Operation(old.operation_id.clone()))
        .await
        .unwrap();
    assert_eq!(removal.generations(), 1);
    assert!(!removal.removes_in_use());
    removal.remove().await.unwrap();
    assert!(!slot.join(old.generation_name()).exists());
    assert!(!old_temp.exists());
    assert_eq!(
        fs::read_link(in_use_temp).unwrap(),
        PathBuf::from(in_use.generation_name())
    );
    assert_eq!(selected_view(&slot), in_use_link);
    assert_eq!(fs::read(slot.join("cert.toml")).unwrap(), config);
    let remaining = fixture.store.list().await.unwrap();
    assert_eq!(remaining.len(), 2);
    assert!(
        remaining
            .iter()
            .any(|r| r.operation_id == in_use.operation_id && r.is_in_use)
    );
    assert!(
        remaining
            .iter()
            .any(|r| r.operation_id == pending_record.operation_id && !r.is_in_use)
    );
}

#[tokio::test]
async fn removing_in_use_clears_selection_without_promoting_any_historical_version() {
    use removal::RemovalScope;
    let fixture = fixture().await;
    let old = completed_generation(&fixture).await;
    let in_use = completed_generation(&fixture).await;
    let slot = fixture.store.slot(&in_use.name);
    let removal = fixture
        .store
        .prepare_removal(
            &in_use.name,
            RemovalScope::Operation(in_use.operation_id.clone()),
        )
        .await
        .unwrap();
    assert!(removal.removes_in_use());
    removal.remove().await.unwrap();
    assert!(fs::symlink_metadata(slot.join("in_use")).is_err());
    assert!(selection(&slot).unwrap().cert.in_use.is_none());
    assert!(
        slot.join(old.generation_name())
            .join("private-key.pk8")
            .exists()
    );
    assert!(!slot.join(in_use.generation_name()).exists());
    let remaining = fixture.store.list().await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert!(!remaining[0].is_in_use);
    fixture
        .store
        .prepare_removal(&old.name, RemovalScope::Operation(old.operation_id.clone()))
        .await
        .unwrap()
        .remove()
        .await
        .unwrap();
    assert!(!slot.join("cert.toml").exists());
    assert_eq!(fixture.store.list().await.unwrap().len(), 0);
}

#[tokio::test]
async fn history_cleanup_preserves_in_use_pending_and_is_repeatable_without_side_effects() {
    use removal::RemovalScope;
    let fixture = fixture().await;
    let old = completed_generation(&fixture).await;
    let other_old = completed_generation(&fixture).await;
    let in_use = completed_generation(&fixture).await;
    let session = fixture
        .store
        .renew(&request().name, &fixture.account)
        .await
        .unwrap();
    let pending = session.record().await.unwrap();
    drop(session);
    let slot = fixture.store.slot(&in_use.name);
    let config = fs::read(slot.join("cert.toml")).unwrap();
    let in_use_key = fs::read(slot.join(in_use.generation_name()).join("private-key.pk8")).unwrap();
    let removal = fixture
        .store
        .prepare_removal(&in_use.name, RemovalScope::History)
        .await
        .unwrap();
    assert_eq!(removal.generations(), 2);
    assert!(!removal.removes_in_use());
    removal.remove().await.unwrap();
    for old in [old, other_old] {
        assert!(!slot.join(old.generation_name()).exists());
    }
    assert_eq!(fs::read(slot.join("cert.toml")).unwrap(), config);
    assert_eq!(
        fs::read(slot.join(in_use.generation_name()).join("private-key.pk8")).unwrap(),
        in_use_key
    );
    assert!(
        slot.join(pending.generation_name())
            .join("private-key.pk8")
            .exists()
    );
    let empty = fixture
        .store
        .prepare_removal(&in_use.name, RemovalScope::History)
        .await
        .unwrap();
    assert_eq!(empty.generations(), 0);
    empty.remove().await.unwrap();
    assert!(!slot.join(".removing").exists());
    assert_eq!(fixture.store.list().await.unwrap().len(), 2);
}

#[tokio::test]
async fn history_without_consistent_in_use_and_unknown_operation_delete_nothing() {
    use removal::RemovalScope;
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let pending = session.record().await.unwrap();
    drop(session);
    assert!(
        fixture
            .store
            .prepare_removal(&pending.name, RemovalScope::History)
            .await
            .is_err()
    );
    assert!(
        fixture
            .store
            .prepare_removal(&pending.name, RemovalScope::Operation("missing".into()))
            .await
            .is_err()
    );
    let in_use = completed_generation(&fixture).await;
    let slot = fixture.store.slot(&in_use.name);
    fs::remove_file(slot.join("in_use")).unwrap();
    assert!(
        fixture
            .store
            .prepare_removal(&in_use.name, RemovalScope::History)
            .await
            .is_err()
    );
    assert_eq!(fixture.store.list().await.unwrap().len(), 2);
    assert!(
        slot.join(in_use.generation_name())
            .join("private-key.pk8")
            .exists()
    );
    assert!(!slot.join(".removing").exists());
}

#[tokio::test]
async fn revoked_cleanup_matches_only_confirmed_versions_and_can_clear_revoked_in_use() {
    use aster_acme_core::revocation::RevocationState;
    use removal::RemovalScope;
    let fixture = fixture().await;
    let valid = completed_generation(&fixture).await;
    let uncertain = completed_generation(&fixture).await;
    let revoked = completed_generation(&fixture).await;
    for (record, state) in [
        (&uncertain, RevocationState::Pending),
        (&revoked, RevocationState::Confirmed),
    ] {
        let session = fixture
            .store
            .open(&record.name, &record.operation_id)
            .await
            .unwrap();
        let mut saved = session.record().await.unwrap();
        saved.revocation.state = state;
        session.save(&saved).await.unwrap();
    }
    let slot = fixture.store.slot(&revoked.name);
    let cleanup = fixture
        .store
        .prepare_removal(&revoked.name, RemovalScope::Revoked)
        .await
        .unwrap();
    assert_eq!(cleanup.generations(), 1);
    assert!(cleanup.removes_in_use());
    cleanup.remove().await.unwrap();
    assert!(!slot.join(revoked.generation_name()).exists());
    assert!(
        slot.join(uncertain.generation_name())
            .join("private-key.pk8")
            .exists()
    );
    assert!(
        slot.join(valid.generation_name())
            .join("private-key.pk8")
            .exists()
    );
    assert!(selection(&slot).unwrap().cert.in_use.is_none());
    assert!(fs::symlink_metadata(slot.join("in_use")).is_err());
    let no_op = fixture
        .store
        .prepare_removal(&revoked.name, RemovalScope::Revoked)
        .await
        .unwrap();
    assert_eq!(no_op.generations(), 0);
    no_op.remove().await.unwrap();
    assert!(!slot.join(".removing").exists());
}

#[tokio::test]
async fn revoked_cleanup_preserves_unrevoked_in_use_and_incomplete_requests() {
    use aster_acme_core::revocation::RevocationState;
    use removal::RemovalScope;
    let fixture = fixture().await;
    let revoked = completed_generation(&fixture).await;
    let session = fixture
        .store
        .open(&revoked.name, &revoked.operation_id)
        .await
        .unwrap();
    let mut saved = session.record().await.unwrap();
    saved.revocation.state = RevocationState::Confirmed;
    session.save(&saved).await.unwrap();
    drop(session);
    let in_use = completed_generation(&fixture).await;
    let session = fixture
        .store
        .renew(&request().name, &fixture.account)
        .await
        .unwrap();
    let pending = session.record().await.unwrap();
    drop(session);
    let cleanup = fixture
        .store
        .prepare_removal(&in_use.name, RemovalScope::Revoked)
        .await
        .unwrap();
    assert!(!cleanup.removes_in_use());
    cleanup.remove().await.unwrap();
    let slot = fixture.store.slot(&in_use.name);
    assert_eq!(
        selected_view(&slot),
        PathBuf::from(in_use.generation_name())
    );
    assert!(
        slot.join(pending.generation_name())
            .join("private-key.pk8")
            .exists()
    );
    assert_eq!(fixture.store.list().await.unwrap().len(), 2);
}

#[tokio::test]
async fn new_managed_name_is_exclusive_and_duplicate_new_issue_preserves_definition_and_keys() {
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let record = session.record().await.unwrap();
    let slot = fixture.store.slot(&record.name);
    let key_path = slot.join(record.generation_name()).join("private-key.pk8");
    let key = fs::read(&key_path).unwrap();
    let definition = fs::read(slot.join("cert.toml")).unwrap();
    drop(session);
    assert!(
        matches!(fixture.store.create(&request(),&fixture.account).await,Err(IssueError::NameAlreadyExists(name)) if name==record.name)
    );
    assert_eq!(fs::read(slot.join("cert.toml")).unwrap(), definition);
    assert_eq!(fs::read(&key_path).unwrap(), key);
    assert_eq!(fixture.store.list().await.unwrap().len(), 1);
    let mut other = request();
    other.name = CertificateName::new("example.com-other").unwrap();
    fixture
        .store
        .create(&other, &fixture.account)
        .await
        .unwrap();
    assert_eq!(fixture.store.list().await.unwrap().len(), 2);
}

#[tokio::test]
async fn concurrent_new_issue_claims_exactly_one_managed_name_under_the_certificate_lock() {
    let fixture = fixture().await;
    let store = Arc::new(CliIssueStore::new(
        fixture.temp.path().into(),
        Duration::from_secs(3),
    ));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let store = store.clone();
        let account = fixture.account.clone();
        handles.push(tokio::spawn(async move {
            match store.create(&request(), &account).await {
                Ok(session) => {
                    let record = session.record().await.unwrap();
                    drop(session);
                    Ok(record.operation_id)
                }
                Err(error) => Err(error),
            }
        }));
    }
    let mut created = 0;
    let mut collisions = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => created += 1,
            Err(IssueError::NameAlreadyExists(_)) => collisions += 1,
            Err(error) => panic!("unexpected allocation error: {error}"),
        }
    }
    assert_eq!((created, collisions), (1, 1));
    assert_eq!(store.list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn renewed_generation_keeps_the_managed_definition_and_rejects_changed_account_bindings() {
    let fixture = fixture().await;
    let initial = completed_generation(&fixture).await;
    let slot = fixture.store.slot(&initial.name);
    let definition = fs::read(slot.join("cert.toml")).unwrap();
    let old_key = fs::read(slot.join(initial.generation_name()).join("private-key.pk8")).unwrap();
    let session = fixture
        .store
        .renew(&initial.name, &fixture.account)
        .await
        .unwrap();
    let next = session.record().await.unwrap();
    assert_eq!(next.name, initial.name);
    assert_eq!(next.identifiers, initial.identifiers);
    assert_eq!(next.account_name, initial.account_name);
    assert_eq!(next.account_id, initial.account_id);
    assert_ne!(next.operation_id, initial.operation_id);
    assert!(!next.is_in_use);
    assert_eq!(fs::read(slot.join("cert.toml")).unwrap(), definition);
    assert_ne!(
        fs::read(slot.join(next.generation_name()).join("private-key.pk8")).unwrap(),
        old_key
    );
    drop(session);
    for change in ["account", "directory"] {
        let mut other = fixture.account.clone();
        match change {
            "account" => other.account_id = "another".into(),
            _ => other.directory_url = AcmeUrl::new("https://other.example/directory").unwrap(),
        }
        assert!(fixture.store.renew(&initial.name, &other).await.is_err());
    }
    assert_eq!(fixture.store.list().await.unwrap().len(), 2);
    let config = selection(&slot).unwrap();
    assert_eq!(config.cert.identifiers, initial.identifiers);
    assert_eq!(config.cert.solver_id, "manual_dns");
}

#[tokio::test]
async fn certificate_algorithm_is_fixed_in_definition_journal_recovery_and_new_renewal_material() {
    use aster_acme::crypto::key_algorithm::KeyAlgorithm;
    for algorithm in KeyAlgorithm::ALL {
        let fixture = fixture().await;
        let mut requested = request();
        requested.key_algorithm = algorithm;
        let session = fixture
            .store
            .create(&requested, &fixture.account)
            .await
            .unwrap();
        let record = session.record().await.unwrap();
        assert_eq!(record.key_algorithm, algorithm);
        let generation = fixture
            .store
            .slot(&record.name)
            .join(record.generation_name());
        let key = fs::read(generation.join("private-key.pk8")).unwrap();
        let csr = fs::read(generation.join("request.der")).unwrap();
        algorithm.validate_key(&key).unwrap();
        let config = selection(&fixture.store.slot(&record.name)).unwrap();
        assert_eq!(config.cert.key_algorithm, algorithm);
        drop(session);
        let reopened = fixture
            .store
            .open(&record.name, &record.operation_id)
            .await
            .unwrap();
        assert_eq!(reopened.record().await.unwrap().key_algorithm, algorithm);
        assert_eq!(reopened.csr().await.unwrap(), csr);
        let mut mutated = record.clone();
        mutated.key_algorithm = match algorithm {
            KeyAlgorithm::EcdsaP256 => KeyAlgorithm::EcdsaP384,
            _ => KeyAlgorithm::EcdsaP256,
        };
        assert!(reopened.save(&mutated).await.is_err());
        let mut issued = record.clone();
        let chain = leaf_for(&generation, &record.identifiers);
        issued.phase = IssuancePhase::Completed;
        reopened.complete(&issued, chain.as_bytes()).await.unwrap();
        drop(reopened);
        // Preparing a renewal uses the existing key choice, with new fixed material.
        let renewed = fixture
            .store
            .renew(&record.name, &fixture.account)
            .await
            .unwrap();
        let next = renewed.record().await.unwrap();
        assert_eq!(next.key_algorithm, algorithm);
        let next_key = fs::read(
            fixture
                .store
                .slot(&next.name)
                .join(next.generation_name())
                .join("private-key.pk8"),
        )
        .unwrap();
        algorithm.validate_key(&next_key).unwrap();
        assert_ne!(key, next_key);
        assert_ne!(renewed.csr().await.unwrap(), csr);
    }
}

#[tokio::test]
async fn recovery_refuses_key_algorithm_mismatch_even_when_material_digest_is_unchanged() {
    use aster_acme::crypto::key_algorithm::KeyAlgorithm;
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let mut record = session.record().await.unwrap();
    let path = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name())
        .join("operation.toml");
    drop(session);
    record.key_algorithm = KeyAlgorithm::Rsa2048;
    write_journal(&path, &record).unwrap();
    assert!(
        fixture
            .store
            .open(&record.name, &record.operation_id)
            .await
            .is_err()
    );
    assert!(
        fixture
            .store
            .renew(&record.name, &fixture.account)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejected_fixed_csr_survives_restart_even_when_another_request_completes_the_same_order() {
    use aster_acme::crypto::key_algorithm::KeyAlgorithm;
    use aster_acme_protocol::problem::ProblemKind;
    let fixture = fixture().await;
    let stage = mount_flow(&fixture).await;
    // Skip authorizing only in this fixture: the CA reports an already-ready order.
    stage.store(2, Ordering::SeqCst);
    let mut requested = request();
    requested.key_algorithm = KeyAlgorithm::EcdsaP521;
    let mut session = fixture
        .store
        .create(&requested, &fixture.account)
        .await
        .unwrap();
    let initial = session.record().await.unwrap();
    let generation = fixture
        .store
        .slot(&initial.name)
        .join(initial.generation_name());
    let key = fs::read(generation.join("private-key.pk8")).unwrap();
    let csr = fs::read(generation.join("request.der")).unwrap();
    Mock::given(method("POST"))
        .and(path("/finalize/custom"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("Replay-Nonce", "rejected")
                .set_body_json(
                    serde_json::json!({"type":ProblemKind::BadCsr,"detail":"ECDSA curve P-521 not allowed"}),
                ),
        )
        .expect(1)
        .mount(&fixture.server)
        .await;
    let error = fixture
        .service
        .run(session.as_mut(), &Dns(true), &execution())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(error,IssueError::Transport(ref error) if error.is_problem(&ProblemKind::BadCsr))
    );
    let rejected = session.record().await.unwrap();
    assert_eq!(
        rejected
            .finalize_rejection
            .as_ref()
            .unwrap()
            .detail
            .as_deref(),
        Some("ECDSA curve P-521 not allowed")
    );
    drop(session);
    complete_shared_order_with_p384(&fixture, stage, rejected.order_url.as_ref().unwrap()).await;
    let requests_before = fixture.server.received_requests().await.unwrap().len();
    let mut restarted = fixture
        .store
        .open(&initial.name, &initial.operation_id)
        .await
        .unwrap();
    let error = fixture
        .service
        .run(restarted.as_mut(), &Dns(true), &execution())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(error,IssueError::Transport(crate_error) if matches!(&crate_error,aster_acme::transport::TransportError::Problem {status:400,problem,..} if problem.kind==ProblemKind::BadCsr && problem.detail.as_deref()==Some("ECDSA curve P-521 not allowed")))
    );
    assert_eq!(
        fixture.server.received_requests().await.unwrap().len(),
        requests_before
    );
    assert_eq!(fs::read(generation.join("private-key.pk8")).unwrap(), key);
    assert_eq!(fs::read(generation.join("request.der")).unwrap(), csr);
    assert!(!generation.join("fullchain.pem").exists());
    assert!(
        selection(&fixture.store.slot(&initial.name))
            .unwrap()
            .cert
            .in_use
            .is_none()
    );
}

// Model a second client operation winning finalization of a CA-reused order.
async fn complete_shared_order_with_p384(
    fixture: &Fixture,
    stage: Arc<AtomicUsize>,
    expected_order: &AcmeUrl,
) {
    use aster_acme::crypto::key_algorithm::KeyAlgorithm;
    // A second managed certificate receives the identical CA order URL and succeeds.
    let mut other = request();
    other.name = CertificateName::new("another-cert").unwrap();
    other.key_algorithm = KeyAlgorithm::EcdsaP384;
    let mut second = fixture
        .store
        .create(&other, &fixture.account)
        .await
        .unwrap();
    let second_record = second.record().await.unwrap();
    let second_generation = fixture
        .store
        .slot(&second_record.name)
        .join(second_record.generation_name());
    let chain = leaf_for(&second_generation, &second_record.identifiers);
    let next_stage = stage.clone();
    let valid = order(&fixture.server, "valid", Some("2099-01-01T00:00:00Z"));
    Mock::given(method("POST"))
        .and(path("/finalize/custom"))
        .respond_with(move |_: &wiremock::Request| {
            next_stage.store(3, Ordering::SeqCst);
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "other_finalized")
                .insert_header("Retry-After", "0")
                .set_body_json(valid.clone())
        })
        .with_priority(1)
        .expect(1)
        .mount(&fixture.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/certificate"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "certificate")
                .set_body_raw(chain, "application/pem-certificate-chain"),
        )
        .expect(1)
        .mount(&fixture.server)
        .await;
    // mount_creation expects one request; override it for the second independent identity.
    Mock::given(method("POST"))
        .and(path("/vendor/create"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("Replay-Nonce", "same_order")
                .insert_header("Location", format!("{}/order/custom", fixture.server.uri()))
                .set_body_json(order(
                    &fixture.server,
                    "ready",
                    Some("2099-01-01T00:00:00Z"),
                )),
        )
        .with_priority(1)
        .expect(1)
        .mount(&fixture.server)
        .await;
    let outcome = fixture
        .service
        .run(second.as_mut(), &Dns(true), &execution())
        .await
        .unwrap();
    let IssueOutcome::Completed {
        record: completed, ..
    } = outcome
    else {
        panic!("second request should complete")
    };
    assert_eq!(completed.order_url.as_ref(), Some(expected_order));
    drop(second);
}

async fn renewal_client(fixture: &Fixture, ari: bool) -> Arc<IssueService> {
    Mock::given(method("GET")).and(path("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce":format!("{}/nonce",fixture.server.uri()),"newAccount":format!("{}/unused",fixture.server.uri()),
            "newOrder":format!("{}/vendor/create",fixture.server.uri()),"renewalInfo":ari.then(||format!("{}/renewal-info",fixture.server.uri()))
        }))).with_priority(1).mount(&fixture.server).await;
    let client = aster_acme::transport::HttpPool::default()
        .discover(
            fixture.account.directory_url.clone(),
            TransportOptions {
                allow_loopback_http: true,
                ..TransportOptions::default()
            },
        )
        .await
        .unwrap();
    let accounts =
        super::super::CliAccountStore::open(fixture.temp.path(), "default", Duration::from_secs(1))
            .unwrap();
    let signer = accounts
        .signer(
            &fixture.account.directory_url,
            "default",
            KeyAccess::Existing,
        )
        .await
        .unwrap();
    Arc::new(
        IssueService::new(
            Arc::new(client),
            IssueIdentity {
                account: fixture.account.clone(),
                signer,
            },
        )
        .unwrap(),
    )
}

async fn mount_renewal_order(fixture: &Fixture, replacement: Option<String>, chain: String) {
    let valid = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let expected = replacement.clone();
    let mut ready = order(&fixture.server, "ready", Some("2099-01-01T00:00:00Z"));
    let mut issued = order(&fixture.server, "valid", Some("2099-01-01T00:00:00Z"));
    if let Some(replaces) = &replacement {
        ready["replaces"] = serde_json::json!(replaces);
        issued["replaces"] = serde_json::json!(replaces);
    }
    let created = ready.clone();
    Mock::given(method("POST"))
        .and(path("/vendor/create"))
        .respond_with(move |request: &wiremock::Request| {
            let jws: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
            let payload: serde_json::Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
            assert_eq!(
                payload.get("replaces").and_then(serde_json::Value::as_str),
                expected.as_deref()
            );
            ResponseTemplate::new(201)
                .insert_header("Replay-Nonce", "renewal_created")
                .insert_header(
                    "Location",
                    created["finalize"]
                        .as_str()
                        .unwrap()
                        .replace("/finalize/custom", "/order/renewal"),
                )
                .insert_header("Retry-After", "0")
                .set_body_json(created.clone())
        })
        .expect(1)
        .mount(&fixture.server)
        .await;
    let observed = valid.clone();
    let ready_poll = ready.clone();
    let valid_poll = issued.clone();
    Mock::given(method("POST"))
        .and(path("/order/renewal"))
        .respond_with(move |_: &wiremock::Request| {
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "renewal_poll")
                .insert_header("Retry-After", "0")
                .set_body_json(if observed.load(Ordering::SeqCst) {
                    valid_poll.clone()
                } else {
                    ready_poll.clone()
                })
        })
        .mount(&fixture.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/finalize/custom"))
        .respond_with(move |_: &wiremock::Request| {
            valid.store(true, Ordering::SeqCst);
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "renewal_finalized")
                .insert_header("Retry-After", "0")
                .set_body_json(issued.clone())
        })
        .expect(1)
        .mount(&fixture.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/certificate"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "renewed_cert")
                .set_body_raw(chain, "application/pem-certificate-chain"),
        )
        .expect(1)
        .mount(&fixture.server)
        .await;
}

#[tokio::test]
async fn scheduled_renewal_keeps_name_definition_and_promotes_new_key_with_and_without_ari() {
    for ari in [false, true] {
        let fixture = fixture().await;
        let in_use = completed_generation(&fixture).await;
        let slot = fixture.store.slot(&in_use.name);
        let old_key =
            fs::read(slot.join(in_use.generation_name()).join("private-key.pk8")).unwrap();
        assert!(matches!(
            fixture
                .store
                .prepare_renewal(&in_use.name, &in_use.operation_id, false, &fixture.account)
                .await,
            Ok(RenewalPreparation::NotDue(_))
        ));
        assert_eq!(fixture.store.list().await.unwrap().len(), 1);
        let RenewalPreparation::Ready(session) = fixture
            .store
            .prepare_renewal(&in_use.name, &in_use.operation_id, true, &fixture.account)
            .await
            .unwrap()
        else {
            panic!("renewal session expected")
        };
        let record = session.record().await.unwrap();
        let previous = record.renewal_of.as_ref().unwrap();
        assert_eq!(previous.operation_id, in_use.operation_id);
        assert_eq!(record.name, in_use.name);
        let chain = leaf_for(&slot.join(record.generation_name()), &record.identifiers);
        mount_renewal_order(
            &fixture,
            if ari {
                previous.certificate_id.clone()
            } else {
                None
            },
            chain,
        )
        .await;
        drop(session);
        // A subsequent command, even without --now, resumes the same durable operation.
        let RenewalPreparation::Ready(mut resumed) = fixture
            .store
            .prepare_renewal(&in_use.name, &in_use.operation_id, false, &fixture.account)
            .await
            .unwrap()
        else {
            panic!("renewal session expected")
        };
        assert_eq!(
            resumed.record().await.unwrap().operation_id,
            record.operation_id
        );
        assert_eq!(
            selected_view(&slot),
            PathBuf::from(in_use.generation_name())
        );
        let service = renewal_client(&fixture, ari).await;
        let result = service
            .run(resumed.as_mut(), &Dns(true), &execution())
            .await
            .unwrap();
        let IssueOutcome::Completed {
            record: completed, ..
        } = result
        else {
            panic!("expected completed renewal")
        };
        assert_eq!(completed.name, in_use.name);
        assert_eq!(completed.identifiers, in_use.identifiers);
        assert_eq!(completed.key_algorithm, in_use.key_algorithm);
        assert_eq!(
            selected_view(&slot),
            PathBuf::from(record.generation_name())
        );
        assert_eq!(
            fs::read(slot.join(in_use.generation_name()).join("private-key.pk8")).unwrap(),
            old_key
        );
        assert_ne!(
            fs::read(slot.join(record.generation_name()).join("private-key.pk8")).unwrap(),
            old_key
        );
        assert_eq!(fixture.store.list().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn scheduled_renewal_checks_due_time_stale_in_use_and_revocation_before_creating_material() {
    use aster_acme_core::revocation::RevocationState;
    let fixture = fixture().await;
    let in_use = completed_generation(&fixture).await;
    assert!(
        fixture
            .store
            .prepare_renewal(&in_use.name, "stale", true, &fixture.account)
            .await
            .is_err()
    );
    let session = fixture
        .store
        .open(&in_use.name, &in_use.operation_id)
        .await
        .unwrap();
    let mut saved = session.record().await.unwrap();
    saved.revocation.state = RevocationState::Pending;
    session.save(&saved).await.unwrap();
    drop(session);
    assert!(
        fixture
            .store
            .prepare_renewal(&in_use.name, &in_use.operation_id, true, &fixture.account)
            .await
            .is_err()
    );
    let session = fixture
        .store
        .open(&in_use.name, &in_use.operation_id)
        .await
        .unwrap();
    let mut saved = session.record().await.unwrap();
    saved.revocation.state = RevocationState::NotRequested;
    saved.renewal.as_mut().unwrap().renew_at =
        time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
    session.save(&saved).await.unwrap();
    drop(session);
    let RenewalPreparation::Ready(renewal) = fixture
        .store
        .prepare_renewal(&in_use.name, &in_use.operation_id, false, &fixture.account)
        .await
        .unwrap()
    else {
        panic!("renewal session expected")
    };
    assert!(renewal.record().await.unwrap().renewal_of.is_some());
    assert_eq!(fixture.store.list().await.unwrap().len(), 2);
}

#[tokio::test]
async fn interrupted_manual_renewal_retains_old_in_use_and_resumes_the_same_order_and_material() {
    let fixture = fixture().await;
    let in_use = completed_generation(&fixture).await;
    let slot = fixture.store.slot(&in_use.name);
    let stage = mount_flow(&fixture).await;
    let RenewalPreparation::Ready(mut session) = fixture
        .store
        .prepare_renewal(&in_use.name, &in_use.operation_id, true, &fixture.account)
        .await
        .unwrap()
    else {
        panic!("renewal session expected")
    };
    let initial = session.record().await.unwrap();
    let generation = slot.join(initial.generation_name());
    let key = fs::read(generation.join("private-key.pk8")).unwrap();
    let csr = fs::read(generation.join("request.der")).unwrap();
    let outcome = fixture
        .service
        .run(session.as_mut(), &Dns(false), &execution())
        .await
        .unwrap();
    assert!(matches!(outcome, IssueOutcome::ActionRequired { .. }));
    assert_eq!(stage.load(Ordering::SeqCst), 0);
    drop(session);
    let RenewalPreparation::Ready(mut restored) = fixture
        .store
        .prepare_renewal(&in_use.name, &in_use.operation_id, false, &fixture.account)
        .await
        .unwrap()
    else {
        panic!("renewal session expected")
    };
    assert_eq!(
        restored.record().await.unwrap().operation_id,
        initial.operation_id
    );
    let cancelled = execution();
    cancelled.context.cancellation.cancel();
    assert!(matches!(
        fixture
            .service
            .run(restored.as_mut(), &Dns(true), &cancelled)
            .await,
        Err(IssueError::Interrupted)
    ));
    assert_eq!(
        selected_view(&slot),
        PathBuf::from(in_use.generation_name())
    );
    assert_eq!(fs::read(generation.join("private-key.pk8")).unwrap(), key);
    assert_eq!(restored.csr().await.unwrap(), csr);
    assert_eq!(fixture.store.list().await.unwrap().len(), 2);
    assert_eq!(
        fixture
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/vendor/create")
            .count(),
        1
    );
}

#[tokio::test]
async fn renewal_rejects_missing_or_changed_replaces_echo_without_redoing_new_order() {
    for echo in [None, Some("different.identifier")] {
        let fixture = fixture().await;
        let in_use = completed_generation(&fixture).await;
        let RenewalPreparation::Ready(mut session) = fixture
            .store
            .prepare_renewal(&in_use.name, &in_use.operation_id, true, &fixture.account)
            .await
            .unwrap()
        else {
            panic!("renewal session expected")
        };
        let record = session.record().await.unwrap();
        let mut created = order(&fixture.server, "ready", Some("2099-01-01T00:00:00Z"));
        if let Some(echo) = echo {
            created["replaces"] = serde_json::json!(echo);
        }
        mount_creation(&fixture, created.clone()).await;
        Mock::given(method("POST"))
            .and(path("/order/custom"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Replay-Nonce", "query")
                    .insert_header("Retry-After", "0")
                    .set_body_json(created),
            )
            .expect(1)
            .mount(&fixture.server)
            .await;
        let service = renewal_client(&fixture, true).await;
        assert!(
            service
                .run(session.as_mut(), &Dns(true), &execution())
                .await
                .is_err()
        );
        let saved = session.record().await.unwrap();
        assert!(saved.order_url.is_some());
        assert!(saved.submitted_replaces.is_some());
        drop(session);
        let RenewalPreparation::Ready(mut session) = fixture
            .store
            .prepare_renewal(&in_use.name, &in_use.operation_id, false, &fixture.account)
            .await
            .unwrap()
        else {
            panic!("renewal session expected")
        };
        assert_eq!(
            session.record().await.unwrap().operation_id,
            record.operation_id
        );
        assert!(
            service
                .run(session.as_mut(), &Dns(true), &execution())
                .await
                .is_err()
        );
        assert_eq!(
            selected_view(&fixture.store.slot(&in_use.name)),
            PathBuf::from(in_use.generation_name())
        );
    }
}

#[tokio::test]
async fn failed_renewal_cannot_promote_an_old_result_after_in_use_changes() {
    let fixture = fixture().await;
    let first = completed_generation(&fixture).await;
    let RenewalPreparation::Ready(session) = fixture
        .store
        .prepare_renewal(&first.name, &first.operation_id, true, &fixture.account)
        .await
        .unwrap()
    else {
        panic!("renewal session expected")
    };
    let mut pending = session.record().await.unwrap();
    drop(session);
    // Simulate an independent replacement already selected by a previous executor.
    let slot = fixture.store.slot(&first.name);
    let mut config = selection(&slot).unwrap();
    config.cert.in_use = None;
    write_selection(&slot, &config).unwrap();
    let session = fixture
        .store
        .open(&pending.name, &pending.operation_id)
        .await
        .unwrap();
    let generation = slot.join(pending.generation_name());
    let chain = leaf_for(&generation, &pending.identifiers);
    pending.phase = IssuancePhase::Completed;
    assert!(session.complete(&pending, chain.as_bytes()).await.is_err());
    assert!(!generation.join("fullchain.pem").exists());
    assert!(selection(&slot).unwrap().cert.in_use.is_none());
}

#[tokio::test]
async fn complete_removal_cleans_object_directories_and_keeps_shared_lock_inodes_stable() {
    use crate::state_file::tests::file_identity;
    let fixture = fixture().await;
    let session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let record = session.record().await.unwrap();
    drop(session);
    let lock = toml_file::object_lock(
        &fixture.store.root,
        toml_file::ObjectKind::Certificate,
        record.name.as_str(),
    )
    .unwrap();
    let inode = file_identity(&lock);
    fixture
        .store
        .prepare_removal(&record.name, removal::RemovalScope::All)
        .await
        .unwrap()
        .remove()
        .await
        .unwrap();
    assert!(!fixture.store.slot(&record.name).exists());
    assert_eq!(file_identity(&lock), inode);
    drop(
        fixture
            .store
            .create(&request(), &fixture.account)
            .await
            .unwrap(),
    );
    assert_eq!(file_identity(&lock), inode);
}

fn selected_view(slot: &Path) -> PathBuf {
    let target = publication::NATIVE
        .target(&slot.join("in_use"))
        .unwrap()
        .unwrap();
    let record = read_journal(&slot.join(&target).join("operation.toml")).unwrap();
    assert_eq!(record.generation_name(), target);
    assert!(publication::NATIVE.matches(slot, &record).unwrap());
    PathBuf::from(target)
}
