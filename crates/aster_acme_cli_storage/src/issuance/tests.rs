//! Loopback CA exercises real journals, fixed CSR and restartable foreground execution.
use super::*;
use aster_acme::identifier::DnsIdentifier;
use aster_acme::issuance::service::IssueService;
use aster_acme::{
    account::{AccountKeyStore, AccountStore},
    issuance::{DnsReadiness, DnsRequirement, IssueExecution, IssueIdentity, IssueOutcome},
    solver::ExecutionContext,
    transport::{AcmeClient, TransportOptions},
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
    let signer = accounts.signer(&directory, "default", true).await.unwrap();
    let thumb = signer.jwk().unwrap().thumbprint().unwrap();
    let mut account = accounts.load(&directory, &thumb).await.unwrap().unwrap();
    account.state = AccountRecordState::Registered;
    account.last_status = Some(AccountStatus::Valid);
    account.account_url = Some(AcmeUrl::new(&format!("{}/account/1", server.uri())).unwrap());
    accounts.save(&account).await.unwrap();
    let client = AcmeClient::discover(
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
        context: ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(5),
        },
        force: false,
        poll_interval: Duration::from_millis(100),
    }
}

struct Dns(bool);
#[async_trait]
impl DnsReadiness for Dns {
    async fn ready(
        &self,
        records: &[DnsRequirement],
        _force: bool,
        _execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].name, records[1].name);
        assert_ne!(records[0].value, records[1].value);
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
            .current,
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
    let mut execution = execution();
    execution.force = true;
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
        .create(&request(), &fixture.account)
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
async fn failed_artifact_checks_never_replace_current_certificate() {
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
    let current = selection(&fixture.store.slot(&record.name))
        .unwrap()
        .cert
        .current;
    let second = fixture
        .store
        .create(&request(), &fixture.account)
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
            .current,
        current
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
        assert!(authorization.dns.is_some());
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
impl DnsReadiness for DelayedPublication {
    async fn ready(
        &self,
        _records: &[DnsRequirement],
        _force: bool,
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
    let mut execution = execution();
    execution.force = true;
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
    assert!(matches!(observed[0], IssueEvent::CreatingOrder));
    assert!(matches!(observed[1], IssueEvent::OrderCreated { .. }));
    assert!(observed.iter().any(|event| matches!(
        event,
        IssueEvent::OrderObserved {
            status: aster_acme_core::protocol::OrderStatus::Pending
        }
    )));
    assert!(matches!(
        observed.last().unwrap(),
        IssueEvent::PublicationRequired { count: 2 }
    ));
    let formatted = format!("{observed:?}");
    for requirement in records {
        assert!(!formatted.contains(&requirement.value));
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
            .current,
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
async fn leaf_only_exports_empty_ca_and_failed_artifact_write_keeps_previous_current() {
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
        .create(&request(), &fixture.account)
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
            .current,
        Some(record.operation_id)
    );
    assert!(!matches!(
        second.record().await.unwrap().phase,
        IssuancePhase::Completed
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn current_link_atomically_selects_readable_generations_and_preserves_history() {
    use std::os::unix::fs::symlink;
    let fixture = fixture().await;
    let mut ids = Vec::new();
    let mut generations = Vec::new();
    for _ in 0..2 {
        let session = fixture
            .store
            .create(&request(), &fixture.account)
            .await
            .unwrap();
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
            slot.join(format!(".current-{}", record.operation_id)),
        )
        .unwrap();
        session.complete(&record, chain.as_bytes()).await.unwrap();
        assert_eq!(
            fs::read_link(slot.join("current")).unwrap(),
            PathBuf::from(record.generation_name())
        );
        assert_eq!(
            fs::read_to_string(slot.join("current/fullchain.pem")).unwrap(),
            chain
        );
        assert_eq!(
            fs::read(slot.join("current/private-key.pem")).unwrap(),
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
async fn current_promotion_refuses_foreign_targets_and_keeps_user_entries() {
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
    fs::write(slot.join("current"), b"user file").unwrap();
    assert!(session.complete(&record, chain.as_bytes()).await.is_err());
    assert_eq!(fs::read(slot.join("current")).unwrap(), b"user file");
    fs::remove_file(slot.join("current")).unwrap();
    symlink("../outside", slot.join("current")).unwrap();
    assert!(session.complete(&record, chain.as_bytes()).await.is_err());
    assert_eq!(
        fs::read_link(slot.join("current")).unwrap(),
        PathBuf::from("../outside")
    );
    fs::remove_file(slot.join("current")).unwrap();
    let pending = slot.join(format!(".current-{}", record.operation_id));
    fs::write(&pending, b"retain").unwrap();
    assert!(session.complete(&record, chain.as_bytes()).await.is_err());
    assert_eq!(fs::read(&pending).unwrap(), b"retain");
    assert!(selection(&slot).unwrap().cert.current.is_none());
}
