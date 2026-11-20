//! Exercise the example's real adapters with temporary files and a loopback CA.
use crate::{
    ACCOUNT_NAME, EmbeddedAccountStore, EmbeddedIssueStore, EmbeddedWebroot, artifact_paths,
    display_terms, ensure_account,
};
use aster_acme::{
    account::AccountRecord,
    challenge::ChallengeKind,
    crypto::{key::SoftwareSigningKey, key_algorithm::KeyAlgorithm},
    identifier::Identifier,
    issuance::{
        CertificateName, IssueError, IssueExecution, IssueIdentity, IssueOutcome, IssueRequest,
        workflow::Workflow,
    },
    solver::ExecutionContext,
    storage::{
        account::{AccountKeyStore, AccountStore, KeyAccess},
        issuance::IssueStore,
        query::IssueQuery,
    },
    transport::TransportOptions,
};
use aster_acme_core::workflow::IssuancePhase;
use aster_acme_protocol::url::AcmeUrl;
use rcgen::{CertificateParams, Issuer, KeyPair};
use std::{
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn request() -> IssueRequest {
    IssueRequest {
        challenge: ChallengeKind::Http01,
        solver_id: "embedded-webroot".into(),
        solver_config: serde_json::json!({}),
        name: CertificateName::new("test-cert").unwrap(),
        identifiers: vec![Identifier::new("example.com").unwrap()],
        key_algorithm: KeyAlgorithm::default(),
        profile: None,
        account_name: ACCOUNT_NAME.into(),
    }
}

async fn account() -> AccountRecord {
    let store = EmbeddedAccountStore::default();
    let directory = AcmeUrl::new("https://ca.example/directory").unwrap();
    let signer = store
        .signer(&directory, ACCOUNT_NAME, KeyAccess::Create(None))
        .await
        .unwrap();
    let thumbprint = signer.jwk().unwrap().thumbprint().unwrap();
    let mut record = store.load(&directory, &thumbprint).await.unwrap().unwrap();
    record.account_url = Some(AcmeUrl::new("https://ca.example/account/1").unwrap());
    record
}

fn chain(key_der: &[u8], domain: &str) -> String {
    let key = KeyPair::try_from(key_der).unwrap();
    let issuer = Issuer::new(
        CertificateParams::new(Vec::new()).unwrap(),
        KeyPair::generate().unwrap(),
    );
    let mut params = CertificateParams::new(vec![domain.to_owned()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(89);
    params.signed_by(&key, &issuer).unwrap().pem()
}

#[tokio::test]
async fn account_key_is_stable_and_rejects_identity_changes() {
    // The key is stable for one directory and cannot be rebound to another CA identity.
    let store = EmbeddedAccountStore::default();
    let directory = AcmeUrl::new("https://ca.example/directory").unwrap();
    assert!(
        store
            .signer(&directory, ACCOUNT_NAME, KeyAccess::Existing)
            .await
            .is_err()
    );
    let signer = store
        .signer(&directory, ACCOUNT_NAME, KeyAccess::Create(None))
        .await
        .unwrap();
    let existing = store
        .signer(&directory, ACCOUNT_NAME, KeyAccess::Existing)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&signer, &existing));
    assert!(
        store
            .signer(
                &directory,
                ACCOUNT_NAME,
                KeyAccess::Create(Some(KeyAlgorithm::EcdsaP384))
            )
            .await
            .is_err()
    );
    let other_directory = AcmeUrl::new("https://other.example/directory").unwrap();
    assert!(
        store
            .signer(&other_directory, ACCOUNT_NAME, KeyAccess::Existing)
            .await
            .is_err()
    );
    let thumbprint = signer.jwk().unwrap().thumbprint().unwrap();
    let mut record = store.load(&directory, &thumbprint).await.unwrap().unwrap();
    let lease = store.lock_account(&directory, &thumbprint).await.unwrap();
    record.directory_url = other_directory;
    assert!(store.save(&record, &lease).await.is_err());
    assert!(store.load(&directory, &thumbprint).await.unwrap().is_some());
}

#[tokio::test]
async fn checkpoints_and_csr_survive_reopening_without_changing_the_definition() {
    // Reopening preserves the original CSR and checkpoint while rejecting edited request data.
    let temp = TempDir::new().unwrap();
    let store = EmbeddedIssueStore::new(temp.path().into());
    let request = request();
    let account = account().await;
    let session = store.create(&request, &account).await.unwrap();
    assert!(matches!(
        store.create(&request, &account).await,
        Err(IssueError::NameAlreadyExists(_))
    ));
    let csr = session.csr().await.unwrap();
    let mut record = session.record().await.unwrap();
    record.new_order_intent_saved = true;
    session.save(&record).await.unwrap();
    let reopened = store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
    assert_eq!(csr, reopened.csr().await.unwrap());
    assert!(reopened.record().await.unwrap().new_order_intent_saved);
    let mut changed = record.clone();
    changed.identifiers = vec![Identifier::new("other.example").unwrap()];
    assert!(reopened.save(&changed).await.is_err());
    assert_eq!(
        reopened.record().await.unwrap().identifiers,
        request.identifiers
    );
    assert!(store.open(&record.name, "missing").await.is_err());
    let saved = store
        .query(IssueQuery {
            name: Some(record.name),
            unfinished: Some(true),
            ..IssueQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(saved.len(), 1);
    assert!(saved[0].new_order_intent_saved);
}

#[tokio::test]
async fn promotion_validates_material_and_leaves_checkpoint_on_write_failure() {
    // Invalid chain/key/SAN data and failed publication must leave the saved phase retryable.
    let temp = TempDir::new().unwrap();
    let store = EmbeddedIssueStore::new(temp.path().into());
    let request = request();
    let session = store.create(&request, &account().await).await.unwrap();
    let mut record = session.record().await.unwrap();
    record.phase = IssuancePhase::Downloading;
    session.save(&record).await.unwrap();
    let (pem, wrong_san) = {
        let generations = store.generations.lock().unwrap();
        (
            chain(&generations[0].key, "example.com"),
            chain(&generations[0].key, "other.example"),
        )
    };
    record.phase = IssuancePhase::Completed;
    let wrong_key = SoftwareSigningKey::generate(KeyAlgorithm::default()).unwrap();
    let wrong_key_pem = chain(&wrong_key.to_pkcs8().unwrap(), "example.com");
    for invalid in [
        b"invalid PEM".as_slice(),
        wrong_san.as_bytes(),
        wrong_key_pem.as_bytes(),
    ] {
        assert!(session.complete(&record, invalid).await.is_err());
        assert!(!artifact_paths(temp.path(), &record.name).exists());
        assert_eq!(
            session.record().await.unwrap().phase,
            IssuancePhase::Downloading
        );
    }
    let blocker = temp.path().join("certs");
    std::fs::write(&blocker, b"prevent directory creation").unwrap();
    assert!(session.complete(&record, pem.as_bytes()).await.is_err());
    assert_eq!(
        session.record().await.unwrap().phase,
        IssuancePhase::Downloading
    );
    std::fs::remove_file(blocker).unwrap();
    let completed = session.complete(&record, pem.as_bytes()).await.unwrap();
    assert!(completed.is_in_use);
    assert!(completed.renewal.is_some());
    let output = artifact_paths(temp.path(), &record.name);
    assert_eq!(
        std::fs::read_to_string(output.join("cert.pem"))
            .unwrap()
            .replace("\r\n", "\n"),
        pem.replace("\r\n", "\n")
    );
    assert_eq!(
        std::fs::read_to_string(output.join("fullchain.pem"))
            .unwrap()
            .replace("\r\n", "\n"),
        pem.replace("\r\n", "\n")
    );
    assert_eq!(std::fs::read(output.join("ca.pem")).unwrap(), b"");
    assert!(
        std::fs::read_to_string(output.join("private-key.pem"))
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
    assert!(session.complete(&record, pem.as_bytes()).await.is_err());
    assert_eq!(
        std::fs::read_to_string(output.join("cert.pem"))
            .unwrap()
            .replace("\r\n", "\n"),
        pem.replace("\r\n", "\n")
    );
}

#[tokio::test]
async fn loopback_ca_drives_the_real_workflow_and_example_adapters_to_completion() {
    // Exercise the public workflow against a local CA-shaped server without external network use.
    let server = MockServer::start().await;
    let url = |suffix: &str| format!("{}{suffix}", server.uri());
    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce":url("/nonce"), "newAccount":url("/account"), "newOrder":url("/create")
        })))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "fresh"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/account"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Location", url("/account/1"))
                .set_body_json(serde_json::json!({"status":"valid","contact":[]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let directory = AcmeUrl::new(&url("/directory")).unwrap();
    let transport = TransportOptions {
        allow_loopback_http: true,
        ..TransportOptions::default()
    };
    let account_store = Arc::new(EmbeddedAccountStore::default());
    let (account, signer, pool) =
        ensure_account(&directory, transport.clone(), &account_store, Vec::new())
            .await
            .unwrap();
    let temp = TempDir::new().unwrap();
    let store = EmbeddedIssueStore::new(temp.path().into());
    let mut session = store.create(&request(), &account).await.unwrap();
    let pem = {
        let generations = store.generations.lock().unwrap();
        chain(&generations[0].key, "example.com")
    };
    let ready = serde_json::json!({
        "status":"ready", "expires":"2099-01-01T00:00:00Z",
        "identifiers":[{"type":"dns","value":"example.com"}],
        "authorizations":[], "finalize":url("/finalize")
    });
    Mock::given(method("POST"))
        .and(path("/create"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("Location", url("/order"))
                .set_body_json(ready.clone()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let valid = serde_json::json!({
        "status":"valid", "expires":"2099-01-01T00:00:00Z",
        "identifiers":[{"type":"dns","value":"example.com"}],
        "authorizations":[], "finalize":url("/finalize"), "certificate":url("/certificate")
    });
    Mock::given(method("POST"))
        .and(path("/finalize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ready.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let order_poll = Arc::new(AtomicUsize::new(0));
    let order_responses = order_poll.clone();
    Mock::given(method("POST"))
        .and(path("/order"))
        .respond_with(move |_request: &wiremock::Request| {
            let body = if order_responses.fetch_add(1, Ordering::SeqCst) == 0 {
                ready.clone()
            } else {
                valid.clone()
            };
            ResponseTemplate::new(200).set_body_json(body)
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/certificate"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "Content-Type",
                    "application/pem-certificate-chain; charset=utf-8",
                )
                .set_body_bytes(pem.as_bytes().to_vec()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let workflow = Workflow::new(pool, directory, transport).unwrap();
    let execution = IssueExecution {
        max_polls: 5,
        poll_interval: Duration::from_millis(1),
        context: ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(10),
        },
    };
    // The mock CA reuses prior authorizations, so no public challenge server is needed.
    let outcome = workflow
        .run(
            IssueIdentity { account, signer },
            session.as_mut(),
            &EmbeddedWebroot::new(temp.path().join("webroot")),
            &execution,
        )
        .await
        .unwrap();
    let IssueOutcome::Completed { record, .. } = outcome else {
        panic!("issuance did not complete")
    };
    assert!(record.is_in_use);
    assert!(record.renewal.is_some());
    assert_eq!(
        std::fs::read_to_string(artifact_paths(temp.path(), &record.name).join("fullchain.pem"))
            .unwrap()
            .replace("\r\n", "\n"),
        pem.replace("\r\n", "\n")
    );
    assert_eq!(
        session.record().await.unwrap().phase,
        IssuancePhase::Completed
    );
}

#[test]
fn term_display_escapes_terminal_controls_and_keeps_plain_values() {
    let plain = "data:text/plain,Do%20what%20thou%20wilt";
    assert_eq!(display_terms(plain), plain);
    assert_eq!(display_terms("none advertised"), "none advertised");
    let hostile = "data:text/plain,\u{1b}[2J\u{1b}[Hfake success\u{202e}evil";
    let rendered = display_terms(hostile);
    assert!(!rendered.chars().any(char::is_control));
    assert!(!rendered.contains('\u{202e}'));
    assert!(rendered.contains("\\u{1b}"));
}
