//! Managed revocation checkpoints, artifact preservation and execution eligibility.
use crate::issuance::tests::*;

#[tokio::test]
async fn confirmed_revocation_is_durable_preserves_in_use_and_suppresses_renewal_queries() {
    use aster_acme_core::revocation::RevocationState;
    use aster_acme_protocol::revocation::RevocationReason;
    let fixture = fixture().await;
    let record = completed_generation(&fixture).await;
    let (client, service) = revocation_service(&fixture).await;
    let mut session = fixture
        .store
        .open_revocation(&record.name, &record.operation_id)
        .await
        .unwrap();
    let slot = fixture.store.slot(&record.name);
    let generation = slot.join(record.generation_name());
    let chain = fs::read_to_string(generation.join("fullchain.pem")).unwrap();
    let key_before = fs::read(generation.join("private-key.pk8")).unwrap();
    service
        .revoke(
            &mut session,
            Some(RevocationReason::Superseded),
            &execution().context,
        )
        .await
        .unwrap();
    drop(session);
    let reopened = fixture
        .store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
    let durable = reopened.record().await.unwrap();
    assert_eq!(durable.revocation.state, RevocationState::Confirmed);
    let reason = Some(RevocationReason::Superseded);
    assert_eq!(durable.revocation.reason, reason);
    assert!(durable.revocation.confirmed_at.is_some());
    drop(reopened);
    let mut revocation = fixture
        .store
        .open_revocation(&record.name, &record.operation_id)
        .await
        .unwrap();
    service
        .revoke(&mut revocation, None, &execution().context)
        .await
        .unwrap();
    drop(revocation);
    let mut reopened = fixture
        .store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
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

async fn revocation_service(
    fixture: &Fixture,
) -> (
    Arc<aster_acme::transport::AcmeClient>,
    aster_acme::revocation::RevocationService,
) {
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
                fixture.account.directory_url.clone(),
                TransportOptions {
                    allow_loopback_http: true,
                    ..TransportOptions::default()
                },
            )
            .await
            .unwrap(),
    );
    let accounts = crate::account::CliAccountStore::open(
        fixture.temp.path(),
        "default",
        Duration::from_secs(1),
    )
    .unwrap();
    let signer = accounts
        .signer(
            &fixture.account.directory_url,
            "default",
            KeyAccess::Existing,
        )
        .await
        .unwrap();
    let service = aster_acme::revocation::RevocationService::new(
        client.clone(),
        aster_acme::revocation::authority::RevocationAuthority::Account {
            account: Arc::new(fixture.account.clone()),
            signer,
        },
    );
    (client, service)
}

#[tokio::test]
async fn revocation_certificate_lease_excludes_another_process_and_releases_on_drop() {
    let fixture = fixture().await;
    let record = completed_generation(&fixture).await;
    let session = fixture
        .store
        .open_revocation(&record.name, &record.operation_id)
        .await
        .unwrap();
    let root = fixture.temp.path().to_path_buf();
    let name = record.name.as_str().to_owned();
    let operation = record.operation_id.clone();
    let output = revocation_child(root.clone(), name.clone(), operation.clone(), true).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    drop(session);
    let output = revocation_child(root, name, operation, false).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn revocation_child(
    root: PathBuf,
    name: String,
    operation: String,
    held: bool,
) -> std::process::Output {
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "issuance::tests::revocation::cross_process_revocation_child",
                "--ignored",
                "--nocapture",
            ])
            .env("ASTER_REVOCATION_TEST_ROOT", root)
            .env("ASTER_REVOCATION_TEST_NAME", name)
            .env("ASTER_REVOCATION_TEST_OPERATION", operation)
            .env(
                "ASTER_REVOCATION_TEST_HELD",
                if held { "yes" } else { "no" },
            )
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "subprocess revocation lease fixture"]
async fn cross_process_revocation_child() {
    let store = CliIssueStore::new(
        PathBuf::from(std::env::var_os("ASTER_REVOCATION_TEST_ROOT").unwrap()),
        Duration::from_millis(100),
    );
    let name = CertificateName::new(&std::env::var("ASTER_REVOCATION_TEST_NAME").unwrap()).unwrap();
    let operation = std::env::var("ASTER_REVOCATION_TEST_OPERATION").unwrap();
    let held = std::env::var("ASTER_REVOCATION_TEST_HELD").unwrap() == "yes";
    let result = store.open_revocation(&name, &operation).await;
    if held {
        assert!(matches!(result, Err(IssueError::LeaseUnavailable(..))));
    } else {
        assert!(result.is_ok());
    }
}
