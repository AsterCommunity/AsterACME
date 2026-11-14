//! The composed entry point completes real generation storage using one fixed CSR.
use crate::issuance::tests::*;
use aster_acme::issuance::workflow::Workflow;

#[tokio::test]
async fn composed_workflow_discovers_resumes_and_commits_the_original_material() {
    let f = fixture().await;
    let stage = mount_flow(&f).await;
    let accounts =
        crate::account::CliAccountStore::open(f.temp.path(), "default", Duration::from_secs(1))
            .unwrap();
    let signer = accounts
        .signer(&f.account.directory_url, "default", KeyAccess::Existing)
        .await
        .unwrap();
    let identity = || IssueIdentity {
        account: f.account.clone(),
        signer: signer.clone(),
    };
    let workflow = Workflow::new(
        aster_acme::transport::HttpPool::default(),
        f.account.directory_url.clone(),
        TransportOptions {
            allow_loopback_http: true,
            ..TransportOptions::default()
        },
    )
    .unwrap();
    let mut session = f.store.create(&request(), &f.account).await.unwrap();
    assert!(matches!(
        workflow
            .run(identity(), session.as_mut(), &Dns(false), &execution())
            .await
            .unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    let saved = session.record().await.unwrap();
    let generation = f.store.slot(&saved.name).join(saved.generation_name());
    let key = fs::read(generation.join("private-key.pk8")).unwrap();
    let csr = fs::read(generation.join("request.der")).unwrap();
    let chain = leaf_for(&generation, &saved.identifiers);
    Mock::given(method("POST"))
        .and(path("/certificate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(chain.clone(), "application/pem-certificate-chain"),
        )
        .expect(1)
        .mount(&f.server)
        .await;
    let valid = order(&f.server, "valid", Some("2099-01-01T00:00:00Z"));
    let expected_csr = csr.clone();
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
            stage.store(3, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(valid.clone())
        })
        .expect(1)
        .mount(&f.server)
        .await;
    drop(session);
    let mut resumed = f
        .store
        .open(&saved.name, &saved.operation_id)
        .await
        .unwrap();
    assert!(matches!(
        workflow
            .run(identity(), resumed.as_mut(), &Dns(true), &execution())
            .await
            .unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(fs::read(generation.join("private-key.pk8")).unwrap(), key);
    assert_eq!(fs::read(generation.join("request.der")).unwrap(), csr);
    assert_eq!(
        fs::read(generation.join("fullchain.pem")).unwrap(),
        chain.as_bytes()
    );
    assert_eq!(
        selection(&f.store.slot(&saved.name)).unwrap().cert.in_use,
        Some(saved.operation_id)
    );
    assert_eq!(
        f.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/vendor/create")
            .count(),
        1
    );
}
