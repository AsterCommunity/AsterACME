//! Real CLI solver + file journals + loopback CA, without public DNS/CA side effects.
use crate::commands::cert::validation::tests::flow::*;
use aster_acme::crypto::{AccountSigner as _, key::AccountKey, key_algorithm::KeyAlgorithm};

#[tokio::test]
async fn dns_persist_initial_setup_restart_and_unattended_renewal_keep_exact_txt_after_rollover() {
    let mut fixture = Fixture::new(ValidationMethod::DnsPersist).await;
    let first = fixture.run(true).await.unwrap();
    let IssueOutcome::ActionRequired { records, record } = first else {
        panic!("expected setup");
    };
    assert_eq!(records.len(), 1);
    let ValidationRequirement::DnsPersist01 {
        record: publication,
    } = &records[0]
    else {
        panic!("expected persistent TXT");
    };
    assert_eq!(publication.name.as_str(), "_validation-persist.example.com");
    assert!(
        publication
            .value
            .starts_with("authority.example; accounturi=https://ca.example/account-hash/sha-256/")
    );
    assert!(
        !publication
            .value
            .contains(fixture.account.account_url.as_ref().unwrap().as_str())
    );
    assert!(
        record
            .authorizations
            .iter()
            .all(|auth| !auth.cleanup_pending)
    );
    assert_eq!(fixture.count("/persist-challenge").await, 0);
    assert_eq!(fixture.count("/account/1").await, 1);
    let first_key =
        std::fs::read(fixture.generation.lock().unwrap().join("private-key.pk8")).unwrap();
    let first_csr = fixture.session.as_ref().unwrap().csr().await.unwrap();
    fixture.reopen().await;
    let IssueOutcome::Completed { record, cleanup } = fixture.run(true).await.unwrap() else {
        panic!("expected issued certificate");
    };
    assert_eq!(cleanup, Vec::<ValidationRequirement>::new());
    assert_eq!(
        record.retained_validation_requirements(),
        vec![ValidationRequirement::DnsPersist01 {
            record: publication.clone()
        }]
    );
    assert_eq!(fixture.count("/orders/create").await, 1);
    assert_eq!(fixture.count("/persist-challenge").await, 1);
    assert_eq!(
        fixture.session.as_ref().unwrap().csr().await.unwrap(),
        first_csr
    );
    assert_eq!(
        std::fs::read(fixture.generation.lock().unwrap().join("private-key.pk8")).unwrap(),
        first_key
    );
    rotate_account_identity(&mut fixture).await;
    drop(fixture.session.take());
    let session = fixture
        .store
        .renew(&record.name, &fixture.account)
        .await
        .unwrap();
    let renewal = session.record().await.unwrap();
    assert_eq!(
        renewal.renewal_of.as_ref().unwrap().retained_validation,
        vec![ValidationRequirement::DnsPersist01 {
            record: publication.clone()
        }]
    );
    assert_ne!(renewal.account_thumbprint, record.account_thumbprint);
    *fixture.generation.lock().unwrap() = fixture
        .temp
        .path()
        .join("certs/web")
        .join(renewal.generation_name());
    fixture.session = Some(session);
    fixture.reopen().await;
    // No --yes and no TTY: only previously confirmed, unchanged publication is reused.
    let IssueOutcome::Completed {
        record: renewed,
        cleanup,
    } = fixture.run(false).await.unwrap()
    else {
        panic!("expected unattended renewal");
    };
    assert_eq!(cleanup, Vec::<ValidationRequirement>::new());
    assert_eq!(
        renewed.retained_validation_requirements(),
        vec![ValidationRequirement::DnsPersist01 {
            record: publication.clone()
        }]
    );
    assert_eq!(fixture.count("/orders/create").await, 2);
    assert_eq!(fixture.count("/persist-challenge").await, 2);
}

#[tokio::test]
async fn persistent_completion_reports_retention_and_no_cleanup_permission_in_text_and_json() {
    let mut fixture = Fixture::new(ValidationMethod::DnsPersist).await;
    assert!(matches!(
        fixture.run(true).await.unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    let IssueOutcome::Completed { record, cleanup } = fixture.run(true).await.unwrap() else {
        panic!("expected completion");
    };
    assert_eq!(cleanup, Vec::<ValidationRequirement>::new());
    let rendered = crate::commands::cert::render::outcome(
        &IssueOutcome::Completed {
            record: record.clone(),
            cleanup: vec![],
        },
        crate::common::session::Format::plain(false),
        fixture.temp.path(),
    )
    .unwrap();
    assert!(rendered.contains("Retain these persistent validation requirements"));
    assert!(!rendered.contains("You may remove"));
    let rendered = crate::commands::cert::render::outcome(
        &IssueOutcome::Completed { record, cleanup },
        crate::common::session::Format::plain(true),
        fixture.temp.path(),
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(json["records"], serde_json::json!([]));
    assert_eq!(
        json["operation"]["authorizations"][0]["validation_requirement"]["method"],
        "dns-persist-01"
    );
    assert!(
        json["operation"]["authorizations"][0]["validation_requirement"]["value"]
            .as_str()
            .unwrap()
            .contains("sha-256/")
    );
}

async fn rotate_account_identity(fixture: &mut Fixture) {
    let key = Arc::new(AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap());
    fixture.account.key_thumbprint = key.jwk().unwrap().thumbprint().unwrap();
    let client = HttpPool::default()
        .discover(
            fixture.account.directory_url.clone(),
            TransportOptions {
                allow_loopback_http: true,
                ..TransportOptions::default()
            },
        )
        .await
        .unwrap();
    fixture.service = IssueService::new(
        Arc::new(client),
        aster_acme::issuance::IssueIdentity {
            account: fixture.account.clone(),
            signer: key,
        },
    )
    .unwrap();
}

#[tokio::test]
async fn dns_persist_malformed_offers_and_failed_account_proof_never_publish_or_ack() {
    for (parameters, account_status) in [
        (serde_json::json!({}), "valid"),
        (
            serde_json::json!({"issuer-domain-names":["authority.example"]}),
            "valid",
        ),
        (serde_json::json!({"issuerDomainNames":[]}), "valid"),
        (
            serde_json::json!({"issuerDomainNames":["AUTHORITY.EXAMPLE"]}),
            "valid",
        ),
        (
            serde_json::json!({"issuerDomainNames":["unadvertised.example"]}),
            "valid",
        ),
        (
            serde_json::json!({"issuerDomainNames":["authority.example"]}),
            "deactivated",
        ),
    ] {
        let mut fixture = Fixture::new(ValidationMethod::DnsPersist).await;
        let mut challenge = parameters;
        challenge["type"] = serde_json::json!("dns-persist-01");
        challenge["url"] = serde_json::json!(format!("{}/persist-challenge", fixture.server.uri()));
        challenge["status"] = serde_json::json!("pending");
        Mock::given(method("POST")).and(path("/authorize"))
            .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "auth")
                .set_body_json(serde_json::json!({"identifier":{"type":"dns","value":"example.com"}, "status":"pending", "challenges":[challenge]})))
            .with_priority(1).mount(&fixture.server).await;
        Mock::given(method("POST"))
            .and(path("/account/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Replay-Nonce", "proof")
                    .set_body_json(serde_json::json!({"status":account_status})),
            )
            .with_priority(1)
            .mount(&fixture.server)
            .await;
        assert!(fixture.run(true).await.is_err());
        assert_eq!(fixture.count("/persist-challenge").await, 0);
        assert_eq!(fixture.count("/finalize").await, 0);
    }
}

#[tokio::test]
async fn dns_persist_ack_parameter_changes_are_uncertain_and_not_replayed() {
    let mut fixture = Fixture::new(ValidationMethod::DnsPersist).await;
    assert!(matches!(
        fixture.run(false).await.unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    Mock::given(method("POST")).and(path("/persist-challenge"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "changed")
            .set_body_json(serde_json::json!({"type":"dns-persist-01","status":"processing",
                "url":format!("{}/persist-challenge", fixture.server.uri()), "issuerDomainNames":["other.example"]})))
        .with_priority(1).mount(&fixture.server).await;
    assert!(fixture.run(true).await.is_err());
    assert_eq!(fixture.count("/persist-challenge").await, 1);
    fixture.reopen().await;
    let mut execution = IssueExecution {
        max_polls: 1,
        poll_interval: Duration::from_millis(1),
        context: execution(),
    };
    execution.context.deadline = Instant::now() + Duration::from_secs(3);
    let record = fixture.session.as_ref().unwrap().record().await.unwrap();
    let solver = adapter(&record, false, true, progress()).unwrap();
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
    assert_eq!(fixture.count("/persist-challenge").await, 1);
    assert_eq!(fixture.count("/finalize").await, 0);
}

#[tokio::test]
async fn dns_persist_changed_prefix_requires_manual_publication_and_account_retargeting_is_rejected()
 {
    let mut fixture = Fixture::new(ValidationMethod::DnsPersist).await;
    assert!(matches!(
        fixture.run(true).await.unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    let IssueOutcome::Completed { record, .. } = fixture.run(true).await.unwrap() else {
        panic!("expected completed setup");
    };
    drop(fixture.session.take());
    let mut retargeted = fixture.account.clone();
    retargeted.account_url =
        Some(AcmeUrl::new(&format!("{}/account/other", fixture.server.uri())).unwrap());
    assert!(
        fixture
            .store
            .renew(&record.name, &retargeted)
            .await
            .is_err()
    );
    let base = fixture.server.uri();
    Mock::given(method("GET")).and(path("/arbitrary-directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce":format!("{base}/nonce"), "newAccount":format!("{base}/account"), "newOrder":format!("{base}/orders/create"),
            "meta":{"issuerDomainNames":["authority.example"],"accountHashPrefix":"https://ca.example/new-prefix/"}
        }))).with_priority(1).mount(&fixture.server).await;
    rotate_account_identity(&mut fixture).await;
    let session = fixture
        .store
        .renew(&record.name, &fixture.account)
        .await
        .unwrap();
    let renewal = session.record().await.unwrap();
    *fixture.generation.lock().unwrap() = fixture
        .temp
        .path()
        .join("certs/web")
        .join(renewal.generation_name());
    fixture.session = Some(session);
    let IssueOutcome::ActionRequired { records, .. } = fixture.run(true).await.unwrap() else {
        panic!("new hash needs publication");
    };
    let ValidationRequirement::DnsPersist01 {
        record: publication,
    } = &records[0]
    else {
        panic!("expected TXT");
    };
    assert!(publication.value.contains("/new-prefix/sha-256/"));
    assert_eq!(fixture.count("/persist-challenge").await, 1);
    fixture.reopen().await;
    assert!(matches!(
        fixture.run(false).await.unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    assert_eq!(fixture.count("/persist-challenge").await, 1);
    assert!(matches!(
        fixture.run(true).await.unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(fixture.count("/persist-challenge").await, 2);
}

#[tokio::test]
async fn dns_persist_account_proof_rejects_redirects_http_errors_and_malformed_accounts() {
    for (status, body) in [
        (302, r#"{"status":"valid"}"#),
        (403, r#"{"status":"valid"}"#),
        (500, r#"{"status":"valid"}"#),
        (200, "not JSON"),
        (200, r#"{"status":"unknown"}"#),
    ] {
        let mut fixture = Fixture::new(ValidationMethod::DnsPersist).await;
        Mock::given(method("POST"))
            .and(path("/account/1"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Replay-Nonce", "proof")
                    .insert_header(
                        "Location",
                        format!("{}/redirected-account", fixture.server.uri()),
                    )
                    .set_body_raw(body, "application/json"),
            )
            .with_priority(1)
            .mount(&fixture.server)
            .await;
        assert!(fixture.run(true).await.is_err());
        assert_eq!(fixture.count("/redirected-account").await, 0);
        assert_eq!(fixture.count("/persist-challenge").await, 0);
        assert_eq!(fixture.count("/finalize").await, 0);
    }
}

#[tokio::test]
async fn dns_persist_missing_or_invalid_hash_prefix_fails_before_creating_remote_order() {
    for prefix in [
        serde_json::Value::Null,
        serde_json::json!(4),
        serde_json::json!("relative/"),
        serde_json::json!("https://ca.example/;policy=wildcard"),
    ] {
        let mut fixture = Fixture::new(ValidationMethod::DnsPersist).await;
        let base = fixture.server.uri();
        Mock::given(method("GET")).and(path("/arbitrary-directory"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "newNonce":format!("{base}/nonce"), "newAccount":format!("{base}/account"), "newOrder":format!("{base}/orders/create"),
                "meta":{"issuerDomainNames":["authority.example"],"accountHashPrefix":prefix}
            }))).with_priority(1).mount(&fixture.server).await;
        rotate_account_identity(&mut fixture).await;
        assert!(fixture.run(true).await.is_err());
        assert_eq!(fixture.count("/orders/create").await, 0);
        assert_eq!(fixture.count("/account/1").await, 0);
        assert!(
            !fixture
                .session
                .as_ref()
                .unwrap()
                .record()
                .await
                .unwrap()
                .new_order_intent_saved
        );
    }
}

struct PublicationLifecycle {
    inner: Box<dyn ChallengeSolver>,
    restored: Arc<AtomicUsize>,
    cleaned: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ChallengeSolver for PublicationLifecycle {
    fn kind(&self) -> ChallengeKind {
        self.inner.kind()
    }
    async fn restore(
        &self,
        requirements: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<(), IssueError> {
        self.restored.fetch_add(1, Ordering::SeqCst);
        self.inner.restore(requirements, execution).await
    }
    async fn ready(
        &self,
        requirements: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        self.inner.ready(requirements, execution).await
    }
    async fn cleanup(
        &self,
        requirements: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        self.cleaned.fetch_add(1, Ordering::SeqCst);
        self.inner.cleanup(requirements, execution).await
    }
    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

#[tokio::test]
async fn publication_lifetime_drives_restore_cleanup_and_completed_instructions() {
    for (method, callbacks) in [
        (ValidationMethod::ManualHttp, 1),
        (ValidationMethod::DnsPersist, 0),
    ] {
        let mut fixture = Fixture::new(method).await;
        assert!(matches!(
            fixture.run(true).await.unwrap(),
            IssueOutcome::ActionRequired { .. }
        ));
        fixture.reopen().await;
        let saved = fixture.session.as_ref().unwrap().record().await.unwrap();
        let restored = Arc::new(AtomicUsize::new(0));
        let cleaned = Arc::new(AtomicUsize::new(0));
        let solver = PublicationLifecycle {
            inner: adapter(&saved, false, true, progress()).unwrap(),
            restored: restored.clone(),
            cleaned: cleaned.clone(),
        };
        let controls = IssueExecution {
            max_polls: 30,
            poll_interval: Duration::from_millis(1),
            context: ExecutionContext {
                deadline: Instant::now() + Duration::from_secs(10),
                ..execution()
            },
        };
        let IssueOutcome::Completed { cleanup, .. } = fixture
            .service
            .run(
                fixture.session.as_mut().unwrap().as_mut(),
                &solver,
                &controls,
            )
            .await
            .unwrap()
        else {
            panic!("expected completion");
        };
        assert_eq!(restored.load(Ordering::SeqCst), callbacks);
        assert_eq!(cleaned.load(Ordering::SeqCst), callbacks);
        assert_eq!(cleanup.len(), callbacks);
    }
}

#[tokio::test]
async fn cancelled_persistent_publication_keeps_checkpoint_and_never_acknowledges() {
    let mut fixture = Fixture::new(ValidationMethod::DnsPersist).await;
    assert!(matches!(
        fixture.run(true).await.unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    let saved = fixture.session.as_ref().unwrap().record().await.unwrap();
    let csr = fixture.session.as_ref().unwrap().csr().await.unwrap();
    let solver = adapter(&saved, false, true, progress()).unwrap();
    let context = execution();
    context.cancellation.cancel();
    let controls = IssueExecution {
        max_polls: 30,
        poll_interval: Duration::from_millis(1),
        context,
    };
    assert!(matches!(
        fixture
            .service
            .run(
                fixture.session.as_mut().unwrap().as_mut(),
                solver.as_ref(),
                &controls
            )
            .await,
        Err(IssueError::Interrupted)
    ));
    assert_eq!(fixture.count("/persist-challenge").await, 0);
    assert_eq!(fixture.count("/orders/create").await, 1);
    assert_eq!(fixture.session.as_ref().unwrap().csr().await.unwrap(), csr);
    assert_eq!(
        fixture
            .session
            .as_ref()
            .unwrap()
            .record()
            .await
            .unwrap()
            .authorizations[0]
            .validation_requirement,
        saved.authorizations[0].validation_requirement
    );
}
