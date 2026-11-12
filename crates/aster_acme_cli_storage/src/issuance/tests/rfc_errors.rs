//! RFC 8555 error responses are evidence, not synthesized order states.
use crate::issuance::tests::*;
use aster_acme::crypto::AccountSigner as _;
use aster_acme_protocol::problem::ProblemKind;

fn assert_saved_response(
    error: IssueError,
    status: u16,
    kind: Option<ProblemKind>,
    body: &serde_json::Value,
) {
    match error {
        IssueError::Transport(aster_acme::transport::TransportError::Problem {
            status: actual,
            problem,
            retry_after,
        }) => {
            assert_eq!(actual, status);
            assert_eq!(problem.kind, kind.unwrap());
            assert!(retry_after.is_some());
            assert_eq!(
                serde_json::to_value(problem).unwrap(),
                serde_json::to_value(
                    serde_json::from_value::<aster_acme_protocol::problem::Problem>(body.clone())
                        .unwrap()
                )
                .unwrap()
            );
        }
        IssueError::Transport(aster_acme::transport::TransportError::HttpStatus {
            status: actual,
            ..
        }) => {
            assert_eq!(actual, status);
            assert!(kind.is_none());
        }
        other => panic!("unexpected error: {other}"),
    }
}

fn assert_creation_metadata(
    failure: &aster_acme::issuance::RequestFailure,
    custom: bool,
) -> time::OffsetDateTime {
    if custom {
        assert_eq!(
            serde_json::to_value(failure.problem.as_ref().unwrap()).unwrap()["extension"],
            "retained"
        );
    }
    assert!(
        failure.retry_at.unwrap() > time::OffsetDateTime::now_utc() + time::Duration::seconds(115)
    );
    failure.retry_at.unwrap()
}

#[tokio::test]
async fn new_order_error_matrix_is_persisted_losslessly_and_never_replayed() {
    for (status, kind) in [
        (400, Some(ProblemKind::RejectedIdentifier)),
        (400, Some(ProblemKind::UnsupportedIdentifier)),
        (400, Some(ProblemKind::Compound)),
        (403, Some(ProblemKind::Unauthorized)),
        (403, Some(ProblemKind::UserActionRequired)),
        (409, Some(ProblemKind::AlreadyReplaced)),
        (429, Some(ProblemKind::RateLimited)),
        (503, Some(ProblemKind::ServerInternal)),
        (
            400,
            Some(ProblemKind::Unknown("https://ca.example/custom".into())),
        ),
        (400, None),
    ] {
        let fixture = fixture().await;
        let expected_kind = kind
            .clone()
            .or_else(|| Some(ProblemKind::Unknown("about:blank".into())));
        let body = kind.as_ref().map_or_else(|| serde_json::json!({"unexpected":"body"}), |kind| serde_json::json!({"type":kind,"detail":"CA refusal","instance":"https://ca.example/action","subproblems":[{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"forbidden","identifier":{"type":"dns","value":"example.com"}}],"extension":"retained"}));
        Mock::given(method("POST"))
            .and(path("/vendor/create"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Replay-Nonce", "error")
                    .insert_header("Retry-After", "120")
                    .set_body_json(body.clone()),
            )
            .expect(1)
            .mount(&fixture.server)
            .await;
        let request = request();
        let mut session = fixture
            .store
            .create(&request, &fixture.account)
            .await
            .unwrap();
        let initial = session.record().await.unwrap();
        let generation = fixture
            .store
            .slot(&initial.name)
            .join(initial.generation_name());
        let key = fs::read(generation.join("private-key.pk8")).unwrap();
        let csr = fs::read(generation.join("request.der")).unwrap();
        assert!(
            fixture
                .service
                .run(session.as_mut(), &Dns(true), &execution())
                .await
                .is_err()
        );
        let saved = session.record().await.unwrap();
        let failure = saved.creation_failure.as_ref().unwrap();
        assert_eq!(failure.status, status);
        assert_eq!(
            failure.problem.as_ref().map(|p| &p.kind),
            expected_kind.as_ref()
        );
        let retry = assert_creation_metadata(failure, kind.is_some());
        assert!(saved.order.is_none());
        assert!(saved.order_url.is_none());
        assert!(!saved.resume_candidate());
        assert!(!saved.matches_unfinished_request(
            &request,
            &fixture.account,
            time::OffsetDateTime::now_utc()
        ));
        drop(session);
        let before = fixture.server.received_requests().await.unwrap().len();
        let mut reopened = fixture
            .store
            .open(&saved.name, &saved.operation_id)
            .await
            .unwrap();
        let error = fixture
            .service
            .run(reopened.as_mut(), &Dns(true), &execution())
            .await
            .err()
            .unwrap();
        assert_saved_response(error, status, expected_kind, &body);
        assert_eq!(
            fixture.server.received_requests().await.unwrap().len(),
            before
        );
        assert_eq!(
            reopened
                .record()
                .await
                .unwrap()
                .creation_failure
                .unwrap()
                .retry_at,
            Some(retry)
        );
        assert_eq!(fs::read(generation.join("private-key.pk8")).unwrap(), key);
        assert_eq!(fs::read(generation.join("request.der")).unwrap(), csr);
    }
}

#[tokio::test]
async fn bad_csr_uses_actual_non400_status_and_survives_restart() {
    let fixture = fixture().await;
    let stage = mount_flow(&fixture).await;
    stage.store(2, Ordering::SeqCst);
    Mock::given(method("POST"))
        .and(path("/finalize/custom"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("Replay-Nonce", "badcsr")
                .insert_header("Retry-After", "60")
                .set_body_json(
                    serde_json::json!({"type":ProblemKind::BadCsr,"detail":"CSR rejected"}),
                ),
        )
        .with_priority(1)
        .expect(1)
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
    let record = session.record().await.unwrap();
    let failure = record.finalize_rejection.as_ref().unwrap();
    assert_eq!(failure.status, 403);
    assert!(failure.retry_at.is_some());
    assert_eq!(failure.problem.as_ref().unwrap().kind, ProblemKind::BadCsr);
    assert!(!record.resume_candidate());
    drop(session);
    let mut reopened = fixture
        .store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .service
            .run(reopened.as_mut(), &Dns(true), &execution())
            .await,
        Err(IssueError::Transport(
            aster_acme::transport::TransportError::Problem { status: 403, .. }
        ))
    ));
}

#[tokio::test]
async fn order_not_ready_403_queries_order_before_resubmitting_and_respects_poll_budget() {
    for permanent in [false, true] {
        let fixture = fixture().await;
        let stage = mount_flow(&fixture).await;
        stage.store(2, Ordering::SeqCst);
        Mock::given(method("POST"))
            .and(path("/finalize/custom"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Replay-Nonce", "finalized")
                    .insert_header("Retry-After", "0")
                    .set_body_json(order(
                        &fixture.server,
                        "processing",
                        Some("2099-01-01T00:00:00Z"),
                    )),
            )
            .with_priority(2)
            .mount(&fixture.server)
            .await;
        let response = Mock::given(method("POST")).and(path("/finalize/custom"))
            .respond_with(ResponseTemplate::new(403).insert_header("Replay-Nonce", "notready").insert_header("Retry-After", "0").set_body_json(serde_json::json!({"type":ProblemKind::OrderNotReady,"detail":"not ready yet"})))
            .with_priority(1);
        if permanent {
            response.expect(2).mount(&fixture.server).await;
        } else {
            response
                .up_to_n_times(1)
                .expect(1)
                .mount(&fixture.server)
                .await;
        }
        let mut session = fixture
            .store
            .create(&request(), &fixture.account)
            .await
            .unwrap();
        let controls = IssueExecution {
            max_polls: 2,
            ..execution()
        };
        assert!(matches!(
            fixture
                .service
                .run(session.as_mut(), &Dns(true), &controls)
                .await,
            Err(IssueError::PollLimit { completed: 2, .. })
        ));
        let saved = session.record().await.unwrap();
        assert_eq!(
            saved.finalize_submitted,
            if permanent {
                aster_acme_core::workflow::SubmissionState::NotSubmitted
            } else {
                aster_acme_core::workflow::SubmissionState::Submitted
            }
        );
        assert!(saved.finalize_rejection.is_none());
        let requests = fixture.server.received_requests().await.unwrap();
        let sequence = requests
            .iter()
            .map(|request| request.url.path())
            .filter(|p| matches!(*p, "/order/custom" | "/finalize/custom"))
            .collect::<Vec<_>>();
        assert_eq!(
            sequence,
            [
                "/order/custom",
                "/finalize/custom",
                "/order/custom",
                "/finalize/custom"
            ]
        );
    }
}

#[tokio::test]
async fn finalize_transient_or_unknown_errors_do_not_authorize_replay() {
    for (status, kind) in [
        (503, ProblemKind::ServerInternal),
        (503, ProblemKind::BadCsr),
    ] {
        let fixture = fixture().await;
        let stage = mount_flow(&fixture).await;
        stage.store(2, Ordering::SeqCst);
        Mock::given(method("POST"))
            .and(path("/finalize/custom"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Replay-Nonce", "error")
                    .set_body_json(serde_json::json!({"type":kind,"detail":"retry later"})),
            )
            .with_priority(1)
            .expect(1)
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
        assert!(session.record().await.unwrap().finalize_rejection.is_none());
        assert!(matches!(
            fixture
                .service
                .run(
                    session.as_mut(),
                    &Dns(true),
                    &IssueExecution {
                        max_polls: 1,
                        ..execution()
                    }
                )
                .await,
            Err(IssueError::PollLimit { .. })
        ));
    }
}

#[tokio::test]
async fn terminal_authorization_and_selected_challenge_failures_keep_problem_and_block_resume() {
    for status in ["invalid", "deactivated", "expired", "revoked", "pending"] {
        let fixture = fixture().await;
        mount_flow(&fixture).await;
        let challenge_url = format!("{}/challenge/0", fixture.server.uri());
        Mock::given(method("POST")).and(path("/auth/0"))
            .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "failed").set_body_json(serde_json::json!({"identifier":{"type":"dns","value":"example.com"},"status":status,"expires":"2099-01-01T00:00:00Z","challenges":[{"type":"dns-01","url":challenge_url,"status":"invalid","token":"long-enough-opaque-token-0","error":{"type":ProblemKind::Dns,"detail":"TXT missing","subproblems":[{"type":ProblemKind::IncorrectResponse,"detail":"wrong value"}]}}]})))
            .with_priority(1).mount(&fixture.server).await;
        let mut session = fixture
            .store
            .create(&request(), &fixture.account)
            .await
            .unwrap();
        let error = fixture
            .service
            .run(session.as_mut(), &Dns(true), &execution())
            .await
            .err()
            .unwrap();
        let IssueError::AuthorizationFailed {
            status: actual,
            problem: Some(problem),
        } = error
        else {
            panic!("expected authorization failure");
        };
        assert_eq!(String::from(actual), status);
        assert_eq!(problem.kind, ProblemKind::Dns);
        assert_eq!(problem.detail.as_deref(), Some("TXT missing"));
        assert_eq!(problem.subproblems.len(), 1);
        let saved = session.record().await.unwrap();
        assert!(!saved.resume_candidate());
        assert!(saved.authorization_failure().is_some());
        assert!(!saved.matches_unfinished_request(
            &request(),
            &fixture.account,
            time::OffsetDateTime::now_utc()
        ));
        assert_eq!(
            saved.order.as_ref().unwrap().status,
            aster_acme_core::protocol::OrderStatus::Pending
        );
        assert!(saved.failure_problem().is_some());
        let mut history = saved.clone();
        history.order.as_mut().unwrap().status = aster_acme_core::protocol::OrderStatus::Valid;
        assert!(history.authorization_failure().is_none());
        history.order.as_mut().unwrap().status = aster_acme_core::protocol::OrderStatus::Pending;
        history.authorizations[0].resource.status =
            aster_acme_core::protocol::AuthorizationStatus::Valid;
        assert!(history.authorization_failure().is_none());
        history.authorizations[0].resource.status =
            aster_acme_core::protocol::AuthorizationStatus::Invalid;
        for challenge in &mut history.authorizations[0].resource.challenges {
            challenge.error = None;
        }
        assert!(matches!(
            history.authorization_failure(),
            Some(IssueError::AuthorizationFailed { problem: None, .. })
        ));
        drop(session);
        let before = fixture.server.received_requests().await.unwrap();
        assert!(
            !before
                .iter()
                .any(|r| r.url.path().starts_with("/challenge/")
                    || r.url.path() == "/finalize/custom")
        );
        let mut reopened = fixture
            .store
            .open(&saved.name, &saved.operation_id)
            .await
            .unwrap();
        assert!(matches!(
            fixture
                .service
                .run(reopened.as_mut(), &Dns(true), &execution())
                .await,
            Err(IssueError::AuthorizationFailed { .. })
        ));
        assert_eq!(
            fixture.server.received_requests().await.unwrap().len(),
            before.len()
        );
    }
}

#[tokio::test]
async fn rejected_acknowledgement_is_retryable_but_server_errors_remain_submitted() {
    for status in [403, 503] {
        let fixture = fixture().await;
        mount_flow(&fixture).await;
        Mock::given(method("POST"))
            .and(path("/challenge/0"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Replay-Nonce", "refused")
                    .set_body_json(
                        serde_json::json!({"type":ProblemKind::Unauthorized,"detail":"refused"}),
                    ),
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
        let saved = session.record().await.unwrap();
        assert_eq!(
            saved.authorizations[0].acknowledgement,
            if status == 403 {
                SubmissionState::NotSubmitted
            } else {
                SubmissionState::Submitted
            }
        );
        let before = saved.authorizations[0].validation.clone();
        if status == 403 {
            // The next explicit invocation reaches acknowledgement again with unchanged material.
            assert!(
                fixture
                    .service
                    .run(session.as_mut(), &Dns(true), &execution())
                    .await
                    .is_err()
            );
            assert_eq!(
                session.record().await.unwrap().authorizations[0].validation,
                before
            );
            assert_eq!(
                fixture
                    .server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .filter(|r| r.url.path() == "/challenge/0")
                    .count(),
                2
            );
        }
    }
}

#[tokio::test]
async fn chain_media_type_accepts_case_and_optional_whitespace() {
    let fixture = fixture().await;
    mount_flow(&fixture).await.store(3, Ordering::SeqCst);
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    let record = session.record().await.unwrap();
    let generation = fixture
        .store
        .slot(&record.name)
        .join(record.generation_name());
    let leaf = leaf_for(&generation, &record.identifiers);
    Mock::given(method("POST"))
        .and(path("/certificate"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "chain")
                .set_body_raw(leaf, "Application/PEM-Certificate-Chain ; charset=utf-8"),
        )
        .with_priority(1)
        .mount(&fixture.server)
        .await;
    assert!(matches!(
        fixture
            .service
            .run(session.as_mut(), &Dns(true), &execution())
            .await
            .unwrap(),
        IssueOutcome::Completed { .. }
    ));
}

#[tokio::test]
async fn rotated_account_signer_can_resume_saved_material_without_changing_its_thumbprint() {
    let fixture = fixture().await;
    mount_flow(&fixture).await;
    let mut session = fixture
        .store
        .create(&request(), &fixture.account)
        .await
        .unwrap();
    fixture
        .service
        .run(session.as_mut(), &Dns(false), &execution())
        .await
        .unwrap();
    let before = session.record().await.unwrap();
    let old_material = serde_json::to_value(&before.authorizations).unwrap();
    let new =
        Arc::new(aster_acme::crypto::key::AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap());
    let mut account = fixture.account.clone();
    account.key_thumbprint = new.jwk().unwrap().thumbprint().unwrap();
    let client = aster_acme::transport::HttpPool::default()
        .discover(
            account.directory_url.clone(),
            TransportOptions {
                allow_loopback_http: true,
                ..TransportOptions::default()
            },
        )
        .await
        .unwrap();
    let service = IssueService::new(
        Arc::new(client),
        IssueIdentity {
            account,
            signer: new,
        },
    )
    .unwrap();
    assert!(matches!(
        service
            .run(session.as_mut(), &Dns(false), &execution())
            .await
            .unwrap(),
        IssueOutcome::ActionRequired { .. }
    ));
    let after = session.record().await.unwrap();
    assert_eq!(after.account_thumbprint, before.account_thumbprint);
    assert_eq!(
        serde_json::to_value(after.authorizations).unwrap(),
        old_material
    );
}

#[tokio::test]
async fn rejected_acknowledgement_retry_after_survives_reopen_and_blocks_early_requests() {
    let http_date = time::format_description::parse_borrowed::<1>(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT",
    )
    .unwrap();
    for retry_after in [
        "120".to_owned(),
        (time::OffsetDateTime::now_utc() + time::Duration::seconds(120))
            .format(&http_date)
            .unwrap(),
    ] {
        let fixture = fixture().await;
        mount_flow(&fixture).await;
        Mock::given(method("POST"))
            .and(path("/challenge/0"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Replay-Nonce", "limited")
                    .insert_header("Retry-After", retry_after)
                    .set_body_json(serde_json::json!({"type": ProblemKind::RateLimited})),
            )
            .with_priority(1)
            .mount(&fixture.server)
            .await;
        let mut session = fixture
            .store
            .create(&request(), &fixture.account)
            .await
            .unwrap();
        let started = time::OffsetDateTime::now_utc();
        assert!(
            fixture
                .service
                .run(session.as_mut(), &Dns(true), &execution())
                .await
                .is_err()
        );
        let saved = session.record().await.unwrap();
        assert_eq!(
            saved.authorizations[0].acknowledgement,
            SubmissionState::NotSubmitted
        );
        assert!(saved.next_poll_at.unwrap() >= started + time::Duration::seconds(115));
        assert_eq!(
            saved.poll_wait_source,
            Some(aster_acme::issuance::PollWaitSource::RetryAfter)
        );
        drop(session);
        let before = fixture.server.received_requests().await.unwrap().len();
        let mut reopened = fixture
            .store
            .open(&saved.name, &saved.operation_id)
            .await
            .unwrap();
        let mut retry = execution();
        retry.context.deadline = Instant::now() + Duration::from_millis(100);
        assert!(
            fixture
                .service
                .run(reopened.as_mut(), &Dns(true), &retry)
                .await
                .is_err()
        );
        assert_eq!(
            fixture.server.received_requests().await.unwrap().len(),
            before
        );
        assert_eq!(
            reopened.record().await.unwrap().next_poll_at,
            saved.next_poll_at
        );
    }
}

#[tokio::test]
async fn definitive_finalize_refusals_reset_submission_and_preserve_retry_deadline() {
    for (status, kind) in [
        (429, ProblemKind::RateLimited),
        (403, ProblemKind::Unauthorized),
        (
            400,
            ProblemKind::Unknown("https://ca.example/custom".into()),
        ),
    ] {
        let fixture = fixture().await;
        mount_flow(&fixture).await.store(2, Ordering::SeqCst);
        Mock::given(method("POST"))
            .and(path("/finalize/custom"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Replay-Nonce", "refused")
                    .insert_header("Retry-After", "120")
                    .set_body_json(serde_json::json!({"type":kind})),
            )
            .with_priority(1)
            .expect(1)
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
        let saved = session.record().await.unwrap();
        assert_eq!(saved.finalize_submitted, SubmissionState::NotSubmitted);
        assert!(saved.finalize_rejection.is_none());
        assert!(
            saved.next_poll_at.unwrap()
                > time::OffsetDateTime::now_utc() + time::Duration::seconds(110)
        );
        drop(session);
        let before = fixture.server.received_requests().await.unwrap().len();
        let mut reopened = fixture
            .store
            .open(&saved.name, &saved.operation_id)
            .await
            .unwrap();
        let mut limits = execution();
        limits.context.deadline = Instant::now() + Duration::from_millis(100);
        assert!(
            fixture
                .service
                .run(reopened.as_mut(), &Dns(true), &limits)
                .await
                .is_err()
        );
        assert_eq!(
            fixture.server.received_requests().await.unwrap().len(),
            before
        );
    }
}
