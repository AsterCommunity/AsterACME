//! Real account signatures, exact DER payloads and durable revocation failure boundaries.
use crate::crypto::key_algorithm::KeyAlgorithm;
use crate::revocation::*;
use crate::{
    account::AccountRecord,
    crypto::{AccountSigner, key::AccountKey},
    transport::TransportOptions,
};
use aster_acme_protocol::{jws::FlattenedJws, url::AcmeUrl};
use async_trait::async_trait;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::sync::Mutex;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct Session {
    record: Mutex<IssueRecord>,
    der: Vec<u8>,
    fail_save: AtomicBool,
    fail_confirmation: AtomicBool,
}

#[async_trait]
impl IssueSession for Session {
    async fn record(&self) -> Result<IssueRecord, IssueError> {
        Ok(self.record.lock().await.clone())
    }
    async fn save(&self, record: &IssueRecord) -> Result<(), IssueError> {
        if self.fail_save.load(Ordering::SeqCst)
            || (self.fail_confirmation.load(Ordering::SeqCst)
                && matches!(record.revocation.state, RevocationState::Confirmed))
        {
            return Err(IssueError::InvalidInput("injected journal write failure"));
        }
        *self.record.lock().await = record.clone();
        Ok(())
    }
    async fn certificate_der(&self) -> Result<Vec<u8>, IssueError> {
        Ok(self.der.clone())
    }
    async fn csr(&self) -> Result<Vec<u8>, IssueError> {
        Err(IssueError::InvalidInput("revocation must not load CSR"))
    }
    async fn complete(&self, _: &IssueRecord, _: &[u8]) -> Result<IssueRecord, IssueError> {
        Err(IssueError::InvalidInput("revocation must not promote"))
    }
    async fn record_renewal_failure(
        &self,
        _: time::OffsetDateTime,
        _: Option<time::OffsetDateTime>,
        _: Option<String>,
    ) -> Result<crate::issuance::RenewalRetryState, IssueError> {
        Err(IssueError::InvalidInput(
            "revocation must not schedule renewals",
        ))
    }
}

async fn fixture(endpoint: bool, timeout: Duration) -> (MockServer, RevocationService, Session) {
    let server = MockServer::start().await;
    let url = |path: &str| AcmeUrl::new(&format!("{}{path}", server.uri())).unwrap();
    Mock::given(method("GET")).and(path("/directory")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "newNonce":url("/nonce"),"newAccount":url("/unused"),"revokeCert":endpoint.then(||url("/vendor/revoke"))
    }))).mount(&server).await;
    Mock::given(method("HEAD"))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "fresh_nonce"))
        .mount(&server)
        .await;
    let client = crate::transport::HttpPool::default()
        .discover(
            url("/directory"),
            TransportOptions {
                allow_loopback_http: true,
                request_timeout: timeout,
                ..TransportOptions::default()
            },
        )
        .await
        .unwrap();
    let signer = Arc::new(AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap());
    let account:AccountRecord=serde_json::from_value(serde_json::json!({"key_algorithm":"ecdsa-p256",
        "account_id":"local-id","directory_url":url("/directory"),"account_url":url("/account/1"),
        "key_thumbprint":signer.jwk().unwrap().thumbprint().unwrap(),"contacts":[],"server_contacts":null,
        "last_status":"valid","deactivation":"not_requested","key_rotation":null,"accepted_terms_url":null,"state":"registered"
    })).unwrap();
    let record:IssueRecord=serde_json::from_value(serde_json::json!({
        "key_algorithm":"ecdsa-p256","challenge":"dns-01","solver_config":{},"solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"example.com",
        "created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"local-id","account_thumbprint":account.key_thumbprint,
        "directory":url("/directory"),"account_url":url("/account/1"),"identifiers":["example.com"],
        "phase":"completed","new_order_intent_saved":true,"order_url":url("/order/1"),"finalize_submitted":"submitted","authorizations":[]
    })).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["example.com".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (
        server,
        RevocationService::new(Arc::new(client), IssueIdentity { account, signer }),
        Session {
            record: Mutex::new(record),
            der: leaf.der().to_vec(),
            fail_save: AtomicBool::new(false),
            fail_confirmation: AtomicBool::new(false),
        },
    )
}

#[tokio::test]
async fn revoke_signs_exact_leaf_der_and_reason_and_confirmed_repeat_is_local() {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
    Mock::given(method("POST"))
        .and(path("/vendor/revoke"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "after_revoke"))
        .expect(1)
        .mount(&server)
        .await;
    let record = service
        .revoke(
            &mut session,
            Some(aster_acme_protocol::revocation::RevocationReason::KeyCompromise),
        )
        .await
        .unwrap();
    assert_eq!(record.revocation.state, RevocationState::Confirmed);
    assert_eq!(
        record.revocation.reason,
        Some(aster_acme_protocol::revocation::RevocationReason::KeyCompromise)
    );
    assert!(record.revocation.requested_at.is_some());
    assert!(record.revocation.confirmed_at.is_some());
    service
        .revoke(
            &mut session,
            Some(aster_acme_protocol::revocation::RevocationReason::Superseded),
        )
        .await
        .unwrap(); // Confirmed result does not revoke again.
    let requests = server.received_requests().await.unwrap();
    let request = requests
        .iter()
        .find(|request| request.method == "POST")
        .unwrap();
    let jws: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&jws.protected).unwrap()).unwrap();
    assert_eq!(header["kid"], format!("{}/account/1", server.uri()));
    assert_eq!(header["url"], format!("{}/vendor/revoke", server.uri()));
    assert_eq!(header["nonce"], "fresh_nonce");
    assert!(header.get("jwk").is_none());
    let payload: RevocationRequest =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&jws.payload).unwrap()).unwrap();
    assert_eq!(
        payload.reason,
        Some(aster_acme_protocol::revocation::RevocationReason::KeyCompromise)
    );
    assert_eq!(
        URL_SAFE_NO_PAD.decode(payload.certificate).unwrap(),
        session.der
    );
    let jwk = serde_json::to_value(service.identity.signer.jwk().unwrap()).unwrap();
    let mut point = vec![4];
    point.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap());
    point.extend(URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap());
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .verify(
            format!("{}.{}", jws.protected, jws.payload).as_bytes(),
            &URL_SAFE_NO_PAD.decode(jws.signature).unwrap(),
        )
        .unwrap();
}

#[tokio::test]
async fn already_revoked_is_confirmed_and_unspecified_reason_is_omitted() {
    let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
    Mock::given(method("POST"))
        .and(path("/vendor/revoke"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("Replay-Nonce", "next")
                .set_body_json(serde_json::json!({"type":ProblemKind::AlreadyRevoked})),
        )
        .mount(&server)
        .await;
    assert_eq!(
        service
            .revoke(&mut session, None)
            .await
            .unwrap()
            .revocation
            .state,
        RevocationState::Confirmed
    );
    let requests = server.received_requests().await.unwrap();
    let request = requests.iter().find(|r| r.method == "POST").unwrap();
    let jws: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
    assert!(payload.get("reason").is_none());
}

#[tokio::test]
async fn local_eligibility_endpoint_identity_and_save_failures_send_nothing() {
    for case in 0..4 {
        let (server, service, mut session) = fixture(case != 0, Duration::from_secs(5)).await;
        match case {
            1 => session.record.lock().await.phase = IssuancePhase::Authorizing,
            2 => session.record.lock().await.account_id = "other".into(),
            3 => session.fail_save.store(true, Ordering::SeqCst),
            _ => {}
        }
        let reason = None;
        assert!(service.revoke(&mut session, reason).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn timeout_is_pending_and_explicit_retry_preserves_original_reason() {
    let (server, service, mut session) = fixture(true, Duration::from_secs(1)).await;
    Mock::given(method("POST"))
        .and(path("/vendor/revoke"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
        .expect(1)
        .mount(&server)
        .await;
    assert!(
        service
            .revoke(
                &mut session,
                Some(aster_acme_protocol::revocation::RevocationReason::KeyCompromise)
            )
            .await
            .is_err()
    );
    let pending = session.record().await.unwrap().revocation;
    assert_eq!(pending.state, RevocationState::Pending);
    assert!(pending.confirmed_at.is_none());
    assert!(
        service
            .revoke(
                &mut session,
                Some(aster_acme_protocol::revocation::RevocationReason::Superseded)
            )
            .await
            .is_err()
    );
    Mock::given(method("POST"))
        .and(path("/vendor/revoke"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({"type":ProblemKind::AlreadyRevoked})),
        )
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    let record = service.revoke(&mut session, None).await.unwrap();
    assert_eq!(
        record.revocation.reason,
        Some(aster_acme_protocol::revocation::RevocationReason::KeyCompromise)
    );
    assert_eq!(record.revocation.requested_at, pending.requested_at);
    assert_eq!(record.revocation.state, RevocationState::Confirmed);
}

#[tokio::test]
async fn explicit_rejection_resets_only_fresh_requests_and_never_hides_prior_uncertainty() {
    for pending in [false, true] {
        let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
        if pending {
            session.record.lock().await.revocation.state = RevocationState::Pending;
        }
        Mock::given(method("POST"))
            .and(path("/vendor/revoke"))
            .respond_with(ResponseTemplate::new(403).set_body_json(
                serde_json::json!({"type":"urn:ietf:params:acme:error:unauthorized"}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        assert!(service.revoke(&mut session, None).await.is_err());
        assert_eq!(
            session.record().await.unwrap().revocation.state,
            if pending {
                RevocationState::Pending
            } else {
                RevocationState::NotRequested
            }
        );
    }
}

#[tokio::test]
async fn ambiguous_status_server_failure_and_failed_confirmation_stay_pending() {
    for (status, fail_confirmation) in [(201, false), (503, false), (200, true)] {
        let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
        session
            .fail_confirmation
            .store(fail_confirmation, Ordering::SeqCst);
        Mock::given(method("POST"))
            .and(path("/vendor/revoke"))
            .respond_with(ResponseTemplate::new(status).insert_header("Replay-Nonce", "next"))
            .expect(1)
            .mount(&server)
            .await;
        assert!(service.revoke(&mut session, None).await.is_err());
        assert_eq!(
            session.record().await.unwrap().revocation.state,
            RevocationState::Pending
        );
    }
}

#[tokio::test]
async fn dropped_in_flight_revocation_preserves_pending_intent() {
    let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
    Mock::given(method("POST"))
        .and(path("/vendor/revoke"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
        .mount(&server)
        .await;
    let future = service.revoke(&mut session, None);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), future)
            .await
            .is_err()
    );
    assert_eq!(
        session.record().await.unwrap().revocation.state,
        RevocationState::Pending
    );
}

#[tokio::test]
async fn every_assigned_reason_is_sent_as_numeric_code_without_a_client_ca_policy_allowlist() {
    for reason in RevocationReason::ALL {
        let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
        Mock::given(method("POST"))
            .and(path("/vendor/revoke"))
            .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "next"))
            .expect(1)
            .mount(&server)
            .await;
        let result = service.revoke(&mut session, Some(reason)).await.unwrap();
        assert_eq!(result.revocation.reason, Some(reason));
        let requests = server.received_requests().await.unwrap();
        let request = requests
            .iter()
            .find(|request| request.method == "POST")
            .unwrap();
        let jws: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
        assert_eq!(payload["reason"], reason.code());
    }
}

#[tokio::test]
async fn ca_bad_revocation_reason_is_preserved_as_protocol_error_and_not_reported_as_revoked() {
    let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
    Mock::given(method("POST")).and(path("/vendor/revoke"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({"type":"urn:ietf:params:acme:error:badRevocationReason","detail":"this CA accepts only keyCompromise"})))
        .expect(1).mount(&server).await;
    let error = service
        .revoke(&mut session, Some(RevocationReason::CertificateHold))
        .await
        .unwrap_err();
    assert!(
        matches!(error,IssueError::Transport(ref error) if error.is_problem(&ProblemKind::BadRevocationReason))
    );
    assert_eq!(
        session.record().await.unwrap().revocation.state,
        RevocationState::NotRequested
    );
}
