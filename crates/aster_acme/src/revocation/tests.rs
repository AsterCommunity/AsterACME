//! Real signatures and revocation checkpoints with no issuance-session dependency.
use crate::{
    account::AccountRecord,
    crypto::{CryptoError, JwsSigner, key::SoftwareSigningKey, key_algorithm::KeyAlgorithm},
    issuance::IssueError,
    revocation::{
        RevocationIssuer, RevocationRecord, RevocationService, RevocationSigner,
        RevocationSigningMethod, RevocationTarget, authority::RevocationAuthority,
    },
    solver::ExecutionContext,
    storage::revocation::RevocationSession,
    transport::{HttpPool, TransportError, TransportOptions},
};
use aster_acme_core::revocation::RevocationState;
use aster_acme_protocol::{jws::FlattenedJws, revocation::RevocationReason, url::AcmeUrl};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rcgen::PublicKeyData as _;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct Session {
    target: RevocationTarget,
    record: Mutex<RevocationRecord>,
    writes: AtomicUsize,
    fail_save: AtomicBool,
    fail_confirmation: AtomicBool,
    cancel_on_intent: Option<CancellationToken>,
}
#[async_trait]
impl RevocationSession for Session {
    async fn target(&self) -> Result<RevocationTarget, IssueError> {
        Ok(self.target.clone())
    }
    async fn revocation(&self) -> Result<RevocationRecord, IssueError> {
        Ok(self.record.lock().await.clone())
    }
    async fn save_revocation(&self, record: &RevocationRecord) -> Result<(), IssueError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.fail_save.load(Ordering::SeqCst)
            || self.fail_confirmation.load(Ordering::SeqCst)
                && record.state == RevocationState::Confirmed
        {
            return Err(IssueError::InvalidInput("injected checkpoint failure"));
        }
        *self.record.lock().await = record.clone();
        if record.state == RevocationState::Pending
            && let Some(token) = &self.cancel_on_intent
        {
            token.cancel();
        }
        Ok(())
    }
}
struct Fixture {
    server: MockServer,
    client: Arc<crate::transport::AcmeClient>,
    account: AccountRecord,
    account_key: Arc<SoftwareSigningKey>,
    certificate_key: Arc<SoftwareSigningKey>,
    session: Session,
    priority: AtomicUsize,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_key(
            SoftwareSigningKey::generate(KeyAlgorithm::EcdsaP256).unwrap(),
            false,
        )
        .await
    }
    async fn with_key(certificate_key: SoftwareSigningKey, expired: bool) -> Self {
        let server = MockServer::start().await;
        let url = |p: &str| AcmeUrl::new(&format!("{}{p}", server.uri())).unwrap();
        Mock::given(method("GET")).and(path("/directory")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce":url("/nonce"),"newAccount":url("/must-not-register"),"revokeCert":url("/vendor/revoke")
        }))).mount(&server).await;
        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "fresh_nonce"))
            .mount(&server)
            .await;
        let client = Arc::new(
            HttpPool::default()
                .discover(
                    url("/directory"),
                    TransportOptions {
                        allow_loopback_http: true,
                        request_timeout: Duration::from_secs(1),
                        ..TransportOptions::default()
                    },
                )
                .await
                .unwrap(),
        );
        let account_key = Arc::new(SoftwareSigningKey::generate(KeyAlgorithm::EcdsaP256).unwrap());
        let account:AccountRecord=serde_json::from_value(serde_json::json!({"key_algorithm":"ecdsa-p256",
            "account_id":"stable-account","directory_url":url("/directory"),"account_url":url("/account/1"),
            "key_thumbprint":account_key.jwk().unwrap().thumbprint().unwrap(),"contacts":[],"server_contacts":null,
            "last_status":"valid","deactivation":"not_requested","key_rotation":null,"accepted_terms_url":null,"state":"registered"
        })).unwrap();
        let key = rcgen::KeyPair::try_from(certificate_key.to_pkcs8().unwrap().as_slice()).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
        if expired {
            params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(100);
            params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        }
        let certificate = params.self_signed(&key).unwrap();
        let target = RevocationTarget {
            directory: url("/directory"),
            certificate_der: certificate.der().to_vec(),
            issuer: Some(RevocationIssuer {
                account_id: account.account_id.clone(),
                account_url: account.account_url.clone().unwrap(),
            }),
        };
        Self {
            server,
            priority: AtomicUsize::new(100),
            client,
            account,
            account_key,
            certificate_key: Arc::new(certificate_key),
            session: Session {
                target,
                record: Mutex::new(RevocationRecord::default()),
                writes: AtomicUsize::new(0),
                fail_save: AtomicBool::new(false),
                fail_confirmation: AtomicBool::new(false),
                cancel_on_intent: None,
            },
        }
    }
    fn service(&self, method: RevocationSigningMethod) -> RevocationService {
        let authority = match method {
            RevocationSigningMethod::Account => RevocationAuthority::Account {
                account: Arc::new(self.account.clone()),
                signer: self.account_key.clone(),
            },
            RevocationSigningMethod::CertificateKey => RevocationAuthority::CertificateKey {
                signer: self.certificate_key.clone(),
            },
        };
        RevocationService::new(self.client.clone(), authority)
    }
    async fn reply(&self, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/vendor/revoke"))
            .respond_with(response.insert_header("Replay-Nonce", "response_nonce"))
            .with_priority(u8::try_from(self.priority.fetch_sub(1, Ordering::SeqCst)).unwrap())
            .mount(&self.server)
            .await;
    }
    async fn posts(&self) -> Vec<wiremock::Request> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.method == "POST")
            .collect()
    }
    async fn pending(&mut self) {
        self.reply(ResponseTemplate::new(503)).await;
        let service = self.service(RevocationSigningMethod::Account);
        assert!(matches!(
            service
                .revoke(
                    &mut self.session,
                    Some(RevocationReason::Superseded),
                    &execution()
                )
                .await,
            Err(IssueError::RevocationUncertain(_))
        ));
    }
}
fn execution() -> ExecutionContext {
    ExecutionContext {
        cancellation: CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(5),
    }
}
fn problem(status: u16, name: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(serde_json::json!({"type":format!("urn:ietf:params:acme:error:{name}"),"detail":"test CA refusal"}))
}
fn verify(key: &SoftwareSigningKey, jws: &FlattenedJws) {
    use aws_lc_rs::signature;
    let algorithm: &dyn signature::VerificationAlgorithm = match key.algorithm() {
        KeyAlgorithm::EcdsaP256 => &signature::ECDSA_P256_SHA256_FIXED,
        KeyAlgorithm::EcdsaP384 => &signature::ECDSA_P384_SHA384_FIXED,
        KeyAlgorithm::EcdsaP521 => &signature::ECDSA_P521_SHA512_FIXED,
        KeyAlgorithm::Ed25519 => &signature::ED25519,
        KeyAlgorithm::Rsa2048
        | KeyAlgorithm::Rsa3072
        | KeyAlgorithm::Rsa4096
        | KeyAlgorithm::Rsa8192 => &signature::RSA_PKCS1_2048_8192_SHA256,
    };
    let public = rcgen::KeyPair::try_from(key.to_pkcs8().unwrap().as_slice()).unwrap();
    signature::UnparsedPublicKey::new(algorithm, public.der_bytes())
        .verify(
            format!("{}.{}", jws.protected, jws.payload).as_bytes(),
            &URL_SAFE_NO_PAD.decode(&jws.signature).unwrap(),
        )
        .unwrap();
}

#[tokio::test]
async fn both_authorities_sign_exact_der_reason_nonce_and_exclusive_identity() {
    for mode in RevocationSigningMethod::ALL {
        let mut f = Fixture::new().await;
        f.reply(ResponseTemplate::new(200)).await;
        let service = f.service(mode);
        let record = service
            .revoke(
                &mut f.session,
                Some(RevocationReason::KeyCompromise),
                &execution(),
            )
            .await
            .unwrap();
        assert_eq!(record.state, RevocationState::Confirmed);
        assert_eq!(
            record.certificate_sha256,
            Some(f.session.target.fingerprint().unwrap())
        );
        assert!(record.requested_at.is_some() && record.confirmed_at.is_some());
        let posts = f.posts().await;
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].url.path(), "/vendor/revoke");
        let jws: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&jws.protected).unwrap()).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&jws.payload).unwrap()).unwrap();
        assert_eq!(header["url"], format!("{}/vendor/revoke", f.server.uri()));
        assert_eq!(header["nonce"], "fresh_nonce");
        match mode {
            RevocationSigningMethod::Account => {
                assert_eq!(
                    header["kid"],
                    f.account.account_url.as_ref().unwrap().as_str()
                );
                assert!(header.get("jwk").is_none());
                verify(&f.account_key, &jws);
            }
            RevocationSigningMethod::CertificateKey => {
                assert_eq!(
                    header["jwk"],
                    serde_json::to_value(f.certificate_key.jwk().unwrap()).unwrap()
                );
                assert!(header.get("kid").is_none());
                verify(&f.certificate_key, &jws);
            }
        }
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(payload["certificate"].as_str().unwrap())
                .unwrap(),
            f.session.target.certificate_der
        );
        assert_eq!(payload["reason"], 1);
        let repeated = service
            .revoke(
                &mut f.session,
                Some(RevocationReason::Superseded),
                &execution(),
            )
            .await
            .unwrap();
        assert_eq!(repeated, record);
        assert_eq!(f.posts().await.len(), 1);
    }
}

#[tokio::test]
async fn certificate_mode_accepts_external_expired_target_without_account_or_issuance_state() {
    let mut f = Fixture::with_key(
        SoftwareSigningKey::generate(KeyAlgorithm::EcdsaP256).unwrap(),
        true,
    )
    .await;
    f.session.target.issuer = None;
    f.account.account_url = None;
    f.reply(ResponseTemplate::new(200)).await;
    let service = f.service(RevocationSigningMethod::CertificateKey);
    assert_eq!(
        service
            .revoke(&mut f.session, None, &execution())
            .await
            .unwrap()
            .state,
        RevocationState::Confirmed
    );
    let posts = f.posts().await;
    assert_eq!(posts.len(), 1);
    let jws: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
    assert!(payload.get("reason").is_none());
}

#[tokio::test]
async fn certificate_algorithms_use_real_jwk_signatures_and_spki_binding() {
    let fixtures: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../crypto/fixtures/account-keys.json")).unwrap();
    for fixture in fixtures.into_iter().filter(|x| !x["algorithm"].is_null()) {
        let bytes = URL_SAFE_NO_PAD
            .decode(fixture["pkcs8"].as_str().unwrap())
            .unwrap();
        let key = SoftwareSigningKey::from_pkcs8(&bytes).unwrap();
        let mut f = Fixture::with_key(key, false).await;
        f.reply(ResponseTemplate::new(200)).await;
        let service = f.service(RevocationSigningMethod::CertificateKey);
        service
            .revoke(&mut f.session, None, &execution())
            .await
            .unwrap();
        let posts = f.posts().await;
        let jws: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&jws.protected).unwrap()).unwrap();
        assert_eq!(header["jwk"], fixture["jwk"]);
        verify(&f.certificate_key, &jws);
    }
}

#[tokio::test]
async fn mismatched_certificate_key_bad_account_and_malformed_target_send_nothing() {
    for case in 0..6 {
        let mut f = Fixture::new().await;
        let service = match case {
            0 => RevocationService::new(
                f.client.clone(),
                RevocationAuthority::CertificateKey {
                    signer: f.account_key.clone(),
                },
            ),
            1 => {
                f.account.account_id = "wrong".into();
                f.service(RevocationSigningMethod::Account)
            }
            2 => {
                f.account.key_thumbprint = "wrong".into();
                f.service(RevocationSigningMethod::Account)
            }
            3 => {
                f.session.target.certificate_der.clear();
                f.service(RevocationSigningMethod::CertificateKey)
            }
            4 => {
                f.session
                    .target
                    .certificate_der
                    .extend_from_slice(b"trailing");
                f.service(RevocationSigningMethod::CertificateKey)
            }
            _ => {
                f.session.target.directory =
                    AcmeUrl::new("https://other.example/directory").unwrap();
                f.service(RevocationSigningMethod::CertificateKey)
            }
        };
        assert!(
            service
                .revoke(&mut f.session, None, &execution())
                .await
                .is_err()
        );
        assert_eq!(f.posts().await.len(), 0);
        assert_eq!(f.session.writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn missing_endpoint_and_nonce_fail_before_checkpoint_or_post() {
    for endpoint in [false, true] {
        let mut f = Fixture::new().await;
        if endpoint {
            Mock::given(method("HEAD"))
                .and(path("/nonce"))
                .respond_with(ResponseTemplate::new(204))
                .with_priority(1)
                .mount(&f.server)
                .await;
        } else {
            Mock::given(method("GET")).and(path("/directory")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"newNonce":format!("{}/nonce",f.server.uri()),"newAccount":format!("{}/unused",f.server.uri())}))).with_priority(1).mount(&f.server).await;
            f.client = Arc::new(
                HttpPool::default()
                    .discover(
                        f.session.target.directory.clone(),
                        TransportOptions {
                            allow_loopback_http: true,
                            ..TransportOptions::default()
                        },
                    )
                    .await
                    .unwrap(),
            );
        }
        let service = f.service(RevocationSigningMethod::CertificateKey);
        assert!(
            service
                .revoke(&mut f.session, None, &execution())
                .await
                .is_err()
        );
        assert_eq!(f.posts().await.len(), 0);
        assert_eq!(f.session.writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn fresh_explicit_problem_refusals_reset_intent_and_all_assigned_reasons_remain_available() {
    for reason in RevocationReason::ALL {
        let mut f = Fixture::new().await;
        f.reply(problem(400, "badRevocationReason")).await;
        let service = f.service(RevocationSigningMethod::CertificateKey);
        assert!(matches!(
            service
                .revoke(&mut f.session, Some(reason), &execution())
                .await,
            Err(IssueError::Transport(TransportError::Problem {
                status: 400,
                ..
            }))
        ));
        assert_eq!(
            f.session.revocation().await.unwrap(),
            RevocationRecord::default()
        );
        let posts = f.posts().await;
        let jws: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
        assert_eq!(payload["reason"], u8::from(reason));
    }
}

#[tokio::test]
async fn unknown_outcome_keeps_target_reason_and_prior_uncertainty_across_authority_changes() {
    let mut f = Fixture::new().await;
    f.pending().await;
    let pending = f.session.revocation().await.unwrap();
    assert_eq!(pending.state, RevocationState::Pending);
    let service = f.service(RevocationSigningMethod::CertificateKey);
    assert!(
        service
            .revoke(
                &mut f.session,
                Some(RevocationReason::KeyCompromise),
                &execution()
            )
            .await
            .is_err()
    );
    assert_eq!(f.posts().await.len(), 1);
    f.reply(problem(403, "unauthorized")).await;
    assert!(matches!(
        service.revoke(&mut f.session, None, &execution()).await,
        Err(IssueError::RevocationUncertain(_))
    ));
    assert_eq!(
        f.session.revocation().await.unwrap().state,
        RevocationState::Pending
    );
    f.reply(problem(400, "alreadyRevoked")).await;
    let confirmed = service
        .revoke(&mut f.session, None, &execution())
        .await
        .unwrap();
    assert_eq!(confirmed.state, RevocationState::Confirmed);
    assert_eq!(confirmed.reason, pending.reason);
    assert_eq!(confirmed.requested_at, pending.requested_at);
    assert!(matches!(
        confirmed.signer,
        Some(RevocationSigner::CertificateKey { .. })
    ));
}

#[tokio::test]
async fn checkpoint_target_drift_and_incomplete_requested_state_are_never_replayed() {
    for case in 0..3 {
        let mut f = Fixture::new().await;
        f.pending().await;
        match case {
            0 => f.session.record.lock().await.certificate_sha256 = Some("different".into()),
            1 => f.session.record.lock().await.directory = None,
            _ => f.session.record.lock().await.signer = None,
        }
        let service = f.service(RevocationSigningMethod::CertificateKey);
        assert!(
            service
                .revoke(&mut f.session, None, &execution())
                .await
                .is_err()
        );
        assert_eq!(f.posts().await.len(), 1);
    }
}

#[tokio::test]
async fn cancellation_before_submission_and_during_checkpoint_does_not_send() {
    for during_save in [false, true] {
        let mut f = Fixture::new().await;
        let controls = execution();
        if during_save {
            f.session.cancel_on_intent = Some(controls.cancellation.clone());
        } else {
            controls.cancellation.cancel();
        }
        let service = f.service(RevocationSigningMethod::CertificateKey);
        assert!(
            service
                .revoke(&mut f.session, None, &controls)
                .await
                .is_err()
        );
        assert_eq!(f.posts().await.len(), 0);
        assert_eq!(
            f.session.revocation().await.unwrap(),
            RevocationRecord::default()
        );
    }
}

#[tokio::test]
async fn timeout_after_send_and_caller_drop_retain_pending_without_automatic_replay() {
    for drop_caller in [false, true] {
        let mut f = Fixture::new().await;
        f.reply(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .await;
        let mut controls = execution();
        controls.deadline = Instant::now() + Duration::from_millis(100);
        let service = f.service(RevocationSigningMethod::CertificateKey);
        if drop_caller {
            let result = tokio::time::timeout(
                Duration::from_millis(100),
                service.revoke(&mut f.session, None, &execution()),
            )
            .await;
            assert!(result.is_err());
        } else {
            assert!(matches!(
                service.revoke(&mut f.session, None, &controls).await,
                Err(IssueError::RevocationInterrupted)
            ));
        }
        assert_eq!(
            f.session.revocation().await.unwrap().state,
            RevocationState::Pending
        );
        assert_eq!(f.posts().await.len(), 1);
    }
}

#[tokio::test]
async fn failed_intent_write_sends_nothing_and_failed_confirmation_preserves_pending() {
    let mut f = Fixture::new().await;
    f.reply(ResponseTemplate::new(200)).await;
    f.session.fail_save.store(true, Ordering::SeqCst);
    let service = f.service(RevocationSigningMethod::CertificateKey);
    assert!(
        service
            .revoke(&mut f.session, None, &execution())
            .await
            .is_err()
    );
    assert_eq!(f.posts().await.len(), 0);
    f.session.fail_save.store(false, Ordering::SeqCst);
    f.session.fail_confirmation.store(true, Ordering::SeqCst);
    assert!(
        service
            .revoke(&mut f.session, None, &execution())
            .await
            .is_err()
    );
    assert_eq!(
        f.session.revocation().await.unwrap().state,
        RevocationState::Pending
    );
    f.session.fail_confirmation.store(false, Ordering::SeqCst);
    f.reply(problem(400, "alreadyRevoked")).await;
    assert_eq!(
        service
            .revoke(&mut f.session, None, &execution())
            .await
            .unwrap()
            .state,
        RevocationState::Confirmed
    );
}

#[tokio::test]
async fn bad_nonce_resigns_with_the_replacement_nonce_and_same_payload() {
    let mut f = Fixture::new().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    Mock::given(method("POST"))
        .and(path("/vendor/revoke"))
        .respond_with(move |_: &wiremock::Request| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                problem(400, "badNonce").insert_header("Replay-Nonce", "replacement_nonce")
            } else {
                ResponseTemplate::new(200).insert_header("Replay-Nonce", "done_nonce")
            }
        })
        .mount(&f.server)
        .await;
    let service = f.service(RevocationSigningMethod::CertificateKey);
    service
        .revoke(&mut f.session, None, &execution())
        .await
        .unwrap();
    let posts = f.posts().await;
    assert_eq!(posts.len(), 2);
    let first: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
    let second: FlattenedJws = serde_json::from_slice(&posts[1].body).unwrap();
    assert_eq!(first.payload, second.payload);
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&second.protected).unwrap()).unwrap();
    assert_eq!(header["nonce"], "replacement_nonce");
    verify(&f.certificate_key, &second);
}

struct FailingSigner {
    key: Arc<SoftwareSigningKey>,
}
impl JwsSigner for FailingSigner {
    fn algorithm(&self) -> KeyAlgorithm {
        self.key.algorithm()
    }
    fn jwk(&self) -> Result<crate::crypto::jwk::Jwk, CryptoError> {
        self.key.jwk()
    }
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Signing)
    }
}
#[tokio::test]
async fn local_signing_failure_creates_no_intent_and_confirmed_result_needs_no_signer() {
    let mut f = Fixture::new().await;
    f.reply(ResponseTemplate::new(200)).await;
    let failing = RevocationService::new(
        f.client.clone(),
        RevocationAuthority::CertificateKey {
            signer: Arc::new(FailingSigner {
                key: f.certificate_key.clone(),
            }),
        },
    );
    assert!(
        failing
            .revoke(&mut f.session, None, &execution())
            .await
            .is_err()
    );
    assert_eq!(f.session.writes.load(Ordering::SeqCst), 0);
    let service = f.service(RevocationSigningMethod::CertificateKey);
    service
        .revoke(&mut f.session, None, &execution())
        .await
        .unwrap();
    let before = f.posts().await.len();
    failing
        .revoke(&mut f.session, None, &execution())
        .await
        .unwrap();
    assert_eq!(f.posts().await.len(), before);
}

#[tokio::test]
async fn unexpected_success_redirects_nonproblem_errors_and_server_errors_stay_pending() {
    for response in [
        ResponseTemplate::new(201),
        ResponseTemplate::new(204),
        ResponseTemplate::new(302),
        ResponseTemplate::new(403).set_body_string("not a problem"),
        problem(500, "serverInternal"),
        problem(429, "rateLimited"),
    ] {
        let mut f = Fixture::new().await;
        f.reply(response).await;
        let service = f.service(RevocationSigningMethod::CertificateKey);
        let result = service.revoke(&mut f.session, None, &execution()).await;
        if matches!(
            result,
            Err(IssueError::Transport(TransportError::Problem {
                status: 429,
                ..
            }))
        ) {
            assert_eq!(
                f.session.revocation().await.unwrap().state,
                RevocationState::NotRequested
            );
        } else {
            assert!(matches!(result, Err(IssueError::RevocationUncertain(_))));
            assert_eq!(
                f.session.revocation().await.unwrap().state,
                RevocationState::Pending
            );
        }
        assert_eq!(f.posts().await.len(), 1);
    }
}

#[tokio::test]
async fn expired_deadline_and_oversized_certificate_never_request_a_nonce_or_submit() {
    for oversized in [false, true] {
        let mut f = Fixture::new().await;
        let mut controls = execution();
        if oversized {
            f.session.target.certificate_der = vec![0; 1024 * 1024 + 1];
        } else {
            controls.deadline = Instant::now();
        }
        let service = f.service(RevocationSigningMethod::CertificateKey);
        assert!(
            service
                .revoke(&mut f.session, None, &controls)
                .await
                .is_err()
        );
        assert_eq!(f.session.writes.load(Ordering::SeqCst), 0);
        assert!(
            f.server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method == "GET")
        );
    }
}
