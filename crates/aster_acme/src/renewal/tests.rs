//! ARI timing, RFC identifier, HTTP retry and durable schedule boundaries.
use crate::renewal::*;
use crate::transport::TransportOptions;
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(seconds).unwrap()
}

fn plan() -> RenewalPlan {
    RenewalPlan::fallback(
        at(0),
        at(90 * 86400),
        at(0),
        Some("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE".into()),
    )
    .unwrap()
}

fn info(start: i64, end: i64) -> RenewalInfo {
    RenewalInfo {
        suggested_window: SuggestedWindow {
            start: at(start),
            end: at(end),
        },
        explanation_url: Some("https://ca.example/notice".into()),
    }
}

struct Session {
    record: Mutex<IssueRecord>,
    saves: AtomicUsize,
}

#[async_trait]
impl IssueSession for Session {
    async fn record(&self) -> Result<IssueRecord, IssueError> {
        Ok(self.record.lock().await.clone())
    }
    async fn save(&self, record: &IssueRecord) -> Result<(), IssueError> {
        *self.record.lock().await = record.clone();
        self.saves.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn certificate_der(&self) -> Result<Vec<u8>, IssueError> {
        Err(IssueError::InvalidInput(
            "ARI must not load certificate artifacts",
        ))
    }
    async fn csr(&self) -> Result<Vec<u8>, IssueError> {
        Err(IssueError::InvalidInput("ARI must not read CSR"))
    }
    async fn complete(&self, _: &IssueRecord, _: &[u8]) -> Result<IssueRecord, IssueError> {
        Err(IssueError::InvalidInput(
            "ARI must not promote certificates",
        ))
    }
}

async fn fixture(endpoint: bool, timeout: Duration) -> (MockServer, RenewalService, Session) {
    let server = MockServer::start().await;
    let directory =
        aster_acme_protocol::url::AcmeUrl::new(&format!("{}/directory", server.uri())).unwrap();
    Mock::given(method("GET")).and(path("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce":format!("{}/unused",server.uri()),"newAccount":format!("{}/unused",server.uri()),
            "renewalInfo":endpoint.then(|| format!("{}/custom/renewal",server.uri()))
        }))).mount(&server).await;
    let client = crate::transport::HttpPool::default()
        .discover(
            directory.clone(),
            TransportOptions {
                allow_loopback_http: true,
                request_timeout: timeout,
                ..TransportOptions::default()
            },
        )
        .await
        .unwrap();
    let mut record: IssueRecord = serde_json::from_value(serde_json::json!({
        "key_algorithm":"ecdsa-p256","challenge":"dns-01","solver_config":{},"solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"example.com",
        "created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"id","account_thumbprint":"key",
        "directory":directory,"account_url":"https://ca.example/account","identifiers":["example.com"],
        "phase":"completed","creation_submitted":true,"order_url":"https://ca.example/order","finalize_submitted":"submitted","authorizations":[]
    })).unwrap();
    let mut current_plan = plan();
    let shift = OffsetDateTime::now_utc() - at(60 * 86400);
    current_plan.not_before += shift;
    current_plan.not_after += shift;
    current_plan.renew_at += shift;
    record.renewal = Some(current_plan);
    record.is_in_use = true;
    (
        server,
        RenewalService::new(Arc::new(client)),
        Session {
            record: Mutex::new(record),
            saves: AtomicUsize::new(0),
        },
    )
}

fn execution(seconds: u64) -> ExecutionContext {
    ExecutionContext {
        cancellation: CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(seconds),
    }
}

#[test]
fn fallback_uses_original_validity_and_rejects_empty_intervals() {
    let ninety_day = plan();
    assert!(ninety_day.renew_at > at(59 * 86400));
    assert!(ninety_day.renew_at < at(60 * 86400));
    for seconds in [1, 2, 3, 6 * 86400, 90 * 86400] {
        let not_before = at(-100);
        let not_after = at(-100 + seconds);
        let p = RenewalPlan::fallback(not_before, not_after, not_before, None).unwrap();
        let target = not_before + time::Duration::seconds(seconds) * 2 / 3;
        assert!(p.renew_at >= not_before && p.renew_at <= target);
        assert!(p.renew_at >= p.not_before && p.renew_at < p.not_after);
    }
    assert!(RenewalPlan::fallback(at(1), at(1), at(0), None).is_err());
    assert!(RenewalPlan::fallback(at(2), at(1), at(0), None).is_err());
}

#[test]
fn windows_sample_in_range_keep_identical_selection_and_reject_invalid_intervals() {
    let mut p = plan();
    for _ in 0..100 {
        p.suggested_window = None;
        p.apply(info(5, 10)).unwrap();
        assert!((at(5)..at(10)).contains(&p.renew_at));
    }
    let chosen = p.renew_at;
    p.apply(info(5, 10)).unwrap();
    assert_eq!(p.renew_at, chosen);
    assert!(p.renew_at < OffsetDateTime::now_utc()); // Due now; no backwards waiting.
    for (start, end) in [(10, 10), (11, 10), (90 * 86400, 91 * 86400)] {
        assert!(p.apply(info(start, end)).is_err());
        assert_eq!(p.renew_at, chosen);
    }
    let tiny = SuggestedWindow {
        start: at(1),
        end: at(1) + time::Duration::nanoseconds(1),
    };
    assert_eq!(sample(&tiny).unwrap(), at(1));
    let roundtrip: RenewalPlan = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
    assert_eq!(roundtrip.renew_at, chosen);
}

#[test]
fn retry_after_delta_date_and_extremes_are_clamped() {
    for (seconds, expected) in [
        (0, 60),
        (1, 60),
        (60, 60),
        (21600, 21600),
        (u64::MAX, 86400),
    ] {
        assert_eq!(
            next_check(&RetryAfter::Delay(Duration::from_secs(seconds)), at(100)),
            at(100 + expected)
        );
    }
    assert_eq!(
        next_check(
            &RetryAfter::At(std::time::SystemTime::from(at(99))),
            at(100)
        ),
        at(160)
    );
    assert_eq!(
        next_check(
            &RetryAfter::At(std::time::SystemTime::from(at(3700))),
            at(100)
        ),
        at(3700)
    );
}

#[tokio::test]
async fn unsigned_get_persists_window_and_respects_saved_query_deadline() {
    let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
    Mock::given(method("GET"))
        .and(path("/custom/renewal/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Retry-After", "21600")
                .set_body_json(info(100, 200)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let record = service.refresh(&mut session, &execution(5)).await.unwrap();
    let p = record.renewal.unwrap();
    assert_eq!(p.source, RenewalSource::Ari);
    assert!(!p.last_query_failed);
    assert!((at(100)..at(200)).contains(&p.renew_at));
    let second = service
        .refresh(&mut session, &execution(5))
        .await
        .unwrap()
        .renewal
        .unwrap();
    assert_eq!(p.renew_at, second.renew_at);
    assert_eq!(p.next_check_at, second.next_check_at);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let request = &requests[1];
    assert_eq!(request.body, Vec::<u8>::new());
    assert!(request.headers.get("authorization").is_none());
    assert!(request.headers.get("content-type").is_none());
}

#[tokio::test]
async fn absent_endpoint_or_identifier_never_queries_or_saves() {
    for endpoint in [false, true] {
        let (server, service, mut session) = fixture(endpoint, Duration::from_secs(5)).await;
        if endpoint {
            session
                .record
                .lock()
                .await
                .renewal
                .as_mut()
                .unwrap()
                .certificate_id = None;
        }
        service.refresh(&mut session, &execution(2)).await.unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert_eq!(session.saves.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn bad_responses_preserve_existing_ari_and_set_six_hour_retry() {
    for (status, body, retry) in [
        (404, "{}", Some("60")),
        (200, "not json", Some("60")),
        (200, "{}", Some("60")),
        (
            200,
            "{\"suggestedWindow\":{\"start\":\"invalid\",\"end\":\"invalid\"}}",
            Some("60"),
        ),
        (200, "{}", None),
    ] {
        let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
        session
            .record
            .lock()
            .await
            .renewal
            .as_mut()
            .unwrap()
            .apply(info(10, 20))
            .unwrap();
        let before = session.record().await.unwrap().renewal.unwrap();
        let mut response = ResponseTemplate::new(status).set_body_string(body);
        if let Some(retry) = retry {
            response = response.insert_header("Retry-After", retry);
        }
        Mock::given(method("GET"))
            .and(path("/custom/renewal/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let after = service
            .refresh(&mut session, &execution(2))
            .await
            .unwrap()
            .renewal
            .unwrap();
        assert_eq!(before.renew_at, after.renew_at);
        assert_eq!(after.source, RenewalSource::Ari);
        assert!(after.last_query_failed);
        assert_eq!(
            after.next_check_at.unwrap() - after.last_checked_at.unwrap(),
            time::Duration::hours(6)
        );
    }
}

#[tokio::test]
async fn server_errors_retry_with_bound_and_then_keep_fallback() {
    let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
    Mock::given(method("GET"))
        .and(path("/custom/renewal/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"))
        .respond_with(ResponseTemplate::new(503))
        .expect(3)
        .mount(&server)
        .await;
    let p = service
        .refresh(&mut session, &execution(10))
        .await
        .unwrap()
        .renewal
        .unwrap();
    assert_eq!(p.source, RenewalSource::Fallback);
    assert!(
        p.renew_at > p.not_before + time::Duration::days(59)
            && p.renew_at < p.not_before + time::Duration::days(60)
    );
    assert!(p.last_query_failed);
}

#[tokio::test]
async fn transient_failure_then_success_updates_plan() {
    let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
    let count = AtomicUsize::new(0);
    Mock::given(method("GET"))
        .and(path("/custom/renewal/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"))
        .respond_with(
            move |_: &wiremock::Request| match count.fetch_add(1, Ordering::SeqCst) {
                0 => ResponseTemplate::new(500),
                _ => ResponseTemplate::new(200)
                    .insert_header("Retry-After", "60")
                    .set_body_json(info(10, 20)),
            },
        )
        .expect(2)
        .mount(&server)
        .await;
    assert_eq!(
        service
            .refresh(&mut session, &execution(5))
            .await
            .unwrap()
            .renewal
            .unwrap()
            .source,
        RenewalSource::Ari
    );
}

#[tokio::test]
async fn cancellation_and_deadline_keep_persisted_plan_without_requery() {
    let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
    Mock::given(method("GET"))
        .and(path("/custom/renewal/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(3))
                .set_body_json(info(10, 20)),
        )
        .mount(&server)
        .await;
    let cancelled = execution(5);
    cancelled.cancellation.cancel();
    assert!(matches!(
        service.refresh(&mut session, &cancelled).await,
        Err(IssueError::Interrupted)
    ));
    assert_eq!(session.saves.load(Ordering::SeqCst), 0);
    assert!(matches!(
        service.refresh(&mut session, &execution(1)).await,
        Err(IssueError::Interrupted)
    ));
    let saved = session.record().await.unwrap().renewal.unwrap();
    assert!(saved.next_check_at.is_some());
    assert_eq!(saved.source, RenewalSource::Fallback);
    service.refresh(&mut session, &execution(5)).await.unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[test]
fn rfc9773_appendix_certificate_retains_serial_leading_zero() {
    let pem = b"-----BEGIN CERTIFICATE-----\nMIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt\ncGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS\nBgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu\n7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf\nqzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B\nyNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb\n+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK\n-----END CERTIFICATE-----\n";
    let (_, pem) = parse_x509_pem(pem).unwrap();
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&pem.contents).unwrap();
    assert_eq!(
        certificate_identifier(&cert).as_deref(),
        Some("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE")
    );
}

#[tokio::test]
async fn request_timeouts_retry_but_do_not_erase_fallback() {
    let (server, service, mut session) = fixture(true, Duration::from_secs(1)).await;
    Mock::given(method("GET"))
        .and(path("/custom/renewal/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(3))
                .set_body_json(info(10, 20)),
        )
        .expect(3)
        .mount(&server)
        .await;
    let p = service
        .refresh(&mut session, &execution(10))
        .await
        .unwrap()
        .renewal
        .unwrap();
    assert!(p.last_query_failed);
    assert!(
        p.renew_at > p.not_before + time::Duration::days(59)
            && p.renew_at < p.not_before + time::Duration::days(60)
    );
    assert_eq!(p.source, RenewalSource::Fallback);
}

#[tokio::test]
async fn valid_window_with_missing_or_invalid_retry_after_still_updates_renewal_time() {
    for retry in [None, Some("not-a-date")] {
        let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
        let mut response = ResponseTemplate::new(200).set_body_json(info(100, 200));
        if let Some(retry) = retry {
            response = response.insert_header("Retry-After", retry);
        }
        Mock::given(method("GET"))
            .and(path("/custom/renewal/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let p = service
            .refresh(&mut session, &execution(5))
            .await
            .unwrap()
            .renewal
            .unwrap();
        assert_eq!(p.source, RenewalSource::Ari);
        assert!((at(100)..at(200)).contains(&p.renew_at));
        assert!(p.last_query_failed);
        assert_eq!(
            p.next_check_at.unwrap() - p.last_checked_at.unwrap(),
            time::Duration::hours(6)
        );
    }
}

#[tokio::test]
async fn cancellation_during_backoff_prevents_another_attempt() {
    let (server, service, mut session) = fixture(true, Duration::from_secs(5)).await;
    Mock::given(method("GET"))
        .and(path("/custom/renewal/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    let execution = execution(5);
    let cancel = execution.cancellation.clone();
    let stop = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        cancel.cancel();
    });
    assert!(matches!(
        service.refresh(&mut session, &execution).await,
        Err(IssueError::Interrupted)
    ));
    stop.await.unwrap();
    assert!(
        session
            .record()
            .await
            .unwrap()
            .renewal
            .unwrap()
            .last_query_failed
    );
}

#[tokio::test]
async fn expired_certificates_keep_the_plan_without_any_ari_request_or_write() {
    let (server, service, mut session) = fixture(true, Duration::from_secs(1)).await;
    session
        .record
        .lock()
        .await
        .renewal
        .as_mut()
        .unwrap()
        .not_after = OffsetDateTime::now_utc() - time::Duration::seconds(1);
    let before = serde_json::to_value(session.record.lock().await.clone()).unwrap();
    let result = service.refresh(&mut session, &execution(2)).await.unwrap();
    assert_eq!(serde_json::to_value(result).unwrap(), before);
    assert_eq!(session.saves.load(Ordering::SeqCst), 0);
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path().contains("/custom/renewal"))
    );
}

#[test]
fn expired_certificate_identifier_extraction_does_not_create_a_schedule() {
    let mut params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
    params.not_before = OffsetDateTime::now_utc() - time::Duration::days(90);
    params.not_after = OffsetDateTime::now_utc() - time::Duration::days(1);
    let cert = params
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap()
        .pem();
    assert!(identifier_from_certificate(cert.as_bytes()).is_ok());
    assert!(RenewalPlan::from_certificate(cert.as_bytes()).is_err());
}

#[test]
fn ari_window_spanning_expiry_samples_only_its_usable_prefix_and_keeps_ca_window() {
    let mut p = plan();
    let expiry = p.not_after;
    for _ in 0..100 {
        p.suggested_window = None;
        p.apply(info(89 * 86400, 91 * 86400)).unwrap();
        assert!((at(89 * 86400)..expiry).contains(&p.renew_at));
        assert_eq!(p.suggested_window.as_ref().unwrap().end, at(91 * 86400));
    }
    let saved = p.renew_at;
    p.apply(info(89 * 86400, 91 * 86400)).unwrap();
    assert_eq!(saved, p.renew_at);
}
