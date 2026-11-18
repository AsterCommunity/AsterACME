use crate::ForgeDnsHttp;
use aster_acme_dns::{
    ProviderErrorCode, ProviderExecution, SideEffect,
    operation::{HttpExecutor, HttpRequest},
};
use std::time::{Duration, Instant};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
fn scope() -> ProviderExecution {
    ProviderExecution {
        cancellation: tokio_util::sync::CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(2),
    }
}
fn request(url: String) -> HttpRequest {
    HttpRequest {
        method: aster_acme_dns::operation::HttpMethod::Post,
        url,
        headers: vec![("X-Signed".into(), "exact-value".into())],
        body: b"exact signed bytes".to_vec(),
        mutation: true,
    }
}
fn transport() -> ForgeDnsHttp {
    ForgeDnsHttp {
        loopback_http: true,
        ..ForgeDnsHttp::default()
    }
}
#[tokio::test]
async fn exact_request_bytes_are_sent_once_without_redirects_or_automatic_retries() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/write"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream body"))
        .expect(1)
        .mount(&server)
        .await;
    let response = transport()
        .execute(request(format!("{}/write", server.uri())), &scope())
        .await
        .unwrap();
    assert_eq!(response.status, 503);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests[0].body, b"exact signed bytes");
    assert_eq!(requests[0].headers["x-signed"], "exact-value");
    Mock::given(path("/redirect"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/never"))
        .expect(1)
        .mount(&server)
        .await;
    let response = transport()
        .execute(request(format!("{}/redirect", server.uri())), &scope())
        .await
        .unwrap();
    assert_eq!(response.status, 302);
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.url.path() == "/never")
    );
}
#[tokio::test]
async fn cancellation_deadlines_response_limits_and_invalid_headers_are_bounded() {
    let server = MockServer::start().await;
    let http = transport();
    Mock::given(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(1)))
        .mount(&server)
        .await;
    let cancelled = scope();
    cancelled.cancellation.cancel();
    let error = http
        .execute(request(format!("{}/slow", server.uri())), &cancelled)
        .await
        .unwrap_err();
    assert_eq!(error.side_effect, SideEffect::None);
    let execution = ProviderExecution {
        deadline: Instant::now() + Duration::from_millis(30),
        ..scope()
    };
    let before = Instant::now();
    let error = http
        .execute(request(format!("{}/slow", server.uri())), &execution)
        .await
        .unwrap_err();
    assert_eq!(error.code, ProviderErrorCode::ProviderTimeout);
    assert_eq!(error.side_effect, SideEffect::Unknown);
    assert!(before.elapsed() < Duration::from_secs(1));
    Mock::given(path("/large"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 1024 * 1024 + 1]))
        .mount(&server)
        .await;
    assert!(
        http.execute(request(format!("{}/large", server.uri())), &scope())
            .await
            .is_err()
    );
    let mut malformed = request(format!("{}/invalid", server.uri()));
    malformed
        .headers
        .push(("Authorization".into(), "sensitive\ninvalid".into()));
    let error = http.execute(malformed, &scope()).await.unwrap_err();
    assert_eq!(error.side_effect, SideEffect::None);
    assert!(
        !server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.url.path() == "/invalid")
    );
}
#[tokio::test]
async fn production_transport_rejects_insecure_and_credential_bearing_urls_before_io() {
    let http = ForgeDnsHttp::default();
    for url in [
        "http://example.com/write",
        "https://user:sensitive@example.com/write",
        "https://example.com/write#fragment",
        "not a URL",
        "https://example.com/a/../write",
        "https://example.com/write?q=a b",
    ] {
        let error = http
            .execute(request(url.into()), &scope())
            .await
            .unwrap_err();
        assert_eq!(error.side_effect, SideEffect::None);
    }
}

#[tokio::test]
async fn request_body_headers_and_url_limits_fail_before_dispatch() {
    let server = MockServer::start().await;
    let http = transport();
    let mut body = request(format!("{}/large", server.uri()));
    body.body = vec![b'x'; 1024 * 1024 + 1];
    let mut headers = request(format!("{}/headers", server.uri()));
    headers.headers.push(("X-Large".into(), "x".repeat(65537)));
    let url = request(format!("{}/{}", server.uri(), "x".repeat(8193)));
    for request in [body, headers, url] {
        assert_eq!(
            http.execute(request, &scope())
                .await
                .unwrap_err()
                .side_effect,
            SideEffect::None
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
