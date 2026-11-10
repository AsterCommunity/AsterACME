//! HTTP and protocol error/retry boundary tests.
use super::*;
use crate::crypto::AccountKey;
use aster_acme_protocol::jws::FlattenedJws;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

pub(crate) async fn server(options: TransportOptions) -> (MockServer, AcmeClient) {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/directory")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"newNonce":format!("{}/nonce",server.uri()),"newAccount":format!("{}/account",server.uri()),"unknownExtension":true}))).mount(&server).await;
    Mock::given(method("HEAD"))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "initial_nonce"))
        .mount(&server)
        .await;
    // Discovery is fixture setup, not the operation whose timeout is under test.
    // Keep short mutation deadlines independent of parallel test scheduling.
    let mut discovery = options.clone();
    discovery.request_timeout = discovery.request_timeout.max(Duration::from_secs(2));
    let mut client = AcmeClient::discover(
        AcmeUrl::new(&format!("{}/directory", server.uri())).unwrap(),
        discovery,
    )
    .await
    .unwrap();
    // HTTP deadlines live on the pool, so reconstruct it with the tested policy.
    client.http = crate::http_client::build(&options).unwrap();
    client.options = options;
    (server, client)
}

pub(crate) fn local_options() -> TransportOptions {
    TransportOptions {
        allow_loopback_http: true,
        ..TransportOptions::default()
    }
}

#[tokio::test]
async fn centralized_user_agent_is_sent_for_discovery_nonce_and_signed_requests() {
    for user_agent in [None, Some("embedded Aster/1.0".to_owned())] {
        let expected = user_agent
            .clone()
            .unwrap_or_else(|| format!("AsterACME/{}", env!("CARGO_PKG_VERSION")));
        let (server, client) = server(TransportOptions {
            user_agent,
            ..local_options()
        })
        .await;
        Mock::given(method("POST"))
            .and(path("/account"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Replay-Nonce", "next_nonce")
                    .set_body_json(serde_json::json!({})),
            )
            .mount(&server)
            .await;
        let key = AccountKey::generate().unwrap();
        client
            .signed(&client.directory.new_account, &key, None, b"{}")
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 3);
        for request in requests {
            assert_eq!(
                request.headers.get("user-agent").unwrap(),
                expected.as_str()
            );
        }
    }
}

#[test]
fn url_validation_preserves_exact_strings_and_rejects_unsafe_forms() {
    for valid in [
        "https://ca.example/a%2fb?x=%41",
        "http://127.0.0.1:123/a",
        "http://[::1]/a",
    ] {
        assert_eq!(AcmeUrl::new(valid).unwrap().as_str(), valid);
    }
    for invalid in [
        "http://ca.example/a",
        "ftp://ca/a",
        "https://user:password@ca/a",
        "https://ca/a#fragment",
        " https://ca/a",
        "https://ca/a\n",
        "file:///a",
        "relative",
        "http://localhost/a",
    ] {
        assert!(AcmeUrl::new(invalid).is_err(), "{invalid}");
    }
}

#[tokio::test]
async fn plaintext_is_explicit_and_options_are_bounded() {
    let url = AcmeUrl::new("http://127.0.0.1:1/directory").unwrap();
    assert!(matches!(
        AcmeClient::discover(url.clone(), TransportOptions::default()).await,
        Err(TransportError::InsecureTransport)
    ));
    for options in [
        TransportOptions {
            request_timeout: Duration::ZERO,
            ..local_options()
        },
        TransportOptions {
            bad_nonce_retries: 6,
            ..local_options()
        },
    ] {
        assert!(matches!(
            AcmeClient::discover(url.clone(), options).await,
            Err(TransportError::InvalidOptions)
        ));
    }
}

#[tokio::test]
async fn bad_nonce_retries_use_error_nonce_and_resign_exact_payload() {
    let (server, client) = server(local_options()).await;
    Mock::given(method("POST"))
        .and(path("/account"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("Replay-Nonce", "retry_nonce")
                .set_body_json(serde_json::json!({"type":BAD_NONCE})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/account"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "next_nonce")
                .set_body_json(serde_json::json!({})),
        )
        .with_priority(10)
        .mount(&server)
        .await;
    let key = AccountKey::generate().unwrap();
    let result = client
        .signed(
            &client.directory.new_account,
            &key,
            None,
            b"{\"onlyReturnExisting\":true}",
        )
        .await
        .unwrap();
    assert_eq!(result.status, 200);
    let posts: Vec<_> = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method == "POST")
        .collect();
    assert_eq!(posts.len(), 2);
    let requests: Vec<FlattenedJws> = posts
        .iter()
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect();
    assert_eq!(requests[0].payload, requests[1].payload);
    assert_ne!(requests[0].signature, requests[1].signature);
    for (request, nonce) in requests.iter().zip(["initial_nonce", "retry_nonce"]) {
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&request.protected).unwrap()).unwrap();
        assert_eq!(header["nonce"], nonce);
        assert_eq!(header["url"], client.directory.new_account.as_str());
    }
}

#[tokio::test]
async fn nonce_retry_is_bounded_and_missing_or_invalid_nonce_is_rejected() {
    for header in [Some("fresh"), None, Some("bad nonce")] {
        let (server, client) = server(TransportOptions {
            bad_nonce_retries: 1,
            ..local_options()
        })
        .await;
        let mut response =
            ResponseTemplate::new(400).set_body_json(serde_json::json!({"type":BAD_NONCE}));
        if let Some(nonce) = header {
            response = response.insert_header("Replay-Nonce", nonce);
        }
        Mock::given(method("POST"))
            .respond_with(response)
            .mount(&server)
            .await;
        let error = client
            .signed(
                &client.directory.new_account,
                &AccountKey::generate().unwrap(),
                None,
                b"{}",
            )
            .await
            .err()
            .unwrap();
        match header {
            Some("fresh") => assert!(error.is_problem(BAD_NONCE)),
            _ => assert!(matches!(error, TransportError::MissingNonce)),
        }
        let count = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count();
        assert_eq!(count, if header == Some("fresh") { 2 } else { 1 });
    }
}

#[tokio::test]
async fn timeout_does_not_retry_mutations() {
    let (server, client) = server(TransportOptions {
        request_timeout: Duration::from_millis(100),
        ..local_options()
    })
    .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(400)))
        .mount(&server)
        .await;
    let result = client
        .signed(
            &client.directory.new_account,
            &AccountKey::generate().unwrap(),
            None,
            b"{}",
        )
        .await;
    assert!(matches!(result,Err(TransportError::Network(error)) if error.is_timeout()));
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count(),
        1
    );
}

#[tokio::test]
async fn rate_limits_unknown_problems_and_non_json_errors_are_not_retried() {
    for (status, body, retry) in [
        (
            429,
            r#"{"type":"urn:ietf:params:acme:error:rateLimited","detail":"wait","subproblems":[{"type":"future","identifier":{"type":"dns","value":"x"}}]}"#,
            "10",
        ),
        (503, "unavailable", "Wed, 21 Oct 2037 07:28:00 GMT"),
        (
            403,
            r#"{"type":"future-problem","instance":"https://ca/action"}"#,
            "invalid",
        ),
    ] {
        let (server, client) = server(local_options()).await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Retry-After", retry)
                    .set_body_string(body),
            )
            .mount(&server)
            .await;
        let error = client
            .signed(
                &client.directory.new_account,
                &AccountKey::generate().unwrap(),
                None,
                b"{}",
            )
            .await
            .err()
            .unwrap();
        match error {
            TransportError::Problem {
                status: 429,
                problem,
                retry_after: Some(RetryAfter::Delay(delay)),
            } => {
                assert_eq!(delay, Duration::from_secs(10));
                assert_eq!(problem.subproblems.len(), 1);
            }
            TransportError::Problem {
                status: 403,
                problem,
                retry_after: None,
            } => assert_eq!(problem.kind, "future-problem"),
            TransportError::HttpStatus {
                status: 503,
                retry_after: Some(RetryAfter::At(_)),
            } => {}
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method == "POST")
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn oversized_body_and_redirect_are_rejected() {
    for response in [
        ResponseTemplate::new(200)
            .insert_header("Replay-Nonce", "next")
            .set_body_bytes(vec![b'x'; MAX_BODY_BYTES + 1]),
        ResponseTemplate::new(302).insert_header("Location", "https://example.com/"),
    ] {
        let (server, client) = server(local_options()).await;
        Mock::given(method("POST"))
            .respond_with(response)
            .mount(&server)
            .await;
        let result = client
            .signed(
                &client.directory.new_account,
                &AccountKey::generate().unwrap(),
                None,
                b"{}",
            )
            .await;
        assert!(matches!(
            result,
            Err(TransportError::BodyTooLarge | TransportError::HttpStatus { status: 302, .. })
        ));
    }
}

#[test]
fn nonce_header_is_single_and_uses_only_base64url_alphabet() {
    let mut headers = HeaderMap::new();
    for value in ["", "abc=", "abc+", "abc/", "a b"] {
        headers.insert("Replay-Nonce", value.parse().unwrap());
        assert!(nonce(&headers).is_none());
    }
    headers.insert("Replay-Nonce", "abc-_09".parse().unwrap());
    assert_eq!(nonce(&headers).as_deref(), Some("abc-_09"));
    headers.append("Replay-Nonce", "second".parse().unwrap());
    assert!(nonce(&headers).is_none());
}

#[tokio::test]
async fn concurrent_requests_consume_distinct_nonces_and_send_valid_signatures() {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
    use std::{
        collections::HashSet,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    let (server, client) = server(local_options()).await;
    // The nonce bootstrap response seeds one single-use nonce; each POST supplies the next.
    server.reset().await;
    let serial = Arc::new(AtomicUsize::new(0));
    Mock::given(method("HEAD"))
        .and(path("/nonce"))
        .respond_with({
            let serial = serial.clone();
            move |_: &wiremock::Request| {
                ResponseTemplate::new(204).insert_header(
                    "Replay-Nonce",
                    format!("nonce_{}", serial.fetch_add(1, Ordering::SeqCst)),
                )
            }
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with({
            let serial = serial.clone();
            move |_: &wiremock::Request| {
                ResponseTemplate::new(200)
                    .insert_header(
                        "Replay-Nonce",
                        format!("reply_{}", serial.fetch_add(1, Ordering::SeqCst)),
                    )
                    .set_body_json(serde_json::json!({}))
            }
        })
        .mount(&server)
        .await;
    let client = Arc::new(client);
    let key = Arc::new(AccountKey::generate().unwrap());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let client = client.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            client
                .signed(&client.directory.new_account, key.as_ref(), None, b"{}")
                .await
        }));
    }
    for handle in handles {
        assert!(handle.await.unwrap().is_ok());
    }
    let mut nonces = HashSet::new();
    for request in server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method == "POST")
    {
        assert_eq!(
            request.headers.get("content-type").unwrap(),
            "application/jose+json"
        );
        let jws: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&jws.protected).unwrap()).unwrap();
        assert!(nonces.insert(header["nonce"].as_str().unwrap().to_owned()));
        let mut point = vec![4];
        point.extend(
            URL_SAFE_NO_PAD
                .decode(header["jwk"]["x"].as_str().unwrap())
                .unwrap(),
        );
        point.extend(
            URL_SAFE_NO_PAD
                .decode(header["jwk"]["y"].as_str().unwrap())
                .unwrap(),
        );
        let verifier = VerifyingKey::from_sec1_bytes(&point).unwrap();
        verifier
            .verify(
                format!("{}.{}", jws.protected, jws.payload).as_bytes(),
                &Signature::from_slice(&URL_SAFE_NO_PAD.decode(&jws.signature).unwrap()).unwrap(),
            )
            .unwrap();
    }
    assert_eq!(nonces.len(), 8);
    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count(),
        8
    );
}

#[tokio::test]
async fn discovery_timeout_malformed_json_and_insecure_endpoints_are_errors() {
    for response in [
        ResponseTemplate::new(200).set_body_string("not JSON"),
        ResponseTemplate::new(200).set_body_json(serde_json::json!({"newNonce":"http://remote.example/nonce","newAccount":"https://ca/account"})),
        ResponseTemplate::new(200).set_delay(Duration::from_millis(400)),
        ResponseTemplate::new(500).set_body_string("server failure"),
    ] {
        let server=MockServer::start().await;
        Mock::given(method("GET")).respond_with(response).mount(&server).await;
        assert!(AcmeClient::discover(AcmeUrl::new(&format!("{}/directory",server.uri())).unwrap(),TransportOptions{request_timeout:Duration::from_millis(100),..local_options()}).await.is_err());
    }
}
