//! HTTP and protocol error/retry boundary tests.
use crate::crypto::key::AccountKey;
use crate::crypto::key_algorithm::KeyAlgorithm;
use crate::transport::*;
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
    let mut client = crate::transport::HttpPool::default()
        .discover(
            AcmeUrl::new(&format!("{}/directory", server.uri())).unwrap(),
            discovery,
        )
        .await
        .unwrap();
    // Request deadlines are independent of the shared connection pool.
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
        let key = AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
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
        crate::transport::HttpPool::default()
            .discover(url.clone(), TransportOptions::default())
            .await,
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
            crate::transport::HttpPool::default()
                .discover(url.clone(), options)
                .await,
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
                .set_body_json(serde_json::json!({"type":ProblemKind::BadNonce})),
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
    let key = AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
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
        let mut response = ResponseTemplate::new(400)
            .set_body_json(serde_json::json!({"type":ProblemKind::BadNonce}));
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
                &AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap(),
                None,
                b"{}",
            )
            .await
            .err()
            .unwrap();
        match header {
            Some("fresh") => assert!(error.is_problem(&ProblemKind::BadNonce)),
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
            &AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap(),
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
                &AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap(),
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
            } => assert_eq!(problem.kind, ProblemKind::Unknown("future-problem".into())),
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
                &AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap(),
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
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
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
    let key = Arc::new(AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap());
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
        let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point);
        verifier
            .verify(
                format!("{}.{}", jws.protected, jws.payload).as_bytes(),
                &URL_SAFE_NO_PAD.decode(&jws.signature).unwrap(),
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
        assert!(crate::transport::HttpPool::default().discover(AcmeUrl::new(&format!("{}/directory",server.uri())).unwrap(),TransportOptions{request_timeout:Duration::from_millis(100),..local_options()}).await.is_err());
    }
}

#[tokio::test]
async fn successful_post_without_usable_nonce_keeps_location_and_fetches_fresh_nonce_next_time() {
    for header in [None, Some("invalid nonce")] {
        let (server, client) = server(local_options()).await;
        let mut response = ResponseTemplate::new(201)
            .insert_header("Location", format!("{}/created", server.uri()))
            .set_body_json(serde_json::json!({"status":"valid"}));
        if let Some(header) = header {
            response = response.insert_header("Replay-Nonce", header);
        }
        Mock::given(method("POST"))
            .and(path("/account"))
            .respond_with(response)
            .expect(2)
            .mount(&server)
            .await;
        let key = AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
        for _ in 0..2 {
            let response = client
                .signed(&client.directory.new_account, &key, None, b"{}")
                .await
                .unwrap();
            assert_eq!(response.status, StatusCode::CREATED);
            assert_eq!(
                client.account_location(&response).unwrap().as_str(),
                format!("{}/created", server.uri())
            );
        }
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.iter().filter(|r| r.method == "HEAD").count(), 2);
        assert!(
            requests
                .iter()
                .all(|r| r.headers.get("Replay-Nonce").is_none())
        );
    }
}

// Count accepted sockets, rather than just cloned handles: HTTP/1.1 keep-alive
// proves that independent ACME clients actually use the same connection pool.
#[tokio::test]
async fn pool_clones_reuse_tcp_connections_without_sharing_account_policy_or_nonces() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let body = serde_json::to_string(&serde_json::json!({
        "newNonce": format!("{base}/nonce"), "newAccount": format!("{base}/account")
    }))
    .unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted = connections.clone();
    let (sender, mut requests) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                socket = listener.accept() => {
                    let (socket, _) = socket.unwrap();
                    accepted.fetch_add(1, Ordering::SeqCst);
                    let body = body.clone();
                    let sender = sender.clone();
                    tasks.spawn(async move {
                        let mut socket = BufReader::new(socket);
                        loop {
                            let mut headers = String::new();
                            loop {
                                let mut line = String::new();
                                if socket.read_line(&mut line).await.unwrap() == 0 { return; }
                                if line == "\r\n" { break; }
                                headers.push_str(&line);
                            }
                            sender.send(headers.clone()).unwrap();
                            let nonce = if headers.contains("account-a") { "nonce_a" } else { "nonce_b" };
                            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nReplay-Nonce: {nonce}\r\n\r\n{body}",body.len());
                            socket.get_mut().write_all(response.as_bytes()).await.unwrap();
                        }
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    let pool = HttpPool::default();
    assert!(pool.0.get().is_none());
    // Keep system proxies out of the socket-count fixture: a proxy may close
    // its upstream connection independently of reqwest pool reuse.
    pool.0
        .set(
            aster_forge_http::HttpClient::builder()
                .no_proxy()
                .build()
                .unwrap(),
        )
        .unwrap();
    let url = AcmeUrl::new(&format!("{base}/directory")).unwrap();
    let first = pool
        .discover(
            url.clone(),
            TransportOptions {
                user_agent: Some("account-a".into()),
                ..local_options()
            },
        )
        .await
        .unwrap();
    let second = pool
        .clone()
        .discover(
            url.clone(),
            TransportOptions {
                user_agent: Some("account-b".into()),
                ..local_options()
            },
        )
        .await
        .unwrap();
    assert_eq!(first.take_nonce().await.unwrap(), "nonce_a");
    assert_eq!(second.take_nonce().await.unwrap(), "nonce_b");
    first.get(&url).await.unwrap();
    second.get(&url).await.unwrap();
    for agent in ["account-a", "account-b", "account-a", "account-b"] {
        let request = requests.try_recv().unwrap();
        assert!(
            request
                .to_ascii_lowercase()
                .contains(&format!("user-agent: {agent}\r\n")),
            "{request}"
        );
    }
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn shared_pool_keeps_request_deadlines_independent_and_initializes_lazily() {
    let pool = HttpPool::default();
    let url = AcmeUrl::new("http://127.0.0.1:1/directory").unwrap();
    assert!(
        pool.discover(url, TransportOptions::default())
            .await
            .is_err()
    );
    assert!(pool.0.get().is_none());
    let (server, _) = server(local_options()).await;
    let url = AcmeUrl::new(&format!("{}/directory", server.uri())).unwrap();
    let shared = pool.clone();
    let (first, second) = tokio::join!(
        pool.discover(url.clone(), local_options()),
        shared.discover(url, local_options())
    );
    let mut first = first.unwrap();
    let second = second.unwrap();
    first.options.request_timeout = Duration::from_millis(20);
    Mock::given(method("GET"))
        .and(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(150)))
        .mount(&server)
        .await;
    let url = AcmeUrl::new(&format!("{}/slow", server.uri())).unwrap();
    let (short, long) = tokio::join!(first.get(&url), second.get(&url));
    assert!(matches!(short, Err(TransportError::Network(error)) if error.is_timeout()));
    assert_eq!(long.unwrap().status, StatusCode::OK);
    assert!(pool.0.get().is_some());
}

#[tokio::test]
async fn advisory_http_checks_bound_content_and_follow_bounded_redirects() {
    let server = MockServer::start().await;
    let pool = HttpPool::default();
    for (path_name, body, expected) in [
        ("exact", "token.thumb", true),
        ("newline", "token.thumb\n", true),
        ("wrong", "other", false),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/{path_name}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        assert_eq!(
            pool.check_http_challenge(
                &format!("{}/{path_name}", server.uri()),
                b"token.thumb",
                Duration::from_secs(2),
                crate::transport::HttpPrecheckPolicy::LoopbackTest,
            )
            .await
            .unwrap(),
            expected
        );
    }
    Mock::given(method("GET"))
        .and(path("/redirect"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", format!("{}/exact", server.uri())),
        )
        .mount(&server)
        .await;
    assert!(
        pool.check_http_challenge(
            &format!("{}/redirect", server.uri()),
            b"token.thumb",
            Duration::from_secs(2),
            crate::transport::HttpPrecheckPolicy::LoopbackTest,
        )
        .await
        .unwrap()
    );
    Mock::given(method("GET"))
        .and(path("/large"))
        .respond_with(ResponseTemplate::new(200).set_body_string("a".repeat(8193)))
        .mount(&server)
        .await;
    assert!(matches!(
        pool.check_http_challenge(
            &format!("{}/large", server.uri()),
            b"token.thumb",
            Duration::from_secs(2),
            crate::transport::HttpPrecheckPolicy::LoopbackTest,
        )
        .await,
        Err(TransportError::BodyTooLarge)
    ));
}

#[tokio::test]
async fn advisory_redirect_loops_invalid_schemes_and_missing_locations_are_bounded() {
    let server = MockServer::start().await;
    let pool = HttpPool::default();
    for (name, target) in [
        ("loop", Some("/loop")),
        ("file", Some("file:///private/key")),
        ("missing", None),
    ] {
        let mut response = ResponseTemplate::new(302);
        if let Some(target) = target {
            response = response.insert_header("Location", target);
        }
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(response)
            .mount(&server)
            .await;
        let result = pool
            .check_http_challenge(
                &format!("{}/{name}", server.uri()),
                b"body",
                Duration::from_secs(2),
                crate::transport::HttpPrecheckPolicy::LoopbackTest,
            )
            .await;
        assert!(!matches!(result, Ok(true)));
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/loop")
            .count(),
        11
    );
}
