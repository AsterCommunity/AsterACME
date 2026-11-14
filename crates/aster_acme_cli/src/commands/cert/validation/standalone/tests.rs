//! Real loopback sockets exercise parsing, publication, bounds and release semantics.
use crate::commands::cert::validation::standalone::*;
use crate::commands::cert::validation::tests::publications;
use crate::commands::cert::validation::tests::{execution, progress};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn material(domain: &str, token: &str) -> ValidationRequirement {
    ValidationRequirement::Http01 {
        url: format!("http://{domain}/.well-known/acme-challenge/{token}"),
        path: format!("/.well-known/acme-challenge/{token}"),
        content: format!("{token}.account_thumbprint"),
    }
}

const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz012345";
const OTHER: &str = "zyxwvutsrqponmlkjihgfedcba987654";

async fn start() -> (Standalone, SocketAddr) {
    let solver = Standalone::new(([127, 0, 0, 1], 0).into(), progress());
    solver
        .ready(
            &publications(&[
                material("example.com", TOKEN),
                material("other.example", OTHER),
            ]),
            &execution(),
        )
        .await
        .unwrap();
    let address = solver.listener.lock().await.as_ref().unwrap().address;
    (solver, address)
}

async fn request(address: SocketAddr, request: &str) -> String {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut output = String::new();
        if let Err(error) = stream.read_to_string(&mut output).await {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        }
        output
    })
    .await
    .unwrap()
}

async fn assert_released(address: SocketAddr) {
    // Shutdown joins all tasks; bindability proves the listener is actually gone.
    let rebound = tokio::net::TcpListener::bind(address).await.unwrap();
    drop(rebound);
}

#[tokio::test]
async fn exact_host_path_get_multiple_domains_and_tokens_only() {
    let (solver, address) = start().await;
    for (host, token) in [
        ("example.com", TOKEN),
        ("EXAMPLE.COM:80", TOKEN),
        ("example.com.", TOKEN),
        ("other.example", OTHER),
    ] {
        let response = request(
            address,
            &format!("GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: {host}\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with(&format!("{token}.account_thumbprint")));
        assert!(response.contains("cache-control: no-store"));
    }
    for (host, path) in [
        (
            "unrelated.example",
            format!("/.well-known/acme-challenge/{TOKEN}"),
        ),
        (
            "example.com",
            format!("/.well-known/acme-challenge/{OTHER}"),
        ),
        ("example.com", "/".into()),
        ("example.com", "/private-key.pk8".into()),
        ("example.com", "/.well-known/acme-challenge/../token".into()),
        (
            "example.com",
            format!("/.well-known/acme-challenge/{TOKEN}?extra=1"),
        ),
        (
            "example.com",
            "/.well-known/acme-challenge/%61bcdefghijklmnopqrstuvwxyz012345".into(),
        ),
    ] {
        let response = request(
            address,
            &format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
        assert!(!response.contains("account_thumbprint"));
    }
    solver.shutdown().await;
    assert_released(address).await;
}

#[tokio::test]
async fn rejects_other_methods_proxy_requests_bodies_and_ambiguous_hosts() {
    let (solver, address) = start().await;
    for method in ["HEAD", "POST", "PUT", "DELETE", "OPTIONS", "CONNECT"] {
        let response = request(
            address,
            &format!(
                "{method} /.well-known/acme-challenge/{TOKEN} HTTP/1.1\r\nHost: example.com\r\n\r\n"
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 405"), "{response}");
        assert!(!response.contains("account_thumbprint"));
    }
    for raw in [
        format!(
            "GET http://example.com/.well-known/acme-challenge/{TOKEN} HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ),
        format!("GET /.well-known/acme-challenge/{TOKEN} HTTP/1.0\r\n\r\n"),
        format!(
            "GET /.well-known/acme-challenge/{TOKEN} HTTP/1.1\r\nHost: example.com\r\nHost: other.example\r\n\r\n"
        ),
        format!(
            "GET /.well-known/acme-challenge/{TOKEN} HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\nx"
        ),
        format!(
            "GET /.well-known/acme-challenge/{TOKEN} HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        ),
    ] {
        let response = request(address, &raw).await;
        assert!(!response.starts_with("HTTP/1.1 200"));
        assert!(!response.starts_with("HTTP/1.0 200"));
        assert!(!response.contains("account_thumbprint"));
    }
    solver.shutdown().await;
}

#[tokio::test]
async fn idempotent_publication_can_add_material_but_never_replace_it() {
    let (solver, address) = start().await;
    solver
        .ready(
            &publications(&[material("example.com", TOKEN)]),
            &execution(),
        )
        .await
        .unwrap();
    solver
        .ready(
            &publications(&[material("example.com", OTHER)]),
            &execution(),
        )
        .await
        .unwrap();
    assert_eq!(
        solver.listener.lock().await.as_ref().unwrap().address,
        address
    );
    let mut changed = material("example.com", TOKEN);
    if let ValidationRequirement::Http01 { content, .. } = &mut changed {
        content.push('x');
    }
    assert!(
        solver
            .ready(&publications(&[changed]), &execution())
            .await
            .is_err()
    );
    let response = request(
        address,
        &format!("GET /.well-known/acme-challenge/{TOKEN} HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    )
    .await;
    assert!(response.ends_with(&format!("{TOKEN}.account_thumbprint")));
    assert!(
        solver
            .cleanup(&publications(&[]), &execution())
            .await
            .unwrap()
            .failure
            .is_none()
    );
    solver.shutdown().await;
    assert_released(address).await;
}

#[tokio::test]
async fn occupied_port_fails_without_displacing_existing_server() {
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    let solver = Standalone::new(address, progress());
    let error = solver
        .ready(
            &publications(&[material("example.com", TOKEN)]),
            &execution(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, IssueError::Publication(_)));
    assert!(error.to_string().contains(&address.to_string()));
    assert!(tokio::net::TcpStream::connect(address).await.is_ok());
}

#[tokio::test]
async fn cancelled_expired_contexts_do_not_bind_and_active_services_stop() {
    for expired in [false, true] {
        let context = ExecutionContext {
            deadline: if expired {
                Instant::now()
            } else {
                execution().deadline
            },
            ..execution()
        };
        if !expired {
            context.cancellation.cancel();
        }
        let solver = Standalone::new(([127, 0, 0, 1], 0).into(), progress());
        assert!(matches!(
            solver
                .ready(&publications(&[material("example.com", TOKEN)]), &context)
                .await,
            Err(IssueError::Interrupted)
        ));
        assert!(solver.listener.lock().await.is_none());
    }
    for expired in [false, true] {
        let context = ExecutionContext {
            deadline: Instant::now() + Duration::from_millis(50),
            ..execution()
        };
        let solver = Standalone::new(([127, 0, 0, 1], 0).into(), progress());
        solver
            .ready(&publications(&[material("example.com", TOKEN)]), &context)
            .await
            .unwrap();
        let address = solver.listener.lock().await.as_ref().unwrap().address;
        let _idle = tokio::net::TcpStream::connect(address).await.unwrap();
        if !expired {
            context.cancellation.cancel();
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if solver.listener.lock().await.as_ref().unwrap().is_finished() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        solver.shutdown().await;
        assert_released(address).await;
    }
}

#[tokio::test]
async fn drop_releases_socket_and_idle_connections() {
    let (solver, address) = start().await;
    let mut idle = tokio::net::TcpStream::connect(address).await.unwrap();
    tokio::task::yield_now().await;
    drop(solver);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(listener) = tokio::net::TcpListener::bind(address).await {
                drop(listener);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut byte = [0];
    match tokio::time::timeout(Duration::from_secs(1), idle.read(&mut byte))
        .await
        .unwrap()
    {
        Ok(count) => assert_eq!(count, 0),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
}

#[tokio::test]
async fn oversized_headers_are_rejected_without_stopping_listener() {
    let (solver, address) = start().await;
    let response = request(
        address,
        &format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nX-Large: {}\r\n\r\n",
            "a".repeat(9000)
        ),
    )
    .await;
    // Some kernels reset a socket closed with unread oversized input before
    // delivering Hyper's 431. Both reject it; neither exposes challenge content.
    assert!(response.is_empty() || response.starts_with("HTTP/1.1 431"));
    assert!(
        solver
            .ready(
                &publications(&[material("example.com", TOKEN)]),
                &execution()
            )
            .await
            .unwrap()
            .ready
    );
    solver.shutdown().await;
}

#[test]
fn material_validation_rejects_other_methods_bad_paths_urls_and_conflicts() {
    assert!(validate(&[]).is_err());
    assert!(
        validate(&[ValidationRequirement::Dns01 {
            name: "x".into(),
            value: "y".into()
        }])
        .is_err()
    );
    for path in [
        "/",
        "/.well-known/acme-challenge/../key",
        "/.well-known/acme-challenge/%20",
    ] {
        let mut requirement = material("example.com", TOKEN);
        if let ValidationRequirement::Http01 { path: p, .. } = &mut requirement {
            *p = path.into();
        }
        assert!(validate(&[requirement]).is_err());
    }
    for url in [
        "https://example.com",
        "http://127.0.0.1",
        "http://example.com:8080",
        "http://u:p@example.com",
        "http://example.com/",
    ] {
        let mut requirement = material("example.com", TOKEN);
        if let ValidationRequirement::Http01 { url: u, .. } = &mut requirement {
            *u = format!("{url}/.well-known/acme-challenge/{TOKEN}");
        }
        assert!(validate(&[requirement]).is_err());
    }
    for content in [
        "wrong".to_owned(),
        format!("{TOKEN}.\r\nx"),
        format!("{TOKEN}.{}", "a".repeat(8192)),
    ] {
        let mut requirement = material("example.com", TOKEN);
        if let ValidationRequirement::Http01 { content: c, .. } = &mut requirement {
            *c = content;
        }
        assert!(validate(&[requirement]).is_err());
    }
    let first = material("example.com", TOKEN);
    let mut other = first.clone();
    if let ValidationRequirement::Http01 { content, .. } = &mut other {
        content.push('x');
    }
    assert!(validate(&[first.clone(), other]).is_err());
    assert_eq!(validate(&[first.clone(), first]).unwrap().len(), 1);
}

#[tokio::test]
async fn ipv6_listener_uses_same_lifecycle_when_loopback_is_available() {
    let solver = Standalone::new("[::1]:0".parse().unwrap(), progress());
    if tokio::net::TcpListener::bind("[::1]:0").await.is_err() {
        return;
    }
    solver
        .ready(
            &publications(&[material("example.com", TOKEN)]),
            &execution(),
        )
        .await
        .unwrap();
    let address = solver.listener.lock().await.as_ref().unwrap().address;
    assert!(
        request(
            address,
            &format!(
                "GET /.well-known/acme-challenge/{TOKEN} HTTP/1.1\r\nHost: example.com\r\n\r\n"
            )
        )
        .await
        .starts_with("HTTP/1.1 200")
    );
    solver.shutdown().await;
    assert_released(address).await;
}
