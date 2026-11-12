//! Proxy tests isolate environment changes in a child process, never the test runner.
use crate::transport::{HttpPool, http_precheck::validate_target};
use std::time::Duration;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[test]
fn internal_targets_are_accepted_but_url_security_constraints_remain() {
    for target in [
        "http://127.0.0.1/",
        "http://10.1.2.3/",
        "https://192.168.1.1/",
        "http://[::1]/",
        "http://internal.example/",
    ] {
        assert!(validate_target(&url::Url::parse(target).unwrap()).is_ok());
    }
    for target in [
        "file:///tmp/test",
        "http://user:secret@localhost/",
        "http://localhost/#fragment",
    ] {
        assert!(validate_target(&url::Url::parse(target).unwrap()).is_err());
    }
}

#[tokio::test]
async fn environment_proxy_handles_a_name_unresolvable_locally_and_redirects() {
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "http://internal-target.invalid/end"),
        )
        .expect(1)
        .mount(&proxy)
        .await;
    Mock::given(method("GET"))
        .and(path("/end"))
        .respond_with(ResponseTemplate::new(200).set_body_string("token.thumb"))
        .expect(1)
        .mount(&proxy)
        .await;
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "transport::http_precheck::tests::proxy_child",
        "--ignored",
    ]);
    // No global set_var/unsafe: only this child receives the proxy settings.
    for key in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(key);
    }
    command
        .env("http_proxy", proxy.uri())
        .env("HTTP_PROXY", proxy.uri())
        .env("NO_PROXY", "");
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "isolated proxy environment fixture"]
async fn proxy_child() {
    assert!(
        HttpPool::default()
            .check_http_challenge(
                "http://proxy-only.invalid/start",
                b"token.thumb",
                Duration::from_secs(5)
            )
            .await
            .unwrap()
    );
}
