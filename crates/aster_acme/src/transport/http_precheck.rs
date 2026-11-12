//! Advisory HTTP fetches pin validated DNS answers and never use ambient proxies.
use crate::transport::{HttpPool, TransportError};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

/// Public checks reject internal destinations on every redirect and DNS lookup.
#[derive(Clone, Copy, Default)]
pub enum HttpPrecheckPolicy {
    /// Public HTTP-01 checks, starting on port 80 and redirecting on 80/443.
    #[default]
    Public,
    /// Explicit local-fixture mode; only numeric loopback URLs are permitted.
    LoopbackTest,
}

impl HttpPool {
    /// Observe challenge content with at most ten redirects and an overall budget.
    /// TLS remains verified. DNS answers are validated then pinned to the request;
    /// proxies are disabled so they cannot bypass this destination restriction.
    ///
    /// # Errors
    /// Reports forbidden destinations, failed DNS/HTTP, deadlines and oversized bodies.
    pub async fn check_http_challenge(
        &self,
        url: &str,
        expected: &[u8],
        timeout: Duration,
        policy: HttpPrecheckPolicy,
    ) -> Result<bool, TransportError> {
        let mut current = url::Url::parse(url).map_err(|_| TransportError::InvalidOptions)?;
        if current.scheme() != "http" || timeout.is_zero() {
            return Err(TransportError::InvalidOptions);
        }
        let deadline = Instant::now() + timeout;
        for hop in 0..=10 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            let addresses = tokio::time::timeout(remaining, destinations(&current, policy))
                .await
                .map_err(|_| TransportError::InvalidOptions)??;
            if hop == 0
                && matches!(policy, HttpPrecheckPolicy::Public)
                && current.port_or_known_default() != Some(80)
            {
                return Err(TransportError::InvalidOptions);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            let host = current.host_str().ok_or(TransportError::InvalidOptions)?;
            let client = aster_forge_http::HttpClient::builder()
                .tls_backend(aster_forge_http::TlsBackend::Rustls)
                .no_proxy()
                .resolve_to_addrs(host, &addresses)
                .timeout(remaining)
                .build()?;
            let mut response = client
                .get(current.as_str())
                .timeout(remaining)
                .send()
                .await?;
            if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                if hop == 10 {
                    return Ok(false);
                }
                let Some(location) = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                else {
                    return Ok(false);
                };
                current = current
                    .join(location)
                    .map_err(|_| TransportError::InvalidOptions)?;
                continue;
            }
            if response.status() != reqwest::StatusCode::OK {
                return Ok(false);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if body.len().saturating_add(chunk.len()) > 8192 {
                    return Err(TransportError::BodyTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            return Ok(body
                .strip_suffix(b"\r\n")
                .or_else(|| body.strip_suffix(b"\n"))
                .unwrap_or(&body)
                == expected);
        }
        Ok(false)
    }
}

async fn destinations(
    url: &url::Url,
    policy: HttpPrecheckPolicy,
) -> Result<Vec<SocketAddr>, TransportError> {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(TransportError::InvalidOptions);
    }
    let port = url
        .port_or_known_default()
        .ok_or(TransportError::InvalidOptions)?;
    match (url.host(), policy) {
        (Some(url::Host::Ipv4(ip)), HttpPrecheckPolicy::LoopbackTest) if ip.is_loopback() => {
            return Ok(vec![SocketAddr::new(ip.into(), port)]);
        }
        (Some(url::Host::Ipv6(ip)), HttpPrecheckPolicy::LoopbackTest) if ip.is_loopback() => {
            return Ok(vec![SocketAddr::new(ip.into(), port)]);
        }
        (_, HttpPrecheckPolicy::LoopbackTest) => return Err(TransportError::InvalidOptions),
        _ => {}
    }
    if !matches!(port, 80 | 443) {
        return Err(TransportError::InvalidOptions);
    }
    let addresses = match url.host().ok_or(TransportError::InvalidOptions)? {
        url::Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
        url::Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
        url::Host::Domain(host) => tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| TransportError::InvalidOptions)?
            .collect(),
    };
    validate_addresses(addresses)
}

fn validate_addresses(addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, TransportError> {
    // Reject mixed public/private answers as a whole; never ask the HTTP pool
    // to resolve the name again after this check (DNS rebinding).
    if addresses.is_empty() || addresses.iter().any(|address| !public_ip(address.ip())) {
        return Err(TransportError::InvalidOptions);
    }
    Ok(addresses)
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || b == 0 || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Only global unicast; exclude documentation, transition and
            // special-purpose ranges that can encapsulate internal IPv4.
            (s[0] & 0xe000 == 0x2000)
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::transport::http_precheck::*;
    #[test]
    fn public_destination_policy_rejects_internal_mapped_and_mixed_answers() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002:a00:1::",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8"] {
            assert!(public_ip(ip.parse().unwrap()));
        }
        assert!(
            validate_addresses(vec![
                "1.1.1.1:80".parse().unwrap(),
                "127.0.0.1:80".parse().unwrap()
            ])
            .is_err()
        );
    }
    #[tokio::test]
    async fn explicit_fixture_policy_never_accepts_names_or_nonloopback_addresses() {
        for url in [
            "http://localhost:1234/",
            "http://10.0.0.1/",
            "http://1.1.1.1/",
        ] {
            assert!(
                destinations(
                    &url::Url::parse(url).unwrap(),
                    HttpPrecheckPolicy::LoopbackTest
                )
                .await
                .is_err()
            );
        }
        for url in ["http://127.0.0.1:8080/", "http://[::1]:8080/"] {
            assert!(
                destinations(&url::Url::parse(url).unwrap(), HttpPrecheckPolicy::Public)
                    .await
                    .is_err()
            );
            assert!(
                destinations(
                    &url::Url::parse(url).unwrap(),
                    HttpPrecheckPolicy::LoopbackTest
                )
                .await
                .is_ok()
            );
        }
    }
}

#[cfg(test)]
mod fetch_tests {
    use crate::transport::{HttpPool, HttpPrecheckPolicy};
    use std::time::Duration;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    #[tokio::test]
    async fn public_policy_never_contacts_loopback_and_each_redirect_rechecks_policy() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("Location", "http://10.1.2.3/admin"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let url = format!("{}/redirect", server.uri());
        let pool = HttpPool::default();
        assert!(
            pool.check_http_challenge(
                &url,
                b"x",
                Duration::from_secs(1),
                HttpPrecheckPolicy::Public
            )
            .await
            .is_err()
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
        assert!(
            pool.check_http_challenge(
                &url,
                b"x",
                Duration::from_secs(1),
                HttpPrecheckPolicy::LoopbackTest
            )
            .await
            .is_err()
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
