//! Advisory HTTP checks share the normal connection pool and operator proxy policy.
use crate::transport::{HttpPool, TransportError};
use std::time::{Duration, Instant};

impl HttpPool {
    /// Observe challenge content with at most ten redirects and an overall budget.
    /// TLS remains verified. System/environment proxies and internal destinations
    /// are supported: this operator-initiated check is advisory, not an SSRF boundary.
    ///
    /// # Errors
    /// Reports unsupported URLs/ports, failed DNS/HTTP, deadlines and oversized bodies.
    pub async fn check_http_challenge(
        &self,
        url: &str,
        expected: &[u8],
        timeout: Duration,
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
            validate_target(&current)?;
            // Preserve the CA-compatible redirect port restriction. Numeric
            // loopback services may use ephemeral ports for local integrations.
            let permitted_port = if hop == 0 {
                current.port_or_known_default() == Some(80)
            } else {
                matches!(current.port_or_known_default(), Some(80 | 443))
            };
            if !permitted_port
                && !current.host_str().is_some_and(|host| {
                    host.trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
                })
            {
                return Err(TransportError::InvalidOptions);
            }
            let client = self.client().await?;
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

fn validate_target(url: &url::Url) -> Result<(), TransportError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(TransportError::InvalidOptions);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
