//! Centralized Forge HTTP client policy for ACME traffic.

use std::time::Duration;

use aster_forge_http::{HttpClient, TlsBackend};

use crate::transport::TransportError;

/// Construct the reusable ACME HTTP connection pool with its security policy.
///
/// Redirects are disabled because ACME JWS binds an exact URL. TLS validation uses
/// reqwest's rustls platform roots. Forge owns redirect/retry/pool construction;
/// ACME applies User-Agent and total deadlines per request; connecting is also bounded
/// by the shorter of that deadline and the pool's ten-second connect limit.
/// System proxy policy is retained.
///
/// # Errors
/// Reports reqwest client configuration failures. Request-specific agents are validated separately.
pub(crate) fn build() -> Result<HttpClient, TransportError> {
    HttpClient::builder()
        .tls_backend(TlsBackend::Rustls)
        .without_read_timeout()
        .without_total_timeout()
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("AsterACME/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(TransportError::Network)
}

/// Shared validation for an explicit command User-Agent override.
///
/// # Errors
/// Rejects empty, oversized, or control-character-containing header values.
pub(crate) fn validate_user_agent(user_agent: &str) -> Result<(), TransportError> {
    if user_agent.is_empty() || user_agent.len() > 512 || user_agent.chars().any(char::is_control) {
        Err(TransportError::InvalidUserAgent)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportOptions;

    #[test]
    fn user_agent_boundaries_are_checked_in_one_place() {
        for value in [String::new(), "bad\nagent".into(), "x".repeat(513)] {
            let options = TransportOptions {
                user_agent: Some(value),
                ..TransportOptions::default()
            };
            assert!(matches!(
                options.validate(),
                Err(TransportError::InvalidUserAgent)
            ));
        }
        let options = TransportOptions {
            user_agent: Some("Aster ACME integration/1.2".into()),
            ..TransportOptions::default()
        };
        assert!(options.validate().is_ok());
        assert!(build().is_ok());
    }
}
