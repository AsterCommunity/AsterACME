//! Centralized Forge HTTP client policy for ACME traffic.

use std::time::Duration;

use aster_forge_http::{HttpClient, TlsBackend};

use crate::transport::{TransportError, TransportOptions};

/// Construct the reusable ACME HTTP connection pool with its security policy.
///
/// Redirects are disabled because ACME JWS binds an exact URL. TLS validation uses
/// reqwest's rustls platform roots. Forge owns redirect/retry/pool construction;
/// ACME supplies its User-Agent and total/connect deadlines. System proxy policy is retained.
///
/// # Errors
/// Rejects malformed user agents and reports reqwest client configuration failures.
pub(crate) fn build(options: &TransportOptions) -> Result<HttpClient, TransportError> {
    let user_agent = options
        .user_agent
        .as_deref()
        .unwrap_or(concat!("AsterACME/", env!("CARGO_PKG_VERSION")));
    validate_user_agent(user_agent)?;
    HttpClient::builder()
        .tls_backend(TlsBackend::Rustls)
        .without_read_timeout()
        .timeout(options.request_timeout)
        .connect_timeout(options.request_timeout.min(Duration::from_secs(10)))
        .user_agent(user_agent)
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

    #[test]
    fn user_agent_boundaries_are_checked_in_one_place() {
        for value in [String::new(), "bad\nagent".into(), "x".repeat(513)] {
            let options = TransportOptions {
                user_agent: Some(value),
                ..TransportOptions::default()
            };
            assert!(matches!(
                build(&options),
                Err(TransportError::InvalidUserAgent)
            ));
        }
        let options = TransportOptions {
            user_agent: Some("Aster ACME integration/1.2".into()),
            ..TransportOptions::default()
        };
        assert!(build(&options).is_ok());
    }
}
