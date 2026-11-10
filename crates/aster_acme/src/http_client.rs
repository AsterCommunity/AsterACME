//! Centralized reqwest client policy for ACME traffic.

use std::time::Duration;

use reqwest::{Client, redirect::Policy};

use crate::transport::{TransportError, TransportOptions};

/// Construct the reusable ACME HTTP connection pool with its security policy.
///
/// Redirects are disabled because ACME JWS binds an exact URL. TLS validation uses
/// reqwest's rustls platform roots. No proxy, cookie, or decompression policy is enabled here.
///
/// # Errors
/// Rejects malformed user agents and reports reqwest client configuration failures.
pub(crate) fn build(options: &TransportOptions) -> Result<Client, TransportError> {
    let user_agent = options
        .user_agent
        .as_deref()
        .unwrap_or(concat!("AsterACME/", env!("CARGO_PKG_VERSION")));
    if user_agent.is_empty() || user_agent.len() > 512 || user_agent.chars().any(char::is_control) {
        return Err(TransportError::InvalidUserAgent);
    }
    Client::builder()
        .redirect(Policy::none())
        .timeout(options.request_timeout)
        .connect_timeout(options.request_timeout.min(Duration::from_secs(10)))
        .user_agent(user_agent)
        .build()
        .map_err(TransportError::Network)
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
