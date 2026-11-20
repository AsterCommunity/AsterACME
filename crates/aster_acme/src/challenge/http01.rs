//! [RFC 8555 §8.3](https://datatracker.ietf.org/doc/html/rfc8555#section-8.3) and [RFC 8738 §5](https://datatracker.ietf.org/doc/html/rfc8738#section-5) HTTP-01 response material and
//! identifier constraints.
use crate::{
    challenge::{ChallengeError, ChallengeToken, KeyAuthorization},
    identifier::Identifier,
};
use std::net::IpAddr;

/// Exact token response to publish for one non-wildcard hostname or address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http01Response {
    /// Non-wildcard certificate identifier.
    pub identifier: Identifier,
    /// Validated request-path segment.
    pub token: ChallengeToken,
    /// Response body, without account private key material.
    pub key_authorization: KeyAuthorization,
}

impl Http01Response {
    /// Bind the CA token to the account's JWK thumbprint.
    ///
    /// # Errors
    /// Rejects wildcard identifiers and invalid account thumbprints.
    pub fn derive(
        identifier: &Identifier,
        token: &ChallengeToken,
        thumbprint: &str,
    ) -> Result<Self, ChallengeError> {
        if identifier.is_wildcard() {
            return Err(ChallengeError::WildcardMethod);
        }
        Ok(Self {
            identifier: identifier.clone(),
            token: token.clone(),
            key_authorization: KeyAuthorization::new(token, thumbprint)?,
        })
    }

    /// Host authority for the HTTP-01 URL and request Host header. IPv6 uses
    /// the bracketed form required by [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986) and [RFC 8738 §5](https://datatracker.ietf.org/doc/html/rfc8738#section-5).
    #[must_use]
    pub fn host(&self) -> String {
        match &self.identifier {
            Identifier::Dns(dns) => dns.value(),
            Identifier::Ip(ip) => match ip.address() {
                IpAddr::V4(_) => self.identifier.value(),
                IpAddr::V6(_) => format!("[{}]", self.identifier.value()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::challenge::{ChallengeError, ChallengeToken, http01::Http01Response};
    use crate::identifier::{DnsIdentifier, Identifier};
    const THUMBPRINT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn response_preserves_validated_token_and_full_normalized_hostname() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        let domain = Identifier::Dns(DnsIdentifier::new("BÜCHER.Example.").unwrap());
        let response = Http01Response::derive(&domain, &token, THUMBPRINT).unwrap();
        assert_eq!(response.identifier.value(), "xn--bcher-kva.example");
        assert_eq!(response.host(), "xn--bcher-kva.example");
        assert_eq!(response.token, token);
        assert_eq!(
            response.key_authorization.as_str(),
            format!("{}.{}", token.as_str(), THUMBPRINT)
        );
        let label = "a".repeat(63);
        let maximum = Identifier::Dns(
            DnsIdentifier::new(&format!("{label}.{label}.{label}.{}", "b".repeat(61))).unwrap(),
        );
        assert_eq!(
            Http01Response::derive(&maximum, &token, THUMBPRINT)
                .unwrap()
                .identifier,
            maximum
        );
    }

    #[test]
    fn ip_identifiers_derive_material_and_bare_or_bracketed_hosts() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        let ipv4 = Identifier::new("192.0.2.1").unwrap();
        let response = Http01Response::derive(&ipv4, &token, THUMBPRINT).unwrap();
        assert_eq!(response.host(), "192.0.2.1");
        let ipv6 = Identifier::new("2001:DB8::1").unwrap();
        let response = Http01Response::derive(&ipv6, &token, THUMBPRINT).unwrap();
        assert_eq!(response.identifier.value(), "2001:db8::1");
        assert_eq!(response.host(), "[2001:db8::1]");
    }

    #[test]
    fn wildcards_and_malformed_thumbprints_never_produce_http_material() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        let wildcard = Identifier::Dns(DnsIdentifier::new("*.example.com").unwrap());
        assert_eq!(
            Http01Response::derive(&wildcard, &token, THUMBPRINT),
            Err(ChallengeError::WildcardMethod)
        );
        let domain = Identifier::Dns(DnsIdentifier::new("example.com").unwrap());
        for invalid in [
            "",
            "invalid",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ] {
            assert_eq!(
                Http01Response::derive(&domain, &token, invalid),
                Err(ChallengeError::InvalidThumbprint)
            );
        }
    }
}
