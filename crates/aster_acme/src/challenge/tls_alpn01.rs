//! [RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737) and [RFC 8738](https://datatracker.ietf.org/doc/html/rfc8738) TLS-ALPN-01 response material and identifier constraints.
use crate::{
    challenge::{ChallengeError, ChallengeToken, KeyAuthorization},
    identifier::Identifier,
};

/// Inputs for an ALPN validation certificate for one non-wildcard hostname or address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsAlpn01Response {
    /// Non-wildcard certificate identifier for SNI and the SAN.
    pub identifier: Identifier,
    /// Digest for the critical acmeIdentifier extension.
    pub authorization_digest: [u8; 32],
}

impl TlsAlpn01Response {
    /// Derive the digest without generating or publishing a certificate.
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
            authorization_digest: KeyAuthorization::new(token, thumbprint)?.sha256_digest(),
        })
    }

    /// SNI host name for this validation certificate. [RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066) forbids IP    /// literals in SNI, so [RFC 8738 §6](https://datatracker.ietf.org/doc/html/rfc8738#section-6) mandates the IN-ADDR.ARPA or    /// IP6.ARPA reverse mapping of the address instead of its textual form.
    #[must_use]
    pub fn sni_name(&self) -> String {
        match &self.identifier {
            Identifier::Dns(dns) => dns.value(),
            Identifier::Ip(ip) => ip.reverse_name(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::challenge::{ChallengeError, ChallengeToken, tls_alpn01::TlsAlpn01Response};
    use crate::identifier::{DnsIdentifier, Identifier};
    const THUMBPRINT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn digest_binds_exact_token_account_and_normalized_sni_identifier() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        let domain = Identifier::Dns(DnsIdentifier::new("BÜCHER.Example.").unwrap());
        let response = TlsAlpn01Response::derive(&domain, &token, THUMBPRINT).unwrap();
        assert_eq!(response.identifier.value(), "xn--bcher-kva.example");
        assert_eq!(response.sni_name(), "xn--bcher-kva.example");
        assert_eq!(response.authorization_digest.len(), 32);
        let other = ChallengeToken::new("other-long-enough-opaque-challenge-token").unwrap();
        assert_ne!(
            response.authorization_digest,
            TlsAlpn01Response::derive(&domain, &other, THUMBPRINT)
                .unwrap()
                .authorization_digest
        );
        let other_thumbprint = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
        assert_ne!(
            response.authorization_digest,
            TlsAlpn01Response::derive(&domain, &token, other_thumbprint)
                .unwrap()
                .authorization_digest
        );
    }

    #[test]
    fn ip_identifiers_use_reversed_arpa_sni_names() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        let ipv4 =
            TlsAlpn01Response::derive(&Identifier::new("192.0.2.1").unwrap(), &token, THUMBPRINT)
                .unwrap();
        assert_eq!(ipv4.sni_name(), "1.2.0.192.in-addr.arpa");
        let ipv6 =
            TlsAlpn01Response::derive(&Identifier::new("2001:db8::1").unwrap(), &token, THUMBPRINT)
                .unwrap();
        assert_eq!(
            ipv6.sni_name(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn wildcard_and_invalid_account_binding_never_produce_certificate_inputs() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        assert_eq!(
            TlsAlpn01Response::derive(
                &Identifier::Dns(DnsIdentifier::new("*.example.com").unwrap()),
                &token,
                THUMBPRINT
            ),
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
                TlsAlpn01Response::derive(&domain, &token, invalid),
                Err(ChallengeError::InvalidThumbprint)
            );
        }
    }
}
