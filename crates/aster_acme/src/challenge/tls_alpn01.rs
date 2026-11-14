//! RFC 8737 TLS-ALPN-01 response material and identifier constraints.
use crate::{
    challenge::{ChallengeError, ChallengeToken, KeyAuthorization},
    identifier::DnsIdentifier,
};

/// Inputs for an ALPN validation certificate for one non-wildcard hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsAlpn01Response {
    /// Non-wildcard certificate identifier for SNI/SAN.
    pub identifier: DnsIdentifier,
    /// Digest for the critical acmeIdentifier extension.
    pub authorization_digest: [u8; 32],
}

impl TlsAlpn01Response {
    /// Derive the digest without generating or publishing a certificate.
    ///
    /// # Errors
    /// Rejects wildcard identifiers and invalid account thumbprints.
    pub fn derive(
        identifier: &DnsIdentifier,
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
}

#[cfg(test)]
mod tests {
    use crate::challenge::{ChallengeError, ChallengeToken, tls_alpn01::TlsAlpn01Response};
    use crate::identifier::DnsIdentifier;
    const THUMBPRINT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn digest_binds_exact_token_account_and_normalized_sni_identifier() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        let domain = DnsIdentifier::new("BÜCHER.Example.").unwrap();
        let response = TlsAlpn01Response::derive(&domain, &token, THUMBPRINT).unwrap();
        assert_eq!(response.identifier.value(), "xn--bcher-kva.example");
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
    fn wildcard_and_invalid_account_binding_never_produce_certificate_inputs() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        assert_eq!(
            TlsAlpn01Response::derive(
                &DnsIdentifier::new("*.example.com").unwrap(),
                &token,
                THUMBPRINT
            ),
            Err(ChallengeError::WildcardMethod)
        );
        let domain = DnsIdentifier::new("example.com").unwrap();
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
