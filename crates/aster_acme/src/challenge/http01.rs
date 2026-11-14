//! RFC 8555 section 8.3 HTTP-01 response material and identifier constraints.
use crate::{
    challenge::{ChallengeError, ChallengeToken, KeyAuthorization},
    identifier::DnsIdentifier,
};

/// Exact token response to publish for one non-wildcard hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http01Response {
    /// Non-wildcard certificate identifier.
    pub identifier: DnsIdentifier,
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
        identifier: &DnsIdentifier,
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
}

#[cfg(test)]
mod tests {
    use crate::challenge::{ChallengeError, ChallengeToken, http01::Http01Response};
    use crate::identifier::DnsIdentifier;
    const THUMBPRINT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn response_preserves_validated_token_and_full_normalized_hostname() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        let domain = DnsIdentifier::new("BÜCHER.Example.").unwrap();
        let response = Http01Response::derive(&domain, &token, THUMBPRINT).unwrap();
        assert_eq!(response.identifier.value(), "xn--bcher-kva.example");
        assert_eq!(response.token, token);
        assert_eq!(
            response.key_authorization.as_str(),
            format!("{}.{}", token.as_str(), THUMBPRINT)
        );
        let label = "a".repeat(63);
        let maximum =
            DnsIdentifier::new(&format!("{label}.{label}.{label}.{}", "b".repeat(61))).unwrap();
        assert_eq!(
            Http01Response::derive(&maximum, &token, THUMBPRINT)
                .unwrap()
                .identifier,
            maximum
        );
    }

    #[test]
    fn wildcards_and_malformed_thumbprints_never_produce_http_material() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        let wildcard = DnsIdentifier::new("*.example.com").unwrap();
        assert_eq!(
            Http01Response::derive(&wildcard, &token, THUMBPRINT),
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
                Http01Response::derive(&domain, &token, invalid),
                Err(ChallengeError::InvalidThumbprint)
            );
        }
    }
}
