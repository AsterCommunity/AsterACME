//! RFC 8555 section 8.4 DNS-01 TXT material and owner constraints.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{
    challenge::{ChallengeError, ChallengeToken, KeyAuthorization},
    identifier::{DnsIdentifier, DnsName},
};

/// One temporary DNS-01 TXT publication; values at a shared owner must coexist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dns01Record {
    /// Owner name, including `_acme-challenge`.
    pub record_name: DnsName,
    /// Unpadded base64url SHA-256 key authorization digest.
    pub txt_value: String,
}

impl Dns01Record {
    /// Derive a token-bound TXT record, including for a wildcard's base domain.
    ///
    /// # Errors
    /// Rejects invalid account thumbprints and oversized TXT owners.
    pub fn derive(
        identifier: &DnsIdentifier,
        token: &ChallengeToken,
        thumbprint: &str,
    ) -> Result<Self, ChallengeError> {
        let authorization = KeyAuthorization::new(token, thumbprint)?;
        Ok(Self {
            record_name: DnsName::new(&format!("_acme-challenge.{}", identifier.name().as_str()))?,
            txt_value: URL_SAFE_NO_PAD.encode(authorization.sha256_digest()),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::challenge::{ChallengeError, ChallengeToken, dns01::Dns01Record};
    use crate::identifier::DnsIdentifier;
    const THUMBPRINT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn normalization_wildcards_and_binding_are_owned_by_dns01() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        let base = DnsIdentifier::new("BÜCHER.Example.").unwrap();
        let wildcard = DnsIdentifier::new("*.bücher.example").unwrap();
        let record = Dns01Record::derive(&base, &token, THUMBPRINT).unwrap();
        assert_eq!(
            record.record_name.as_str(),
            "_acme-challenge.xn--bcher-kva.example"
        );
        assert_eq!(
            record,
            Dns01Record::derive(&wildcard, &token, THUMBPRINT).unwrap()
        );
        let other = ChallengeToken::new("other-long-enough-opaque-challenge-token").unwrap();
        assert_ne!(
            record.txt_value,
            Dns01Record::derive(&base, &other, THUMBPRINT)
                .unwrap()
                .txt_value
        );
        for invalid in [
            "",
            "invalid",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ] {
            assert_eq!(
                Dns01Record::derive(&base, &token, invalid),
                Err(ChallengeError::InvalidThumbprint)
            );
        }
    }

    #[test]
    fn exact_txt_owner_length_boundary_does_not_truncate_the_identifier() {
        let token = ChallengeToken::new("long-enough-opaque-challenge-token").unwrap();
        let label = "a".repeat(63);
        for (last, accepted) in [(45, true), (46, false)] {
            let domain =
                DnsIdentifier::new(&format!("{label}.{label}.{label}.{}", "b".repeat(last)))
                    .unwrap();
            assert_eq!(
                Dns01Record::derive(&domain, &token, THUMBPRINT).is_ok(),
                accepted
            );
        }
    }
}
