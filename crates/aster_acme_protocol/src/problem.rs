//! ACME problem documents and IANA-registered problem identifiers.
use serde::{Deserialize, Serialize};

aster_forge_macros::wire_enum! {
    /// IANA ACME error types, including RFC 8555 §6.7 and registered extensions; unknown types remain lossless.
    pub enum ProblemKind {
        /// RFC 9773 §5: predecessor was already replaced by another order.
        AlreadyReplaced => "urn:ietf:params:acme:error:alreadyReplaced",
        /// RFC 8739: an auto-renewal order was explicitly canceled.
        AutoRenewalCanceled => "urn:ietf:params:acme:error:autoRenewalCanceled",
        /// RFC 8739: an auto-renewal order expired.
        AutoRenewalExpired => "urn:ietf:params:acme:error:autoRenewalExpired",
        /// RFC 8739: an auto-renewal cancellation request was invalid.
        AutoRenewalCancellationInvalid => "urn:ietf:params:acme:error:autoRenewalCancellationInvalid",
        /// RFC 8739: auto-renewal certificate revocation is unsupported.
        AutoRenewalRevocationNotSupported => "urn:ietf:params:acme:error:autoRenewalRevocationNotSupported",
        /// RFC 8555 §6.7: Account identity does not exist.
        AccountDoesNotExist => "urn:ietf:params:acme:error:accountDoesNotExist",
        /// RFC 8555 §6.7: Certificate was already revoked.
        AlreadyRevoked => "urn:ietf:params:acme:error:alreadyRevoked",
        /// RFC 8555 §6.7: The CSR is unacceptable.
        BadCsr => "urn:ietf:params:acme:error:badCSR",
        /// RFC 8555 §6.7: Nonce rejected; retry with the supplied fresh nonce.
        BadNonce => "urn:ietf:params:acme:error:badNonce",
        /// RFC 8555 §6.7: Unsupported JWS public key.
        BadPublicKey => "urn:ietf:params:acme:error:badPublicKey",
        /// RFC 8555 §6.7: CA policy rejects the requested revocation reason.
        BadRevocationReason => "urn:ietf:params:acme:error:badRevocationReason",
        /// RFC 8555 §6.7: Unsupported JWS signing algorithm.
        BadSignatureAlgorithm => "urn:ietf:params:acme:error:badSignatureAlgorithm",
        /// `draft-ietf-acme-device-attest-09` (IANA reference `RFC-ietf-acme-device-attest-09`): unacceptable device attestation; not a published RFC.
        BadAttestationStatement => "urn:ietf:params:acme:error:badAttestationStatement",
        /// RFC 8555 §6.7: CAA records forbid issuance.
        Caa => "urn:ietf:params:acme:error:caa",
        /// RFC 8555 §6.7: Inspect per-identifier subproblems.
        Compound => "urn:ietf:params:acme:error:compound",
        /// RFC 8555 §6.7: CA could not connect to the validation target.
        Connection => "urn:ietf:params:acme:error:connection",
        /// RFC 8555 §6.7: DNS validation query failed.
        Dns => "urn:ietf:params:acme:error:dns",
        /// RFC 8555 §6.7: External account binding is required.
        ExternalAccountRequired => "urn:ietf:params:acme:error:externalAccountRequired",
        /// RFC 8555 §6.7: Challenge response did not match.
        IncorrectResponse => "urn:ietf:params:acme:error:incorrectResponse",
        /// RFC 8555 §6.7: Invalid contact URI.
        InvalidContact => "urn:ietf:params:acme:error:invalidContact",
        /// RFC 9115: the order delegation configuration is unknown.
        UnknownDelegation => "urn:ietf:params:acme:error:unknownDelegation",
        /// RFC 8555 §6.7: Malformed request.
        Malformed => "urn:ietf:params:acme:error:malformed",
        /// RFC 8555 §6.7: Order is not ready to finalize.
        OrderNotReady => "urn:ietf:params:acme:error:orderNotReady",
        /// RFC 9799 §6.4.1: in-band onion CAA was required.
        OnionCaaRequired => "urn:ietf:params:acme:error:onionCAARequired",
        /// RFC 8555 §6.7: Request rate limit exceeded.
        RateLimited => "urn:ietf:params:acme:error:rateLimited",
        /// RFC 8555 §6.7: CA refuses the requested identifier.
        RejectedIdentifier => "urn:ietf:params:acme:error:rejectedIdentifier",
        /// RFC 8555 §6.7: CA internal error.
        ServerInternal => "urn:ietf:params:acme:error:serverInternal",
        /// RFC 8555 §6.7: TLS validation error.
        Tls => "urn:ietf:params:acme:error:tls",
        /// RFC 8555 §6.7: Account is not authorized.
        Unauthorized => "urn:ietf:params:acme:error:unauthorized",
        /// RFC 8555 §6.7: Unsupported contact scheme.
        UnsupportedContact => "urn:ietf:params:acme:error:unsupportedContact",
        /// RFC 8555 §6.7: Unsupported identifier type.
        UnsupportedIdentifier => "urn:ietf:params:acme:error:unsupportedIdentifier",
        /// RFC 8555 §6.7: Operator action is required.
        UserActionRequired => "urn:ietf:params:acme:error:userActionRequired",
    }
}

impl std::fmt::Display for ProblemKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from(self.clone()))
    }
}

/// ACME problem document, including extension details and nested subproblems.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Problem {
    /// Full problem URI; unknown namespaces are preserved.
    #[serde(rename = "type")]
    pub kind: ProblemKind,
    /// Human-readable server explanation.
    pub detail: Option<String>,
    /// User action URL or problem instance.
    pub instance: Option<String>,
    /// Per-identifier failures.
    #[serde(default)]
    pub subproblems: Vec<Problem>,
    /// Extra fields such as supported algorithms or failing identifiers.
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use crate::problem::*;

    #[test]
    fn rfc8555_problem_types_roundtrip_and_extensions_remain_lossless() {
        for wire in [
            "accountDoesNotExist",
            "alreadyRevoked",
            "autoRenewalCanceled",
            "autoRenewalExpired",
            "autoRenewalCancellationInvalid",
            "autoRenewalRevocationNotSupported",
            "alreadyReplaced",
            "badCSR",
            "badAttestationStatement",
            "badNonce",
            "badPublicKey",
            "badRevocationReason",
            "badSignatureAlgorithm",
            "caa",
            "compound",
            "connection",
            "dns",
            "externalAccountRequired",
            "incorrectResponse",
            "invalidContact",
            "unknownDelegation",
            "malformed",
            "onionCAARequired",
            "orderNotReady",
            "rateLimited",
            "rejectedIdentifier",
            "serverInternal",
            "tls",
            "unauthorized",
            "unsupportedContact",
            "unsupportedIdentifier",
            "userActionRequired",
        ] {
            let uri = format!("urn:ietf:params:acme:error:{wire}");
            let kind = ProblemKind::from(uri.clone());
            assert!(!matches!(kind, ProblemKind::Unknown(_)));
            assert_eq!(kind.to_string(), uri);
            assert_eq!(
                serde_json::from_value::<ProblemKind>(serde_json::json!(uri)).unwrap(),
                kind
            );
            assert_eq!(serde_json::to_value(kind).unwrap(), uri);
        }
        for uri in [
            "",
            "urn:ietf:params:acme:error:future",
            "https://ca.example/error",
            "urn:ietf:params:acme:error:BadNonce",
        ] {
            let kind = ProblemKind::from(uri.to_owned());
            assert_eq!(kind, ProblemKind::Unknown(uri.to_owned()));
            assert_eq!(kind.to_string(), uri);
        }
        assert!(serde_json::from_str::<ProblemKind>("400").is_err());
    }
}
