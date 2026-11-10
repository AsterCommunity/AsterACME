//! RFC 8555 problem documents and standard problem identifiers.
use serde::{Deserialize, Serialize};

aster_forge_macros::wire_enum! {
    /// RFC 8555 section 6.7 problem types; future extensions remain lossless.
    pub enum ProblemKind {
        /// RFC 9773: predecessor was already replaced by another order.
        AlreadyReplaced => "urn:ietf:params:acme:error:alreadyReplaced",
        /// Account identity does not exist.
        AccountDoesNotExist => "urn:ietf:params:acme:error:accountDoesNotExist",
        /// Certificate was already revoked.
        AlreadyRevoked => "urn:ietf:params:acme:error:alreadyRevoked",
        /// The CSR is unacceptable.
        BadCsr => "urn:ietf:params:acme:error:badCSR",
        /// Nonce rejected; retry with the supplied fresh nonce.
        BadNonce => "urn:ietf:params:acme:error:badNonce",
        /// Unsupported JWS public key.
        BadPublicKey => "urn:ietf:params:acme:error:badPublicKey",
        /// CA policy rejects the requested revocation reason.
        BadRevocationReason => "urn:ietf:params:acme:error:badRevocationReason",
        /// Unsupported JWS signing algorithm.
        BadSignatureAlgorithm => "urn:ietf:params:acme:error:badSignatureAlgorithm",
        /// CAA records forbid issuance.
        Caa => "urn:ietf:params:acme:error:caa",
        /// Inspect per-identifier subproblems.
        Compound => "urn:ietf:params:acme:error:compound",
        /// CA could not connect to the validation target.
        Connection => "urn:ietf:params:acme:error:connection",
        /// DNS validation query failed.
        Dns => "urn:ietf:params:acme:error:dns",
        /// External account binding is required.
        ExternalAccountRequired => "urn:ietf:params:acme:error:externalAccountRequired",
        /// Challenge response did not match.
        IncorrectResponse => "urn:ietf:params:acme:error:incorrectResponse",
        /// Invalid contact URI.
        InvalidContact => "urn:ietf:params:acme:error:invalidContact",
        /// Malformed request.
        Malformed => "urn:ietf:params:acme:error:malformed",
        /// Order is not ready to finalize.
        OrderNotReady => "urn:ietf:params:acme:error:orderNotReady",
        /// Request rate limit exceeded.
        RateLimited => "urn:ietf:params:acme:error:rateLimited",
        /// CA refuses the requested identifier.
        RejectedIdentifier => "urn:ietf:params:acme:error:rejectedIdentifier",
        /// CA internal error.
        ServerInternal => "urn:ietf:params:acme:error:serverInternal",
        /// TLS validation error.
        Tls => "urn:ietf:params:acme:error:tls",
        /// Account is not authorized.
        Unauthorized => "urn:ietf:params:acme:error:unauthorized",
        /// Unsupported contact scheme.
        UnsupportedContact => "urn:ietf:params:acme:error:unsupportedContact",
        /// Unsupported identifier type.
        UnsupportedIdentifier => "urn:ietf:params:acme:error:unsupportedIdentifier",
        /// Operator action is required.
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
    use super::*;

    #[test]
    fn rfc8555_problem_types_roundtrip_and_extensions_remain_lossless() {
        for wire in [
            "accountDoesNotExist",
            "alreadyRevoked",
            "badCSR",
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
            "malformed",
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
