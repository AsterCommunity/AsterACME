//! RFC 8555 problem documents and standard problem identifiers.
use serde::{Deserialize, Serialize};

/// Nonce rejected; retry only with a fresh nonce and bounded policy.
pub const BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";
/// No existing account is associated with the supplied key.
pub const ACCOUNT_DOES_NOT_EXIST: &str = "urn:ietf:params:acme:error:accountDoesNotExist";

/// Rate limiting problem identifier.
pub const RATE_LIMITED: &str = "urn:ietf:params:acme:error:rateLimited";
/// User interaction required by the CA.
pub const USER_ACTION_REQUIRED: &str = "urn:ietf:params:acme:error:userActionRequired";
/// External account credentials required by the CA.
pub const EXTERNAL_ACCOUNT_REQUIRED: &str = "urn:ietf:params:acme:error:externalAccountRequired";

/// ACME problem document, including extension details and nested subproblems.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Problem {
    /// Full problem URI; unknown namespaces are preserved.
    #[serde(rename = "type")]
    pub kind: String,
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
