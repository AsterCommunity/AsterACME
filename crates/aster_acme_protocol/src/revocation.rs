//! RFC 8555 section 7.6 certificate revocation wire payload.
use serde::{Deserialize, Serialize};

/// An already revoked certificate is a confirmed remote outcome, not an authorization error.
pub const ALREADY_REVOKED: &str = "urn:ietf:params:acme:error:alreadyRevoked";

/// Revocation request; DER leaf bytes use unpadded base64url, never PEM or the full chain.
#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// Issued leaf certificate in base64url DER form.
    pub certificate: String,
    /// RFC 5280 reason code, omitted when the operator has not selected one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<u8>,
}
