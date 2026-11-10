//! RFC 7515 flattened JWS and RFC 8555 protected headers, independent of signing keys.
use serde::{Deserialize, Serialize};

/// Flattened JWS. No Debug implementation, to discourage signed request logging.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlattenedJws {
    /// Base64url protected JSON.
    pub protected: String,
    /// Base64url payload; empty for POST-as-GET.
    pub payload: String,
    /// Base64url signature.
    pub signature: String,
}

/// Exactly one account identity is serialized in a protected header.
#[derive(Clone, Copy, Serialize)]
#[serde(untagged)]
pub enum RequestIdentity<'a, J> {
    /// Public key for account creation and lookup.
    Jwk { jwk: &'a J },
    /// Account URL for authenticated account requests.
    Kid { kid: &'a str },
}

/// Standard ACME ES256 header. EAB uses its own nonce-free type.
#[derive(Serialize)]
pub struct ProtectedHeader<'a, J> {
    /// Signing algorithm.
    pub alg: &'a str,
    /// Exactly one identity member.
    #[serde(flatten)]
    pub identity: RequestIdentity<'a, J>,
    /// Server replay nonce.
    pub nonce: &'a str,
    /// Exact server resource URL.
    pub url: &'a str,
}

/// HS256 external account binding header, which must not contain a nonce.
#[derive(Serialize)]
pub struct EabHeader<'a> {
    /// HMAC signing algorithm.
    pub alg: &'a str,
    /// External CA credential ID.
    pub kid: &'a str,
    /// Discovered newAccount endpoint.
    pub url: &'a str,
}

/// RFC 8555 keyChange inner protected header: new-key JWK, exact URL, and no nonce.
#[derive(Serialize)]
pub struct KeyChangeHeader<'a, J> {
    /// Signing algorithm.
    pub alg: &'a str,
    /// New account key.
    pub jwk: &'a J,
    /// Same keyChange endpoint as the outer JWS.
    pub url: &'a str,
}
