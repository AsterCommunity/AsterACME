//! RFC 7515 flattened JWS and RFC 8555 protected headers, independent of signing keys.
use serde::{Deserialize, Serialize};

/// Account JWS algorithms implemented by this client. CA acceptance is independent.
/// RFC 8555 mandates ES256 and recommends RFC 8037 `EdDSA` with Ed25519.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// P-256 / SHA-256, fixed 64-byte R || S.
    #[serde(rename = "ES256")]
    Es256,
    /// P-384 / SHA-384, fixed 96-byte R || S.
    #[serde(rename = "ES384")]
    Es384,
    /// P-521 / SHA-512, fixed 132-byte R || S (not 128 bytes).
    #[serde(rename = "ES512")]
    Es512,
    /// Ed25519 using the RFC 8037 JOSE name accepted by ACME.
    #[serde(rename = "EdDSA")]
    EdDsa,
    /// RSA PKCS#1 v1.5 / SHA-256; modulus size is a separate key property.
    #[serde(rename = "RS256")]
    Rs256,
}

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

/// Standard ACME asymmetric-signature header. EAB uses its own nonce-free type.
#[derive(Serialize)]
pub struct ProtectedHeader<'a, J> {
    /// Signing algorithm.
    pub alg: SignatureAlgorithm,
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
    pub alg: SignatureAlgorithm,
    /// New account key.
    pub jwk: &'a J,
    /// Same keyChange endpoint as the outer JWS.
    pub url: &'a str,
}
