//! Account signing, RFC 7638 thumbprints and RFC 8555 flattened JWS.

use aster_acme_protocol::jws::{
    EabHeader, FlattenedJws, KeyChangeHeader, ProtectedHeader, RequestIdentity,
};
use aster_acme_protocol::url::AcmeUrl;
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

pub mod jwk;
pub mod key;
pub mod key_algorithm;

use jwk::Jwk;
use key_algorithm::KeyAlgorithm;

/// A key or signature could not be constructed; never includes secret material.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// OS randomness was unavailable.
    #[error("operating-system randomness unavailable")]
    Randomness,
    /// Key encoding, curve or RSA size was invalid or unsupported.
    #[error("invalid or unsupported key algorithm or PKCS#8 encoding")]
    InvalidKey,
    /// Signature operation failed.
    #[error("account signing failed")]
    Signing,
    /// A public JSON structure could not be encoded.
    #[error("JWS JSON encoding failed")]
    Encoding,
    /// External-account credentials were malformed.
    #[error("EAB requires an ASCII key ID and a base64url HMAC key of at least 32 bytes")]
    InvalidEab,
}

/// Object-safe account signing boundary, including hardware/remote key implementations.
pub trait AccountSigner: Send + Sync {
    /// Actual key choice, which selects the JOSE signature algorithm.
    fn algorithm(&self) -> KeyAlgorithm;
    /// Public JWK matching the signing key.
    ///
    /// # Errors
    /// Reports key-access or encoding failures.
    fn jwk(&self) -> Result<Jwk, CryptoError>;
    /// Sign JWS input: ECDSA uses fixed-width R || S, RSA PKCS#1 v1.5, Ed25519 raw.
    ///
    /// # Errors
    /// Reports signing failures without private material.
    fn sign(&self, input: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub(crate) fn sign_request(
    signer: &dyn AccountSigner,
    identity: RequestIdentity<'_, Jwk>,
    nonce: &str,
    url: &str,
    payload: &[u8],
) -> Result<FlattenedJws, CryptoError> {
    // The alg value follows the signer, including when kid hides the public JWK.
    let header = ProtectedHeader {
        alg: signer.algorithm().jws_algorithm(),
        identity,
        nonce,
        url,
    };
    let protected =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| CryptoError::Encoding)?);
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let signature = signer.sign(format!("{protected}.{payload}").as_bytes())?;
    Ok(FlattenedJws {
        protected,
        payload,
        signature: URL_SAFE_NO_PAD.encode(signature),
    })
}

/// Sign the nonce-free inner JWS required by RFC 8555 §7.3.5.
pub(crate) fn sign_key_change(
    new_signer: &dyn AccountSigner,
    old_key: &Jwk,
    account: &AcmeUrl,
    endpoint: &str,
) -> Result<FlattenedJws, CryptoError> {
    let new_key = new_signer.jwk()?;
    // The inner proof is made by the new key. The transport later wraps it in
    // a nonce-bearing kid JWS signed by the old key, possibly with another alg.
    let header = KeyChangeHeader {
        alg: new_signer.algorithm().jws_algorithm(),
        jwk: &new_key,
        url: endpoint,
    };
    let payload = aster_acme_protocol::account::KeyChangePayload { account, old_key };
    let protected =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| CryptoError::Encoding)?);
    let payload =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).map_err(|_| CryptoError::Encoding)?);
    let signature = new_signer.sign(format!("{protected}.{payload}").as_bytes())?;
    Ok(FlattenedJws {
        protected,
        payload,
        signature: URL_SAFE_NO_PAD.encode(signature),
    })
}

/// External CA account binding credentials. Secret bytes zeroize on drop.
pub struct ExternalAccountCredentials {
    kid: String,
    key: Zeroizing<Vec<u8>>,
}

impl ExternalAccountCredentials {
    /// Decode externally supplied HS256 credentials; never persist the HMAC key.
    ///
    /// # Errors
    /// Rejects non-ASCII/control key IDs, invalid base64url and undersized/oversized keys.
    pub fn new(kid: &str, encoded_key: &str) -> Result<Self, CryptoError> {
        if kid.is_empty()
            || kid.len() > 1024
            || !kid.is_ascii()
            || kid.bytes().any(|c| c.is_ascii_control())
            || encoded_key.len() > 8192
        {
            return Err(CryptoError::InvalidEab);
        }
        let bytes = match URL_SAFE_NO_PAD.decode(encoded_key) {
            Ok(bytes) => bytes,
            Err(_) => URL_SAFE
                .decode(encoded_key)
                .map_err(|_| CryptoError::InvalidEab)?,
        };
        let key = Zeroizing::new(bytes);
        if key.len() < 32 {
            return Err(CryptoError::InvalidEab);
        }
        Ok(Self {
            kid: kid.to_owned(),
            key,
        })
    }

    pub(crate) fn bind(&self, jwk: &Jwk, url: &str) -> Result<FlattenedJws, CryptoError> {
        let header = EabHeader {
            alg: "HS256",
            kid: &self.kid,
            url,
        };
        let protected =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| CryptoError::Encoding)?);
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(jwk).map_err(|_| CryptoError::Encoding)?);
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| CryptoError::InvalidEab)?;
        mac.update(format!("{protected}.{payload}").as_bytes());
        Ok(FlattenedJws {
            protected,
            payload,
            signature: URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
        })
    }
}

#[cfg(test)]
mod tests;
