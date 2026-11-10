//! ES256 account signing, RFC 7638 thumbprints and RFC 8555 flattened JWS.

use aster_acme_protocol::jws::{
    EabHeader, FlattenedJws, KeyChangeHeader, ProtectedHeader, RequestIdentity,
};
use aster_acme_protocol::url::AcmeUrl;
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac as _};
use p256::{
    ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer as _},
    elliptic_curve::Generate as _,
    pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _},
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// A key or signature could not be constructed; never includes secret material.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// OS randomness was unavailable.
    #[error("operating-system randomness unavailable")]
    Randomness,
    /// Key encoding or curve was invalid.
    #[error("invalid P-256 key or PKCS#8 encoding")]
    InvalidKey,
    /// Signature operation failed.
    #[error("ES256 signing failed")]
    Signing,
    /// A public JSON structure could not be encoded.
    #[error("JWS JSON encoding failed")]
    Encoding,
    /// External-account credentials were malformed.
    #[error("EAB requires an ASCII key ID and a base64url HMAC key of at least 32 bytes")]
    InvalidEab,
}

/// P-256 public JWK with canonical RFC 7638 member ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Es256Jwk {
    crv: &'static str,
    kty: &'static str,
    x: String,
    y: String,
}

impl Es256Jwk {
    /// Read a public point from SEC1 encoding.
    ///
    /// # Errors
    /// Rejects invalid P-256 public points.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
        let point = key.to_sec1_point(false);
        let bytes = point.as_bytes();
        Ok(Self {
            crv: "P-256",
            kty: "EC",
            x: URL_SAFE_NO_PAD.encode(&bytes[1..33]),
            y: URL_SAFE_NO_PAD.encode(&bytes[33..65]),
        })
    }

    /// SHA-256 JWK thumbprint, encoded without padding.
    ///
    /// # Errors
    /// Returns an encoding error if canonical JSON cannot be generated.
    pub fn thumbprint(&self) -> Result<String, CryptoError> {
        let json = serde_json::to_vec(self).map_err(|_| CryptoError::Encoding)?;
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(json)))
    }
}

/// ES256 signing boundary; external key stores can supply hardware-backed signers.
pub trait AccountSigner: Send + Sync {
    /// Public JWK matching the signing key.
    ///
    /// # Errors
    /// Returns a key-access or encoding failure.
    fn jwk(&self) -> Result<Es256Jwk, CryptoError>;
    /// Sign bytes as an ES256 JWS signature (64-byte R || S, never ASN.1 DER).
    ///
    /// # Errors
    /// Returns a signing failure without exposing key material.
    fn sign(&self, input: &[u8]) -> Result<[u8; 64], CryptoError>;
}

/// Software account key. No Debug or Clone implementation exposes private material.
pub struct AccountKey(SigningKey);

impl AccountKey {
    /// Generate an account key using fallible OS randomness.
    ///
    /// # Errors
    /// Returns an error if OS randomness is unavailable.
    pub fn generate() -> Result<Self, CryptoError> {
        SigningKey::try_generate()
            .map(Self)
            .map_err(|_| CryptoError::Randomness)
    }
    /// Load a persisted PKCS#8 DER account key.
    ///
    /// # Errors
    /// Rejects malformed encodings and keys on other curves.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoError> {
        SigningKey::from_pkcs8_der(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }
    /// Export PKCS#8 DER into a buffer that zeroizes on drop.
    ///
    /// # Errors
    /// Returns an error if the key cannot be encoded.
    pub fn to_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let document = self.0.to_pkcs8_der().map_err(|_| CryptoError::InvalidKey)?;
        Ok(Zeroizing::new(document.as_bytes().to_vec()))
    }
}

impl AccountSigner for AccountKey {
    fn jwk(&self) -> Result<Es256Jwk, CryptoError> {
        Es256Jwk::from_sec1(self.0.verifying_key().to_sec1_point(false).as_bytes())
    }
    fn sign(&self, input: &[u8]) -> Result<[u8; 64], CryptoError> {
        let signature: Signature = self.0.try_sign(input).map_err(|_| CryptoError::Signing)?;
        Ok(signature.to_bytes().into())
    }
}

pub(crate) fn sign_request(
    signer: &dyn AccountSigner,
    identity: RequestIdentity<'_, Es256Jwk>,
    nonce: &str,
    url: &str,
    payload: &[u8],
) -> Result<FlattenedJws, CryptoError> {
    let header = ProtectedHeader {
        alg: "ES256",
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
    old_key: &Es256Jwk,
    account: &AcmeUrl,
    endpoint: &str,
) -> Result<FlattenedJws, CryptoError> {
    let new_key = new_signer.jwk()?;
    let header = KeyChangeHeader {
        alg: "ES256",
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

    pub(crate) fn bind(&self, jwk: &Es256Jwk, url: &str) -> Result<FlattenedJws, CryptoError> {
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
