//! Public account JWKs with RFC 7638 canonical required-member ordering.
use super::{CryptoError, key_algorithm::KeyAlgorithm};
use aws_lc_rs::signature::{self, ParsedPublicKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use x509_parser::prelude::FromDer as _;

/// Supported public keys; private members and optional metadata cannot enter thumbprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Jwk {
    /// RFC 7518 elliptic-curve key.
    Ec(EcJwk),
    /// RFC 7518 RSA key.
    Rsa(RsaJwk),
    /// RFC 8037 Ed25519 key.
    Okp(OkpJwk),
}

/// Canonical EC members, sorted lexicographically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EcJwk {
    crv: &'static str,
    kty: &'static str,
    x: String,
    y: String,
}

/// Canonical RSA members, with unsigned minimal-length base64url integers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RsaJwk {
    e: String,
    kty: &'static str,
    n: String,
}

/// Canonical OKP members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OkpJwk {
    crv: &'static str,
    kty: &'static str,
    x: String,
}

impl Jwk {
    /// Read and validate an uncompressed SEC1 point for the selected curve.
    ///
    /// # Errors
    /// Rejects other algorithm types, wrong widths and invalid curve points.
    pub fn from_sec1(algorithm: KeyAlgorithm, bytes: &[u8]) -> Result<Self, CryptoError> {
        let (curve, width, verifier) = match algorithm {
            KeyAlgorithm::EcdsaP256 => ("P-256", 32, &signature::ECDSA_P256_SHA256_FIXED),
            KeyAlgorithm::EcdsaP384 => ("P-384", 48, &signature::ECDSA_P384_SHA384_FIXED),
            KeyAlgorithm::EcdsaP521 => ("P-521", 66, &signature::ECDSA_P521_SHA512_FIXED),
            KeyAlgorithm::Ed25519
            | KeyAlgorithm::Rsa2048
            | KeyAlgorithm::Rsa3072
            | KeyAlgorithm::Rsa4096
            | KeyAlgorithm::Rsa8192 => return Err(CryptoError::InvalidKey),
        };
        if bytes.len() != 1 + 2 * width || bytes[0] != 4 {
            return Err(CryptoError::InvalidKey);
        }
        ParsedPublicKey::new(verifier, bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::Ec(EcJwk {
            crv: curve,
            kty: "EC",
            x: URL_SAFE_NO_PAD.encode(&bytes[1..=width]),
            y: URL_SAFE_NO_PAD.encode(&bytes[width + 1..]),
        }))
    }

    /// Read and validate an RFC 8017 DER RSA public key.
    ///
    /// # Errors
    /// Rejects invalid keys, trailing data and unsupported modulus sizes.
    pub fn from_rsa_der(bytes: &[u8]) -> Result<Self, CryptoError> {
        aws_lc_rs::rsa::PublicKey::from_der(bytes).map_err(|_| CryptoError::InvalidKey)?;
        let (rest, public) = x509_parser::public_key::RSAPublicKey::from_der(bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        if !rest.is_empty() || !matches!(public.key_size(), 2048 | 3072 | 4096 | 8192) {
            return Err(CryptoError::InvalidKey);
        }
        let unsigned = |bytes: &[u8]| {
            URL_SAFE_NO_PAD.encode(
                bytes
                    .iter()
                    .position(|b| *b != 0)
                    .map_or(&[][..], |at| &bytes[at..]),
            )
        };
        Ok(Self::Rsa(RsaJwk {
            e: unsigned(public.exponent),
            kty: "RSA",
            n: unsigned(public.modulus),
        }))
    }

    /// Read a raw RFC 8037 Ed25519 public key.
    ///
    /// # Errors
    /// Rejects wrong widths and invalid public keys.
    pub fn from_ed25519(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        ParsedPublicKey::new(&signature::ED25519, bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::Okp(OkpJwk {
            crv: "Ed25519",
            kty: "OKP",
            x: URL_SAFE_NO_PAD.encode(bytes),
        }))
    }

    /// SHA-256 thumbprint of only the sorted required members (RFC 7638 / RFC 8037).
    ///
    /// # Errors
    /// Returns an encoding error if canonical JSON cannot be generated.
    pub fn thumbprint(&self) -> Result<String, CryptoError> {
        let json = serde_json::to_vec(self).map_err(|_| CryptoError::Encoding)?;
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(json)))
    }
}
