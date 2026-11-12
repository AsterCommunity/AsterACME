//! Shared account/certificate key choices, generation and PKCS#8 validation.
use crate::crypto::CryptoError;
use rcgen::{KeyPair, PublicKeyData as _};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::FromDer as _;

/// Algorithms this client can generate. Each CA decides which account JWS and CSR keys it accepts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAlgorithm {
    /// ECDSA P-256 with SHA-256 CSR signatures.
    #[default]
    EcdsaP256,
    /// ECDSA P-384 with SHA-384 CSR signatures.
    EcdsaP384,
    /// ECDSA P-521 with SHA-512 CSR signatures.
    EcdsaP521,
    /// Ed25519 certificate key and CSR signature.
    Ed25519,
    /// RSA 2048 with PKCS#1 SHA-256 CSR signatures.
    #[serde(rename = "rsa-2048")]
    Rsa2048,
    /// RSA 3072 with PKCS#1 SHA-256 CSR signatures.
    #[serde(rename = "rsa-3072")]
    Rsa3072,
    /// RSA 4096 with PKCS#1 SHA-256 CSR signatures.
    #[serde(rename = "rsa-4096")]
    Rsa4096,
    /// RSA 8192; generation can be expensive and CA acceptance varies.
    #[serde(rename = "rsa-8192")]
    Rsa8192,
}

impl KeyAlgorithm {
    /// Supported generation choices; not an assertion about a particular CA.
    pub const ALL: [Self; 8] = [
        Self::EcdsaP256,
        Self::EcdsaP384,
        Self::EcdsaP521,
        Self::Ed25519,
        Self::Rsa2048,
        Self::Rsa3072,
        Self::Rsa4096,
        Self::Rsa8192,
    ];

    /// Stable configuration and CLI spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa-p256",
            Self::EcdsaP384 => "ecdsa-p384",
            Self::EcdsaP521 => "ecdsa-p521",
            Self::Ed25519 => "ed25519",
            Self::Rsa2048 => "rsa-2048",
            Self::Rsa3072 => "rsa-3072",
            Self::Rsa4096 => "rsa-4096",
            Self::Rsa8192 => "rsa-8192",
        }
    }

    /// Parse an exact supported configuration name.
    #[must_use]
    pub fn from_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.name() == value)
    }

    pub(crate) fn generate(self) -> Result<KeyPair, CryptoError> {
        use aws_lc_rs::{
            encoding::AsDer as _,
            rsa::{KeyPair as RsaKeyPair, KeySize},
        };
        let result = match self {
            Self::EcdsaP256 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            Self::EcdsaP384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384),
            Self::EcdsaP521 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512),
            Self::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519),
            // rcgen's RSA size enum stops at 4096; the same AWS-LC backend also
            // supports 8192. Encode standard PKCS#8 and hand it back to rcgen.
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 | Self::Rsa8192 => {
                let size = match self {
                    Self::Rsa2048 => KeySize::Rsa2048,
                    Self::Rsa3072 => KeySize::Rsa3072,
                    Self::Rsa4096 => KeySize::Rsa4096,
                    Self::Rsa8192 => KeySize::Rsa8192,
                    Self::EcdsaP256 | Self::EcdsaP384 | Self::EcdsaP521 | Self::Ed25519 => {
                        return Err(CryptoError::InvalidKey);
                    }
                };
                let key = RsaKeyPair::generate(size).map_err(|_| CryptoError::InvalidKey)?;
                let encoded = key.as_der().map_err(|_| CryptoError::InvalidKey)?;
                let der = zeroize::Zeroizing::new(encoded.as_ref().to_vec());
                KeyPair::try_from(der.as_slice())
            }
        };
        result.map_err(|_| CryptoError::InvalidKey)
    }

    /// JOSE signature algorithm used for account requests (RFC 7518 / RFC 8037).
    #[must_use]
    pub const fn jws_algorithm(self) -> aster_acme_protocol::jws::SignatureAlgorithm {
        use aster_acme_protocol::jws::SignatureAlgorithm;
        match self {
            Self::EcdsaP256 => SignatureAlgorithm::Es256,
            Self::EcdsaP384 => SignatureAlgorithm::Es384,
            Self::EcdsaP521 => SignatureAlgorithm::Es512,
            Self::Ed25519 => SignatureAlgorithm::EdDsa,
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 | Self::Rsa8192 => {
                SignatureAlgorithm::Rs256
            }
        }
    }

    /// Determine the supported algorithm from the actual PKCS#8 key, never a label.
    ///
    /// # Errors
    /// Rejects malformed keys, unsupported curves and unsupported RSA sizes.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoError> {
        // Require a complete single DER object; some backend decoders otherwise
        // accept a valid key followed by unrelated bytes in a managed key file.
        let (rest, _) = x509_parser::der_parser::der::parse_der_sequence(bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        if !rest.is_empty() {
            return Err(CryptoError::InvalidKey);
        }
        let key = KeyPair::try_from(bytes).map_err(|_| CryptoError::InvalidKey)?;
        match key.algorithm() {
            algorithm if algorithm == &rcgen::PKCS_ECDSA_P256_SHA256 => Ok(Self::EcdsaP256),
            algorithm if algorithm == &rcgen::PKCS_ECDSA_P384_SHA384 => Ok(Self::EcdsaP384),
            algorithm if algorithm == &rcgen::PKCS_ECDSA_P521_SHA512 => Ok(Self::EcdsaP521),
            algorithm if algorithm == &rcgen::PKCS_ED25519 => Ok(Self::Ed25519),
            algorithm if algorithm == &rcgen::PKCS_RSA_SHA256 => {
                let spki = key.subject_public_key_info();
                let (rest, public) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki)
                    .map_err(|_| CryptoError::InvalidKey)?;
                if !rest.is_empty() {
                    return Err(CryptoError::InvalidKey);
                }
                match public.parsed().map_err(|_| CryptoError::InvalidKey)? {
                    x509_parser::public_key::PublicKey::RSA(rsa) => match rsa.key_size() {
                        2048 => Ok(Self::Rsa2048),
                        3072 => Ok(Self::Rsa3072),
                        4096 => Ok(Self::Rsa4096),
                        8192 => Ok(Self::Rsa8192),
                        _ => Err(CryptoError::InvalidKey),
                    },
                    _ => Err(CryptoError::InvalidKey),
                }
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }

    /// Check the actual key against a durable requested algorithm.
    ///
    /// # Errors
    /// Rejects unsupported, corrupt or mismatched keys.
    pub fn validate_key(self, bytes: &[u8]) -> Result<(), CryptoError> {
        if Self::from_pkcs8(bytes)? == self {
            Ok(())
        } else {
            Err(CryptoError::InvalidKey)
        }
    }
}

#[cfg(test)]
mod tests;
