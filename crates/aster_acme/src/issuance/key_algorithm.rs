//! Certificate key choices independent of account JWS and CA signing algorithms.
use super::IssueError;
use rcgen::{KeyPair, PublicKeyData as _};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::FromDer as _;

/// Algorithms this client can generate. Each CA decides which CSR keys it accepts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateKeyAlgorithm {
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
    Rsa2048,
    /// RSA 3072 with PKCS#1 SHA-256 CSR signatures.
    Rsa3072,
    /// RSA 4096 with PKCS#1 SHA-256 CSR signatures.
    Rsa4096,
    /// RSA 8192; generation can be expensive and CA acceptance varies.
    Rsa8192,
}

impl CertificateKeyAlgorithm {
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

    pub(super) fn generate(self) -> Result<KeyPair, IssueError> {
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
                        return Err(IssueError::InvalidInput("not an RSA key choice"));
                    }
                };
                let key = RsaKeyPair::generate(size)
                    .map_err(|_| IssueError::InvalidInput("RSA key generation failed"))?;
                let encoded = key
                    .as_der()
                    .map_err(|_| IssueError::InvalidInput("RSA PKCS#8 encoding failed"))?;
                let der = zeroize::Zeroizing::new(encoded.as_ref().to_vec());
                KeyPair::try_from(der.as_slice())
            }
        };
        result.map_err(|_| IssueError::InvalidInput("certificate key generation failed"))
    }

    /// Check the saved key's actual algorithm and RSA modulus length on recovery.
    ///
    /// # Errors
    /// Rejects invalid keys or a mismatch with the durable requested choice.
    pub fn validate_key(self, key_der: &[u8]) -> Result<(), IssueError> {
        let key = KeyPair::try_from(key_der)
            .map_err(|_| IssueError::InvalidInput("invalid certificate key"))?;
        let valid = match self {
            Self::EcdsaP256 => key.algorithm() == &rcgen::PKCS_ECDSA_P256_SHA256,
            Self::EcdsaP384 => key.algorithm() == &rcgen::PKCS_ECDSA_P384_SHA384,
            Self::EcdsaP521 => key.algorithm() == &rcgen::PKCS_ECDSA_P521_SHA512,
            Self::Ed25519 => key.algorithm() == &rcgen::PKCS_ED25519,
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 | Self::Rsa8192 => {
                let spki = key.subject_public_key_info();
                let (_, public) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki)
                    .map_err(|_| IssueError::InvalidInput("invalid certificate SPKI"))?;
                let expected = match self {
                    Self::Rsa2048 => 2048,
                    Self::Rsa3072 => 3072,
                    Self::Rsa4096 => 4096,
                    Self::Rsa8192 => 8192,
                    Self::EcdsaP256 | Self::EcdsaP384 | Self::EcdsaP521 | Self::Ed25519 => {
                        return Err(IssueError::InvalidInput("not an RSA key choice"));
                    }
                };
                matches!(public.parsed(),Ok(x509_parser::public_key::PublicKey::RSA(rsa)) if rsa.key_size()==expected)
            }
        };
        if !valid {
            return Err(IssueError::InvalidInput(
                "certificate key does not match the saved algorithm",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
