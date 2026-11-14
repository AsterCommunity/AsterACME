//! Software JWS signing keys. No Debug/Clone exposes private material.
use crate::crypto::{CryptoError, JwsSigner, jwk::Jwk, key_algorithm::KeyAlgorithm};
use aws_lc_rs::{
    encoding::AsDer as _,
    rand::SystemRandom,
    signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _},
};
use zeroize::Zeroizing;

/// Software signing key with its validated actual algorithm; never inferred from a file name.
pub struct SoftwareSigningKey {
    algorithm: KeyAlgorithm,
    key: SigningKey,
}
enum SigningKey {
    Ec(EcdsaKeyPair),
    Rsa(aws_lc_rs::rsa::KeyPair),
    Ed25519(Ed25519KeyPair),
}

impl SoftwareSigningKey {
    /// Generate a selected key with the shared AWS-LC backend and fallible randomness.
    ///
    /// # Errors
    /// Reports key generation/encoding failures without secret material.
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self, CryptoError> {
        let key = algorithm.generate()?;
        Self::from_pkcs8(&Zeroizing::new(key.serialize_der()))
    }

    /// Load supported PKCS#8 DER, validating the actual curve or RSA modulus size.
    ///
    /// # Errors
    /// Rejects corrupt, unsupported and inconsistent keys.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoError> {
        let algorithm = KeyAlgorithm::from_pkcs8(bytes)?;
        let key = match algorithm {
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 | KeyAlgorithm::EcdsaP521 => {
                let signing = match algorithm {
                    KeyAlgorithm::EcdsaP256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    KeyAlgorithm::EcdsaP384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                    KeyAlgorithm::EcdsaP521 => &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
                    KeyAlgorithm::Ed25519
                    | KeyAlgorithm::Rsa2048
                    | KeyAlgorithm::Rsa3072
                    | KeyAlgorithm::Rsa4096
                    | KeyAlgorithm::Rsa8192 => return Err(CryptoError::InvalidKey),
                };
                SigningKey::Ec(
                    EcdsaKeyPair::from_pkcs8(signing, bytes)
                        .map_err(|_| CryptoError::InvalidKey)?,
                )
            }
            KeyAlgorithm::Ed25519 => SigningKey::Ed25519(
                Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| CryptoError::InvalidKey)?,
            ),
            KeyAlgorithm::Rsa2048
            | KeyAlgorithm::Rsa3072
            | KeyAlgorithm::Rsa4096
            | KeyAlgorithm::Rsa8192 => SigningKey::Rsa(
                aws_lc_rs::rsa::KeyPair::from_pkcs8(bytes).map_err(|_| CryptoError::InvalidKey)?,
            ),
        };
        Ok(Self { algorithm, key })
    }

    /// Encode private material into a buffer that zeroizes on drop.
    ///
    /// # Errors
    /// Reports an encoding failure.
    pub fn to_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let bytes = match &self.key {
            SigningKey::Ec(key) => key.to_pkcs8v1().map(|doc| doc.as_ref().to_vec()),
            SigningKey::Ed25519(key) => key.to_pkcs8v1().map(|doc| doc.as_ref().to_vec()),
            SigningKey::Rsa(key) => key.as_der().map(|doc| doc.as_ref().to_vec()),
        }
        .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Zeroizing::new(bytes))
    }

    pub(super) fn public_key(&self) -> &[u8] {
        match &self.key {
            SigningKey::Ec(key) => key.public_key().as_ref(),
            SigningKey::Ed25519(key) => key.public_key().as_ref(),
            SigningKey::Rsa(key) => key.public_key().as_ref(),
        }
    }
}

impl JwsSigner for SoftwareSigningKey {
    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn jwk(&self) -> Result<Jwk, CryptoError> {
        match &self.key {
            SigningKey::Ec(_) => Jwk::from_sec1(self.algorithm, self.public_key()),
            SigningKey::Rsa(_) => Jwk::from_rsa_der(self.public_key()),
            SigningKey::Ed25519(_) => Jwk::from_ed25519(self.public_key()),
        }
    }

    fn sign(&self, input: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let random = SystemRandom::new();
        match &self.key {
            SigningKey::Ec(key) => key
                .sign(&random, input)
                .map(|sig| sig.as_ref().to_vec())
                .map_err(|_| CryptoError::Signing),
            SigningKey::Ed25519(key) => key
                .try_sign(input)
                .map(|sig| sig.as_ref().to_vec())
                .map_err(|_| CryptoError::Signing),
            SigningKey::Rsa(key) => {
                let mut signature = vec![0; key.public_modulus_len()];
                key.sign(&signature::RSA_PKCS1_SHA256, &random, input, &mut signature)
                    .map_err(|_| CryptoError::Signing)?;
                Ok(signature)
            }
        }
    }
}
