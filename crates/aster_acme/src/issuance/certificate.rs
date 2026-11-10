//! Fixed PKCS#10 CSR generation and issued leaf identity/key checks.
use super::IssueError;
use crate::identifier::DnsIdentifier;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PublicKeyData as _};
use x509_parser::{pem::parse_x509_pem, prelude::FromDer as _, x509::X509Version};
use zeroize::Zeroizing;

/// Certificate private material, never Debug or Serialize.
pub struct CertificateMaterial {
    /// PKCS#8 DER, zeroized when dropped.
    pub key: Zeroizing<Vec<u8>>,
    /// Fixed signed PKCS#10 DER.
    pub csr: Vec<u8>,
}

/// Generate a separate P-256 certificate key and SAN-only CSR.
///
/// # Errors
/// Rejects generation failures and malformed SAN identifiers.
pub fn generate(identifiers: &[DnsIdentifier]) -> Result<CertificateMaterial, IssueError> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|_| IssueError::InvalidInput("certificate key generation failed"))?;
    let mut params = CertificateParams::new(
        identifiers
            .iter()
            .map(DnsIdentifier::value)
            .collect::<Vec<_>>(),
    )
    .map_err(|_| IssueError::InvalidInput("invalid CSR identifiers"))?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(&key)
        .map_err(|_| IssueError::InvalidInput("CSR generation failed"))?;
    Ok(CertificateMaterial {
        key: Zeroizing::new(key.serialize_der()),
        csr: csr.der().to_vec(),
    })
}

/// Check complete PEM syntax, leaf SAN/key/validity, and adjacent chain signatures.
/// This checks the issued artifact, not public trust; staging roots are never installed.
///
/// # Errors
/// Rejects malformed chains, wrong key/SANs, CA leaves and invalid validity intervals.
pub fn validate(
    chain: &[u8],
    key_der: &[u8],
    identifiers: &[DnsIdentifier],
) -> Result<time::OffsetDateTime, IssueError> {
    let invalid = || {
        IssueError::InvalidInput(
            "issued certificate does not match the saved key, identifiers or validity",
        )
    };
    if chain.len() > 1024 * 1024 {
        return Err(invalid());
    }
    let mut remaining = chain;
    let mut ders = Vec::new();
    while !remaining.iter().all(u8::is_ascii_whitespace) {
        let (rest, pem) = parse_x509_pem(remaining).map_err(|_| invalid())?;
        if pem.label != "CERTIFICATE" || ders.len() >= 16 {
            return Err(invalid());
        }
        ders.push(pem.contents);
        remaining = rest;
    }
    let certificates = ders
        .iter()
        .map(|der| {
            x509_parser::certificate::X509Certificate::from_der(der)
                .map_err(|_| invalid())
                .and_then(|(rest, cert)| {
                    if rest.is_empty() {
                        Ok(cert)
                    } else {
                        Err(invalid())
                    }
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = certificates.first().ok_or_else(invalid)?;
    let key = KeyPair::try_from(key_der).map_err(|_| invalid())?;
    if leaf.version() != X509Version::V3
        || leaf.is_ca()
        || leaf.public_key().subject_public_key.data.as_ref() != key.der_bytes()
        || !leaf.validity().is_valid()
    {
        return Err(invalid());
    }
    let names = leaf
        .subject_alternative_name()
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let mut actual = Vec::new();
    for name in &names.value.general_names {
        match name {
            x509_parser::extensions::GeneralName::DNSName(name) => {
                actual.push(DnsIdentifier::new(name)?.value());
            }
            _ => return Err(invalid()),
        }
    }
    let mut expected = identifiers
        .iter()
        .map(DnsIdentifier::value)
        .collect::<Vec<_>>();
    actual.sort();
    expected.sort();
    if actual != expected {
        return Err(invalid());
    }
    for pair in certificates.windows(2) {
        if pair[0].issuer() != pair[1].subject() {
            return Err(invalid());
        }
        pair[0]
            .verify_signature(Some(pair[1].public_key()))
            .map_err(|_| invalid())?;
    }
    time::OffsetDateTime::from_unix_timestamp(leaf.validity().not_after.timestamp())
        .map_err(|_| invalid())
}

/// User-consumable PEM artifacts derived from a validated issuance result.
/// No Debug implementation may expose the private key.
pub struct CertificateArtifacts {
    /// First certificate in the returned chain.
    pub certificate: String,
    /// Remaining CA-provided chain; empty if the CA returned only a leaf.
    pub ca_chain: String,
    /// PEM PKCS#8 encoding of the same persisted certificate key.
    pub private_key: Zeroizing<String>,
}

/// Split validated certificate-chain PEM and encode the fixed key for deployment tools.
///
/// # Errors
/// Rejects malformed PEM or invalid PKCS#8; callers must validate leaf identity first.
pub fn artifacts(chain: &[u8], key_der: &[u8]) -> Result<CertificateArtifacts, IssueError> {
    let (remaining, leaf) =
        parse_x509_pem(chain).map_err(|_| IssueError::InvalidInput("invalid certificate PEM"))?;
    if leaf.label != "CERTIFICATE" {
        return Err(IssueError::InvalidInput("invalid certificate PEM label"));
    }
    let certificate = encode_certificate(&leaf.contents);
    let mut ca_chain = String::new();
    let mut remaining = remaining;
    while !remaining.iter().all(u8::is_ascii_whitespace) {
        let (rest, pem) = parse_x509_pem(remaining)
            .map_err(|_| IssueError::InvalidInput("invalid CA chain PEM"))?;
        if pem.label != "CERTIFICATE" {
            return Err(IssueError::InvalidInput("invalid CA chain PEM label"));
        }
        ca_chain.push_str(&encode_certificate(&pem.contents));
        remaining = rest;
    }
    let key = KeyPair::try_from(key_der)
        .map_err(|_| IssueError::InvalidInput("invalid certificate PKCS#8 key"))?;
    Ok(CertificateArtifacts {
        certificate,
        ca_chain,
        private_key: Zeroizing::new(key.serialize_pem()),
    })
}

fn encode_certificate(der: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let encoded = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    // Base64 is ASCII; chunking at 64 bytes follows the PEM presentation convention.
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend(chunk.iter().map(|byte| char::from(*byte)));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Extract the first PEM certificate as DER for RFC 8555 section 7.6.
///
/// # Errors
/// Rejects missing, non-certificate or malformed leaf data.
pub fn leaf_der(chain: &[u8]) -> Result<Vec<u8>, IssueError> {
    let (_, pem) =
        parse_x509_pem(chain).map_err(|_| IssueError::InvalidInput("invalid leaf PEM"))?;
    if pem.label != "CERTIFICATE" {
        return Err(IssueError::InvalidInput("invalid leaf PEM label"));
    }
    let (rest, _) = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
        .map_err(|_| IssueError::InvalidInput("invalid leaf DER"))?;
    if !rest.is_empty() {
        return Err(IssueError::InvalidInput("trailing leaf DER data"));
    }
    Ok(pem.contents)
}
