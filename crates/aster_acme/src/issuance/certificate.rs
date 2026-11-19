//! Fixed PKCS#10 CSR generation and issued leaf identity/key checks.
use crate::identifier::{DnsIdentifier, Identifier};
use crate::issuance::IssueError;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PublicKeyData as _, SanType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use x509_parser::{pem::parse_x509_pem, prelude::FromDer as _, x509::X509Version};
use zeroize::Zeroizing;

/// Decode an RFC 5280 `iPAddress` SAN: four bytes for IPv4, sixteen for IPv6.
///
/// # Errors
/// Rejects any other length as a malformed address.
fn parse_san_address(bytes: &[u8]) -> Result<IpAddr, IssueError> {
    match bytes {
        [a, b, c, d] => Ok(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        octets if octets.len() == 16 => {
            let mut segments = [0u16; 8];
            for (index, pair) in octets.as_chunks::<2>().0.iter().enumerate() {
                segments[index] = u16::from_be_bytes([pair[0], pair[1]]);
            }
            Ok(IpAddr::V6(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            )))
        }
        _ => Err(IssueError::InvalidInput(
            "issued certificate has a malformed iPAddress SAN",
        )),
    }
}

/// Certificate private material, never Debug or Serialize.
pub struct CertificateMaterial {
    /// PKCS#8 DER, zeroized when dropped.
    pub key: Zeroizing<Vec<u8>>,
    /// Fixed signed PKCS#10 DER.
    pub csr: Vec<u8>,
}

/// One requested SAN, typed so DNS names never masquerade as addresses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum San {
    /// DNS name in canonical form.
    Dns(String),
    /// Parsed IP address.
    Ip(IpAddr),
}

impl San {
    fn of(identifier: &Identifier) -> Self {
        match identifier {
            Identifier::Dns(dns) => Self::Dns(dns.value()),
            Identifier::Ip(ip) => Self::Ip(ip.address()),
        }
    }
}

/// Generate a separate selected certificate key and SAN-only CSR.
///
/// # Errors
/// Rejects generation failures and malformed SAN identifiers.
pub fn generate(
    identifiers: &[Identifier],
    algorithm: crate::crypto::key_algorithm::KeyAlgorithm,
) -> Result<CertificateMaterial, IssueError> {
    let key = algorithm.generate()?;
    let mut params = CertificateParams::new(Vec::new())
        .map_err(|_| IssueError::InvalidInput("invalid CSR identifiers"))?;
    params.subject_alt_names = identifiers
        .iter()
        .map(|identifier| match identifier {
            Identifier::Dns(dns) => Ok(SanType::DnsName(dns.value().as_str().try_into().map_err(
                |_: rcgen::Error| IssueError::InvalidInput("invalid CSR DNS identifier"),
            )?)),
            Identifier::Ip(ip) => Ok(SanType::IpAddress(ip.address())),
        })
        .collect::<Result<Vec<_>, IssueError>>()?;
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
/// Rejects malformed chains, wrong key/SANs (including a DNS name standing in
/// for a requested IP address), CA leaves and invalid validity intervals.
pub fn validate(
    chain: &[u8],
    key_der: &[u8],
    identifiers: &[Identifier],
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
                actual.push(San::Dns(DnsIdentifier::new(name)?.value()));
            }
            x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                actual.push(San::Ip(parse_san_address(bytes)?));
            }
            _ => return Err(invalid()),
        }
    }
    let mut expected = identifiers.iter().map(San::of).collect::<Vec<_>>();
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

#[cfg(test)]
mod tests;
