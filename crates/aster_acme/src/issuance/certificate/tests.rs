//! CSR SAN typing and issued-leaf identity boundaries, including RFC 8738
//! iPAddress subjects.

use crate::{
    crypto::key_algorithm::KeyAlgorithm,
    identifier::{DnsIdentifier, Identifier, IpIdentifier},
    issuance::{IssueError, certificate},
};
use rcgen::{CertificateParams, DistinguishedName, Issuer, KeyPair, SanType};
use x509_parser::prelude::FromDer as _;

fn identifier_dns(value: &str) -> Identifier {
    Identifier::Dns(DnsIdentifier::new(value).unwrap())
}

fn identifier_ip(value: &str) -> Identifier {
    Identifier::Ip(IpIdentifier::new(value).unwrap())
}

/// Sign a leaf with the exact requested SANs so tests control both sides.
fn leaf_pem(sans: &[SanType], key_der: &[u8]) -> String {
    let key = KeyPair::try_from(key_der).unwrap();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.subject_alt_names = sans.to_vec();
    params.distinguished_name = DistinguishedName::new();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(89);
    let issuer = Issuer::new(
        CertificateParams::new(Vec::new()).unwrap(),
        KeyPair::generate().unwrap(),
    );
    params.signed_by(&key, &issuer).unwrap().pem()
}

fn sans_from(identifiers: &[Identifier]) -> Vec<SanType> {
    identifiers
        .iter()
        .map(|identifier| match identifier {
            Identifier::Dns(dns) => SanType::DnsName(dns.value().as_str().try_into().unwrap()),
            Identifier::Ip(ip) => SanType::IpAddress(ip.address()),
        })
        .collect()
}

#[test]
fn csr_encodes_typed_sans_for_dns_ip_and_mixed_orders() {
    let cases: &[&[Identifier]] = &[
        &[identifier_dns("example.com")],
        &[identifier_ip("192.0.2.1")],
        &[identifier_ip("2001:db8::1")],
        &[
            identifier_dns("example.com"),
            identifier_ip("192.0.2.1"),
            identifier_dns("alt.example"),
            identifier_ip("::1"),
        ],
    ];
    for identifiers in cases {
        let material = certificate::generate(identifiers, KeyAlgorithm::EcdsaP256).unwrap();
        let (rest, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&material.csr)
                .unwrap();
        assert_eq!(rest, &[] as &[u8]);
        csr.verify_signature().unwrap();
        let requested = csr
            .requested_extensions()
            .expect("parsed CSR attributes")
            .find_map(|extension| match extension {
                x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
                    Some(san.clone())
                }
                _ => None,
            })
            .expect("CSR carries the requested SAN extension");
        let mut actual = Vec::new();
        for name in &requested.general_names {
            match name {
                x509_parser::extensions::GeneralName::DNSName(value) => {
                    actual.push(identifier_dns(value));
                }
                x509_parser::extensions::GeneralName::IPAddress(bytes) => match *bytes {
                    [a, b, c, d] => {
                        actual.push(identifier_ip(
                            &std::net::Ipv4Addr::new(*a, *b, *c, *d).to_string(),
                        ));
                    }
                    octets => {
                        let mut segments = [0u16; 8];
                        for (index, pair) in octets.as_chunks::<2>().0.iter().enumerate() {
                            segments[index] = u16::from_be_bytes([pair[0], pair[1]]);
                        }
                        let address = std::net::Ipv6Addr::new(
                            segments[0],
                            segments[1],
                            segments[2],
                            segments[3],
                            segments[4],
                            segments[5],
                            segments[6],
                            segments[7],
                        );
                        actual.push(identifier_ip(&address.to_string()));
                    }
                },
                other => panic!("unexpected CSR SAN entry: {other:?}"),
            }
        }
        let mut expected = identifiers.to_vec();
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected);
    }
}

#[test]
fn issued_leaf_with_matching_mixed_sans_is_accepted() {
    // The request stores the expanded IPv6 spelling; the leaf carries the same
    // 16-byte address, so validation compares by address, never by text.
    let identifiers = vec![
        identifier_dns("example.com"),
        identifier_ip("192.0.2.1"),
        identifier_ip("2001:0db8:0000:0000:0000:0000:0000:0001"),
    ];
    let canonical = vec![
        identifiers[0].clone(),
        identifiers[1].clone(),
        identifier_ip("2001:db8::1"),
    ];
    let material = certificate::generate(&identifiers, KeyAlgorithm::EcdsaP256).unwrap();
    let pem = leaf_pem(&sans_from(&identifiers), &material.key);
    let not_after = certificate::validate(pem.as_bytes(), &material.key, &canonical).unwrap();
    assert!(not_after > time::OffsetDateTime::now_utc());
}

#[test]
fn wrong_ip_wrong_key_and_dns_instead_of_ip_never_validate() {
    let identifiers = vec![identifier_dns("example.com"), identifier_ip("192.0.2.1")];
    let material = certificate::generate(&identifiers, KeyAlgorithm::EcdsaP256).unwrap();

    // A different address in the leaf is a different subject.
    let substituted = vec![identifier_dns("example.com"), identifier_ip("192.0.2.2")];
    let pem = leaf_pem(&sans_from(&substituted), &material.key);
    assert!(matches!(
        certificate::validate(pem.as_bytes(), &material.key, &identifiers),
        Err(IssueError::InvalidInput(_))
    ));

    // A DNS name standing in for the requested address is not equivalent:
    // the request asked for an iPAddress SAN, not a dNSName spelling of it.
    // A hostile CA can write any IA5 string into dNSName, so build that leaf
    // directly instead of through DnsIdentifier.
    let dns_instead = vec![
        SanType::DnsName("example.com".try_into().unwrap()),
        SanType::DnsName("192.0.2.1".try_into().unwrap()),
    ];
    let pem = leaf_pem(&dns_instead, &material.key);
    assert!(certificate::validate(pem.as_bytes(), &material.key, &identifiers).is_err());

    // The correct leaf with a different private key is rejected.
    let pem = leaf_pem(&sans_from(&identifiers), &material.key);
    let wrong_key = KeyAlgorithm::EcdsaP256.generate().unwrap();
    assert!(
        certificate::validate(pem.as_bytes(), &wrong_key.serialize_der(), &identifiers).is_err()
    );

    // An extra SAN type the request never made is rejected.
    let extra_email = vec![
        SanType::DnsName("example.com".try_into().unwrap()),
        SanType::IpAddress("192.0.2.1".parse().unwrap()),
        SanType::Rfc822Name("admin@example.com".try_into().unwrap()),
    ];
    let pem = leaf_pem(&extra_email, &material.key);
    assert!(certificate::validate(pem.as_bytes(), &material.key, &identifiers).is_err());
}

#[test]
fn requested_ipv6_never_accepts_a_four_byte_address_san() {
    // rcgen cannot emit a malformed SAN length, so the reachable hostile-CA
    // boundary is an address of the wrong family: the 4-byte IPv4 form must
    // never satisfy a requested IPv6 identifier.
    let identifiers = vec![identifier_ip("2001:db8::1")];
    let material = certificate::generate(&identifiers, KeyAlgorithm::EcdsaP256).unwrap();
    let pem = leaf_pem(
        &[SanType::IpAddress("192.0.2.1".parse().unwrap())],
        &material.key,
    );
    assert!(matches!(
        certificate::validate(pem.as_bytes(), &material.key, &identifiers),
        Err(IssueError::InvalidInput(_))
    ));
}
