//! Generate every advertised key and verify the actual CSR signature and PEM artifacts.
use super::*;
use crate::{identifier::DnsIdentifier, issuance::certificate};
use aws_lc_rs::signature;
use rcgen::{CertificateParams, Issuer};

#[test]
fn every_supported_algorithm_generates_valid_csr_and_matching_certificate_artifacts() {
    let identifiers = [
        DnsIdentifier::new("example.com").unwrap(),
        DnsIdentifier::new("*.example.com").unwrap(),
    ];
    let ca = Issuer::new(
        CertificateParams::new(Vec::<String>::new()).unwrap(),
        KeyPair::generate().unwrap(),
    );
    for algorithm in CertificateKeyAlgorithm::ALL {
        let material = certificate::generate(&identifiers, algorithm).unwrap();
        algorithm.validate_key(&material.key).unwrap();
        assert_eq!(
            serde_json::from_str::<CertificateKeyAlgorithm>(
                &serde_json::to_string(&algorithm).unwrap()
            )
            .unwrap(),
            algorithm
        );
        assert_eq!(
            CertificateKeyAlgorithm::from_name(algorithm.name()),
            Some(algorithm)
        );
        let (rest, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&material.csr)
                .unwrap();
        assert_eq!(rest, &[] as &[u8]);
        // Select an independent verifier explicitly, including P-521 SHA-512 which
        // x509-parser's convenience verifier does not currently dispatch.
        let verifier: &dyn signature::VerificationAlgorithm = match algorithm {
            CertificateKeyAlgorithm::EcdsaP256 => &signature::ECDSA_P256_SHA256_ASN1,
            CertificateKeyAlgorithm::EcdsaP384 => &signature::ECDSA_P384_SHA384_ASN1,
            CertificateKeyAlgorithm::EcdsaP521 => &signature::ECDSA_P521_SHA512_ASN1,
            CertificateKeyAlgorithm::Ed25519 => &signature::ED25519,
            CertificateKeyAlgorithm::Rsa2048
            | CertificateKeyAlgorithm::Rsa3072
            | CertificateKeyAlgorithm::Rsa4096
            | CertificateKeyAlgorithm::Rsa8192 => &signature::RSA_PKCS1_2048_8192_SHA256,
        };
        let public = &csr.certification_request_info.subject_pki;
        signature::UnparsedPublicKey::new(verifier, &public.subject_public_key.data)
            .verify(
                csr.certification_request_info.raw,
                &csr.signature_value.data,
            )
            .unwrap();
        let names = csr
            .requested_extensions()
            .unwrap()
            .find_map(|ext| match ext {
                x509_parser::extensions::ParsedExtension::SubjectAlternativeName(names) => {
                    Some(names.general_names.clone())
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(names.len(), 2);
        let key = KeyPair::try_from(material.key.as_slice()).unwrap();
        let params = CertificateParams::new(
            identifiers
                .iter()
                .map(DnsIdentifier::value)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let leaf = params.signed_by(&key, &ca).unwrap();
        let pem = leaf.pem();
        certificate::validate(pem.as_bytes(), &material.key, &identifiers).unwrap();
        let artifacts = certificate::artifacts(pem.as_bytes(), &material.key).unwrap();
        let restored = KeyPair::from_pem(&artifacts.private_key).unwrap();
        assert_eq!(restored.der_bytes(), key.der_bytes());
        let wrong = KeyPair::generate().unwrap();
        assert!(
            certificate::validate(pem.as_bytes(), &wrong.serialize_der(), &identifiers).is_err()
        );
        if algorithm != CertificateKeyAlgorithm::EcdsaP256 {
            assert!(
                CertificateKeyAlgorithm::EcdsaP256
                    .validate_key(&material.key)
                    .is_err()
            );
        }
    }
}

#[test]
fn invalid_choice_and_key_data_fail_without_fallback() {
    assert_eq!(
        CertificateKeyAlgorithm::default(),
        CertificateKeyAlgorithm::EcdsaP256
    );
    for value in ["rsa-1024", "rsa-16384", "ec-257", "", "ECDSA-P256"] {
        assert!(CertificateKeyAlgorithm::from_name(value).is_none());
        assert!(serde_json::from_str::<CertificateKeyAlgorithm>(&format!("\"{value}\"")).is_err());
    }
    for algorithm in CertificateKeyAlgorithm::ALL {
        assert!(algorithm.validate_key(b"invalid pkcs8").is_err());
    }
}
