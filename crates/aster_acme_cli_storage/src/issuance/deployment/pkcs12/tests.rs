//! Independent vectors, DER structure, key recovery and source policy.
use crate::issuance::deployment::pkcs12::{
    CertBag, ContentInfo, EncryptedPrivateKeyInfo, OID_CERT_BAG, OID_FRIENDLY_NAME,
    OID_LOCAL_KEY_ID, OID_PKCS8_SHROUDED_KEY_BAG, Pfx, SafeBag, aes256_cbc_encrypt, bmp_password,
    build_pkcs12, oid, pbkdf2_sha256, pem_certificates, pkcs12_kdf, resolve_password,
};
use aes::{
    Aes256,
    cipher::{BlockDecrypt as _, KeyInit as _, generic_array::GenericArray},
};
use der::{Decode as _, Encode as _, Tag, Tagged as _};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").unwrap();
        out
    })
}

#[test]
fn kdf_vectors_cover_multi_block_output_and_carry() {
    // OpenSSL PKCS12KDF: SHA256, UTF16BE "password" + NUL, salt 0102030405060708,
    // id 3, 2048 iterations, 80 output bytes. PBKDF2 verified with Python hashlib.
    let salt = [1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(
        hex(&pkcs12_kdf(
            &bmp_password("password").unwrap(),
            &salt,
            3,
            2048,
            80
        )),
        "4f510e1b5428cb3a1b784ceee7b1a95670f60e825199c121bd1752ee9e1c83f22374e2e4e98372ed5935c9eca9f357fad6bcdfa27fd2737f2282d92b9821af730a4739d7c016fb31d25c6b3cf49a0275"
    );
    assert_eq!(
        hex(&pbkdf2_sha256(b"password", &salt, 2048, 65).unwrap()),
        "88741976b8f91388b88bc4f49733edd539657cf7351edbf16a4327c5404fab25b1c75498aa59e42dbc4b652e54dd2cac46d057f6e99188091d95a34409fb431801"
    );
    assert_eq!(
        hex(&pbkdf2_sha256(b"password", b"salt", 1, 32).unwrap()),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
}

fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).unwrap();
    let mut previous = iv.to_vec();
    let mut plaintext = Vec::new();
    let (blocks, remainder) = ciphertext.as_chunks::<16>();
    assert!(
        remainder.is_empty(),
        "ciphertext must contain complete AES blocks"
    );
    for chunk in blocks {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        plaintext.extend(block.iter().zip(&previous).map(|(a, b)| a ^ b));
        previous.copy_from_slice(chunk);
    }
    let pad = *plaintext.last().unwrap() as usize;
    assert!((1..=16).contains(&pad));
    assert!(
        plaintext[plaintext.len() - pad..]
            .iter()
            .all(|b| *b as usize == pad)
    );
    plaintext.truncate(plaintext.len() - pad);
    plaintext
}

#[test]
fn cbc_handles_empty_partial_and_block_aligned_plaintext() {
    for len in [0, 1, 15, 16, 17, 32, 97] {
        let input = vec![42; len];
        let encrypted = aes256_cbc_encrypt(&[7; 32], &[8; 16], &input).unwrap();
        assert_eq!(encrypted.len(), (len / 16 + 1) * 16);
        assert_eq!(decrypt(&[7; 32], &[8; 16], &encrypted), input);
    }
}

#[test]
#[should_panic(expected = "ciphertext must contain complete AES blocks")]
fn key_recovery_rejects_a_partial_trailing_block() {
    let mut encrypted = aes256_cbc_encrypt(&[7; 32], &[8; 16], b"key").unwrap();
    encrypted.push(0);
    decrypt(&[7; 32], &[8; 16], &encrypted);
}

#[test]
fn bundle_structure_mac_attributes_and_private_key_round_trip() {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["example.test".into()]).unwrap();
    let ca = rcgen::generate_simple_self_signed(vec!["ca.test".into()])
        .unwrap()
        .cert;
    let key = signing_key.serialize_der();
    for password in ["password", "中文päss"] {
        let bundle = build_pkcs12(cert.der(), ca.pem().as_bytes(), &key, "web", password).unwrap();
        let pfx = Pfx::from_der(&bundle).unwrap();
        assert_eq!(pfx.version, 3);
        let auth_bytes = pfx.auth_safe.content.value();
        let mac = pfx.mac_data.unwrap();
        let mac_key = pkcs12_kdf(
            &bmp_password(password).unwrap(),
            mac.mac_salt.as_bytes(),
            3,
            mac.iterations,
            32,
        );
        let mut verifier = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
        verifier.update(auth_bytes);
        verifier.verify_slice(mac.mac.digest.as_bytes()).unwrap();
        let bad_key = pkcs12_kdf(
            &bmp_password("wrong").unwrap(),
            mac.mac_salt.as_bytes(),
            3,
            mac.iterations,
            32,
        );
        let mut verifier = Hmac::<Sha256>::new_from_slice(&bad_key).unwrap();
        verifier.update(auth_bytes);
        assert!(verifier.verify_slice(mac.mac.digest.as_bytes()).is_err());
        let safes = Vec::<ContentInfo>::from_der(auth_bytes).unwrap();
        assert_eq!(safes.len(), 2);
        let certs = Vec::<SafeBag>::from_der(safes[0].content.value()).unwrap();
        let keys = Vec::<SafeBag>::from_der(safes[1].content.value()).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(keys.len(), 1);
        let mut leaf_id = None;
        for (index, bag) in certs.iter().chain(keys.iter()).enumerate() {
            assert_eq!(
                bag.id,
                oid(if index < 2 {
                    OID_CERT_BAG
                } else {
                    OID_PKCS8_SHROUDED_KEY_BAG
                })
                .unwrap()
            );
            let attrs = bag.attributes.as_ref().unwrap();
            let mut id = None;
            for attr in attrs.iter() {
                let value = attr.attr_values.iter().next().unwrap();
                if attr.attr_id == oid(OID_FRIENDLY_NAME).unwrap() {
                    assert_eq!(value.tag(), Tag::BmpString);
                    assert_eq!(value.value(), b"\0w\0e\0b");
                } else if attr.attr_id == oid(OID_LOCAL_KEY_ID).unwrap() {
                    id = Some(value.value().to_vec());
                } else {
                    panic!("unexpected attribute");
                }
            }
            match index {
                0 => {
                    assert!(id.is_some());
                    leaf_id = id;
                }
                1 => assert!(id.is_none()),
                _ => assert_eq!(id, leaf_id),
            }
        }
        let leaf = CertBag::from_der(&certs[0].value.to_der().unwrap()).unwrap();
        assert_eq!(leaf.cert_value.value(), cert.der().as_ref());
        let issuer = CertBag::from_der(&certs[1].value.to_der().unwrap()).unwrap();
        assert_eq!(issuer.cert_value.value(), ca.der().as_ref());
        let encrypted =
            EncryptedPrivateKeyInfo::from_der(&keys[0].value.to_der().unwrap()).unwrap();
        let params = encrypted.algorithm.parameters;
        let pbkdf = params.key_derivation_func.parameters;
        let aes_key = pbkdf2_sha256(
            password.as_bytes(),
            pbkdf.salt.as_bytes(),
            pbkdf.iteration_count,
            32,
        )
        .unwrap();
        assert_eq!(
            decrypt(
                &aes_key,
                params.encryption_scheme.parameters.as_bytes(),
                encrypted.encrypted_data.as_bytes()
            ),
            key
        );
        assert_ne!(
            bundle,
            build_pkcs12(cert.der(), ca.pem().as_bytes(), &key, "web", password).unwrap()
        );
    }
}

#[test]
fn password_sources_fail_closed_without_disclosing_values() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("secret");
    assert!(resolve_password(None, None).is_err());
    assert!(resolve_password(Some("ASTER_ACME_TEST_ABSENT_P12_9F4387"), None).is_err());
    assert!(resolve_password(Some("BAD=ENV"), None).is_err());
    assert!(resolve_password(Some("BOTH"), Some(&path)).is_err());
    assert!(resolve_password(None, Some(&path)).is_err());
    for value in [b"".as_slice(), b"\n", b"\xff", b"a\0b", &[42; 4097]] {
        crate::toml_file::atomic_write(&path, value).unwrap();
        assert!(resolve_password(None, Some(&path)).is_err());
    }
    for (contents, expected) in [
        ("secret with spaces\r\nignored", "secret with spaces"),
        ("secret with spaces\nignored", "secret with spaces"),
        ("secret with spaces\r", "secret with spaces\r"),
        (" secret with spaces ", " secret with spaces "),
        ("\r", "\r"),
        ("secret\r\r\nignored", "secret\r"),
    ] {
        crate::toml_file::atomic_write(&path, contents.as_bytes()).unwrap();
        assert_eq!(
            resolve_password(None, Some(&path)).unwrap().as_str(),
            expected
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(resolve_password(None, Some(&path)).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(resolve_password(None, Some(&link)).is_err());
    }
    for value in ["", "x\0y", "🦀"] {
        assert!(bmp_password(value).is_err());
    }
    assert_eq!(
        bmp_password("päss").unwrap().as_slice(),
        b"\0p\0\xe4\0s\0s\0\0"
    );
}

#[test]
fn chain_parser_rejects_non_certificate_content() {
    assert!(pem_certificates(b"junk").is_err());
    assert!(
        pem_certificates(b"junk\n-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----")
            .is_err()
    );
    assert!(pem_certificates(b"-----BEGIN CERTIFICATE-----\nYWJj").is_err());
    assert!(
        pem_certificates(b"-----BEGIN CERTIFICATE-----\n?\n-----END CERTIFICATE-----").is_err()
    );
    assert_eq!(pem_certificates(b"\n").unwrap(), Vec::<Vec<u8>>::new());
}
