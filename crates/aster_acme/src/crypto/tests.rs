//! Signature, identity and encoding boundaries.
use crate::crypto::key::AccountKey;
use crate::crypto::*;
use aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED;
use aws_lc_rs::signature::UnparsedPublicKey;
use sha2::Digest as _;

#[test]
fn key_change_inner_signature_binds_new_key_old_key_and_exact_account_url() {
    let old = AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let new = AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let account = AcmeUrl::new("https://ca.example/user/%41?x=%2f").unwrap();
    let endpoint = "https://ca.example/rollover/%2f?x=%41";
    let inner = sign_key_change(&new, &old.jwk().unwrap(), &account, endpoint).unwrap();
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&inner.protected).unwrap()).unwrap();
    assert_eq!(
        header,
        serde_json::json!({"alg":"ES256", "jwk":new.jwk().unwrap(), "url":endpoint})
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&inner.payload).unwrap()).unwrap();
    assert_eq!(
        payload,
        serde_json::json!({"account":account.as_str(), "oldKey":old.jwk().unwrap()})
    );
    let signature = URL_SAFE_NO_PAD.decode(&inner.signature).unwrap();
    let input = format!("{}.{}", inner.protected, inner.payload);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, new.public_key())
        .verify(input.as_bytes(), &signature)
        .unwrap();
    assert!(
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, old.public_key())
            .verify(input.as_bytes(), &signature)
            .is_err()
    );
}

#[test]
fn key_pkcs8_roundtrip_and_signatures_verify_with_raw_rs_format() {
    let key = AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let restored = AccountKey::from_pkcs8(&key.to_pkcs8().unwrap()).unwrap();
    assert_eq!(key.jwk().unwrap(), restored.jwk().unwrap());
    let signature = restored.sign(b"message").unwrap();
    assert_eq!(signature.len(), 64);
    let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key());
    verifier.verify(b"message", &signature).unwrap();
    assert!(verifier.verify(b"changed", &signature).is_err());
    for invalid in [b"".as_slice(), b"invalid", &[0; 32]] {
        assert!(AccountKey::from_pkcs8(invalid).is_err());
    }
}

#[test]
fn jwk_thumbprint_uses_only_sorted_required_members() {
    let key = AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let jwk = key.jwk().unwrap();
    let public = serde_json::to_value(&jwk).unwrap();
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        public["x"].as_str().unwrap(),
        public["y"].as_str().unwrap()
    );
    assert_eq!(serde_json::to_string(&jwk).unwrap(), canonical);
    assert_eq!(
        jwk.thumbprint().unwrap(),
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical))
    );
    assert!(Jwk::from_sec1(KeyAlgorithm::EcdsaP256, &[0; 65]).is_err());
}

#[test]
fn jws_jwk_and_kid_are_exclusive_and_post_as_get_is_empty() {
    let key = AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let jwk = key.jwk().unwrap();
    for identity in [
        RequestIdentity::Jwk { jwk: &jwk },
        RequestIdentity::Kid {
            kid: "https://ca/account/1",
        },
    ] {
        let jws = sign_request(&key, identity, "nonce", "https://ca/path%2Fexact", b"").unwrap();
        let protected: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&jws.protected).unwrap()).unwrap();
        assert_eq!(protected["url"], "https://ca/path%2Fexact");
        assert_eq!(protected["alg"], "ES256");
        assert_eq!(protected["nonce"], "nonce");
        assert_ne!(
            protected.get("jwk").is_some(),
            protected.get("kid").is_some()
        );
        assert_eq!(jws.payload, "");
        let signature = URL_SAFE_NO_PAD.decode(jws.signature).unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key())
            .verify(
                format!("{}.{}", jws.protected, jws.payload).as_bytes(),
                &signature,
            )
            .unwrap();
    }
    assert_ne!(
        sign_request(
            &key,
            RequestIdentity::Jwk { jwk: &jwk },
            "n",
            "https://ca",
            b"{}"
        )
        .unwrap()
        .payload,
        ""
    );
}

#[test]
fn eab_binds_exact_public_key_and_has_no_nonce() {
    let key = AccountKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let jwk = key.jwk().unwrap();
    let secret = [9_u8; 32];
    for encoded in [URL_SAFE_NO_PAD.encode(secret), URL_SAFE.encode(secret)] {
        let credentials = ExternalAccountCredentials::new("external-id", &encoded).unwrap();
        let jws = credentials.bind(&jwk, "https://ca/new-account").unwrap();
        let protected: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&jws.protected).unwrap()).unwrap();
        assert_eq!(
            protected,
            serde_json::json!({"alg":"HS256","kid":"external-id","url":"https://ca/new-account"})
        );
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&jws.payload).unwrap(),
            serde_json::to_vec(&jwk).unwrap()
        );
        let mut verifier = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
        verifier.update(format!("{}.{}", jws.protected, jws.payload).as_bytes());
        verifier
            .verify_slice(&URL_SAFE_NO_PAD.decode(&jws.signature).unwrap())
            .unwrap();
    }
    for kid in ["", "bad\n", "非ASCII"] {
        assert!(ExternalAccountCredentials::new(kid, &URL_SAFE_NO_PAD.encode(secret)).is_err());
    }
    for secret in [
        String::new(),
        "!".into(),
        URL_SAFE_NO_PAD.encode([1_u8; 31]),
        "a".repeat(8193),
    ] {
        assert!(ExternalAccountCredentials::new("id", &secret).is_err());
    }
}

#[test]
fn external_pkcs8_fixture_keeps_jwk_and_raw_es256_interoperability() {
    // Public test scalar 1, encoded and signed independently with Python cryptography.
    // This is deliberately a test-only key, never an account or certificate credential.
    let der=URL_SAFE_NO_PAD.decode("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGhRANCAARrF9Hy4SxCR_i85uVjpEDydwN9gS3rM6D0oTlF2JjClk_jQuL-Gn-bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1").unwrap();
    let key = AccountKey::from_pkcs8(&der).unwrap();
    let jwk = key.jwk().unwrap();
    let public = serde_json::to_value(&jwk).unwrap();
    assert_eq!(public["x"], "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY");
    assert_eq!(public["y"], "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU");
    let signature=URL_SAFE_NO_PAD.decode("dnzkwp_T0oBSkuyvKCs-qNoLOvuFMvoLlv58_Lpeq6ksJ3rP618VLmFi6kj4U0FtMu5N2ehjwobuEQqDfNrCIg").unwrap();
    let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key());
    verifier
        .verify(
            b"AsterACME ES256 PKCS8 interoperability fixture",
            &signature,
        )
        .unwrap();
    assert!(verifier.verify(b"tampered", &signature).is_err());
    assert_eq!(
        AccountKey::from_pkcs8(&key.to_pkcs8().unwrap())
            .unwrap()
            .jwk()
            .unwrap(),
        jwk
    );
    for invalid in [vec![], vec![4; 65], key.public_key()[..64].to_vec()] {
        assert!(Jwk::from_sec1(KeyAlgorithm::EcdsaP256, &invalid).is_err());
    }
}

fn verify_account_jws(key: &AccountKey, jws: &FlattenedJws) {
    use aws_lc_rs::signature;
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&jws.protected).unwrap()).unwrap();
    let public = serde_json::to_value(key.jwk().unwrap()).unwrap();
    let signature = URL_SAFE_NO_PAD.decode(&jws.signature).unwrap();
    let message = format!("{}.{}", jws.protected, jws.payload);
    let expected = match key.algorithm() {
        KeyAlgorithm::EcdsaP256 => "ES256",
        KeyAlgorithm::EcdsaP384 => "ES384",
        KeyAlgorithm::EcdsaP521 => "ES512",
        KeyAlgorithm::Ed25519 => "EdDSA",
        KeyAlgorithm::Rsa2048
        | KeyAlgorithm::Rsa3072
        | KeyAlgorithm::Rsa4096
        | KeyAlgorithm::Rsa8192 => "RS256",
    };
    assert_eq!(header["alg"], expected);
    match key.algorithm() {
        KeyAlgorithm::Rsa2048
        | KeyAlgorithm::Rsa3072
        | KeyAlgorithm::Rsa4096
        | KeyAlgorithm::Rsa8192 => {
            let n = URL_SAFE_NO_PAD
                .decode(public["n"].as_str().unwrap())
                .unwrap();
            let e = URL_SAFE_NO_PAD
                .decode(public["e"].as_str().unwrap())
                .unwrap();
            assert_ne!(n[0], 0);
            assert_ne!(e[0], 0);
            let verifier = aws_lc_rs::rsa::PublicKeyComponents { n: &n, e: &e };
            verifier
                .verify(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    message.as_bytes(),
                    &signature,
                )
                .unwrap();
            assert!(
                verifier
                    .verify(
                        &signature::RSA_PKCS1_2048_8192_SHA256,
                        b"tampered",
                        &signature
                    )
                    .is_err()
            );
            assert_eq!(signature.len(), n.len());
            assert_eq!(public["kty"], "RSA");
        }
        algorithm => {
            let (verifier, public_key, size): (&dyn signature::VerificationAlgorithm, _, _) =
                match algorithm {
                    KeyAlgorithm::EcdsaP256 => {
                        (&signature::ECDSA_P256_SHA256_FIXED, key.public_key(), 64)
                    }
                    KeyAlgorithm::EcdsaP384 => {
                        (&signature::ECDSA_P384_SHA384_FIXED, key.public_key(), 96)
                    }
                    KeyAlgorithm::EcdsaP521 => {
                        (&signature::ECDSA_P521_SHA512_FIXED, key.public_key(), 132)
                    }
                    KeyAlgorithm::Ed25519 => (&signature::ED25519, key.public_key(), 64),
                    KeyAlgorithm::Rsa2048
                    | KeyAlgorithm::Rsa3072
                    | KeyAlgorithm::Rsa4096
                    | KeyAlgorithm::Rsa8192 => panic!("RSA handled above"),
                };
            let verifier = signature::UnparsedPublicKey::new(verifier, public_key);
            verifier.verify(message.as_bytes(), &signature).unwrap();
            assert!(verifier.verify(b"tampered", &signature).is_err());
            assert_eq!(signature.len(), size);
        }
    }
}

#[test]
fn all_account_algorithms_roundtrip_and_emit_verifiable_jwk_kid_and_eab_requests() {
    for algorithm in KeyAlgorithm::ALL {
        let key = AccountKey::generate(algorithm).unwrap();
        let encoded = key.to_pkcs8().unwrap();
        let restored = AccountKey::from_pkcs8(&encoded).unwrap();
        assert_eq!(restored.algorithm(), algorithm);
        assert_eq!(restored.jwk().unwrap(), key.jwk().unwrap());
        let jwk = key.jwk().unwrap();
        let canonical = serde_json::to_vec(&jwk).unwrap();
        let sorted: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_slice(&canonical).unwrap();
        assert_eq!(canonical, serde_json::to_vec(&sorted).unwrap());
        assert_eq!(
            jwk.thumbprint().unwrap(),
            URL_SAFE_NO_PAD.encode(Sha256::digest(&canonical))
        );
        for identity in [
            RequestIdentity::Jwk { jwk: &jwk },
            RequestIdentity::Kid {
                kid: "https://ca.example/account/1",
            },
        ] {
            let jws = sign_request(
                &restored,
                identity,
                "fresh_nonce",
                "https://ca.example/exact%2f",
                b"",
            )
            .unwrap();
            assert_eq!(jws.payload, "");
            verify_account_jws(&restored, &jws);
        }
        let secret = [3_u8; 32];
        let binding = ExternalAccountCredentials::new("external", &URL_SAFE_NO_PAD.encode(secret))
            .unwrap()
            .bind(&jwk, "https://ca.example/new-account")
            .unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&binding.payload).unwrap(), canonical);
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
        mac.update(format!("{}.{}", binding.protected, binding.payload).as_bytes());
        mac.verify_slice(&URL_SAFE_NO_PAD.decode(binding.signature).unwrap())
            .unwrap();
        let wrong = match algorithm {
            KeyAlgorithm::EcdsaP256 => KeyAlgorithm::Ed25519,
            _ => KeyAlgorithm::EcdsaP256,
        };
        assert!(wrong.validate_key(&encoded).is_err());
    }
}

#[test]
fn cross_algorithm_rollover_signs_inner_with_new_key_and_outer_with_old_key() {
    let algorithms = [
        KeyAlgorithm::EcdsaP256,
        KeyAlgorithm::Rsa2048,
        KeyAlgorithm::Ed25519,
        KeyAlgorithm::EcdsaP384,
        KeyAlgorithm::EcdsaP521,
    ];
    let keys = algorithms.map(|algorithm| AccountKey::generate(algorithm).unwrap());
    let account = AcmeUrl::new("https://ca.example/account/%2f").unwrap();
    let endpoint = "https://ca.example/change-key?exact=%41";
    for index in 0..keys.len() {
        let old = &keys[index];
        let new = &keys[(index + 1) % keys.len()];
        let inner = sign_key_change(new, &old.jwk().unwrap(), &account, endpoint).unwrap();
        verify_account_jws(new, &inner);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&inner.protected).unwrap()).unwrap();
        assert_eq!(
            header["jwk"],
            serde_json::to_value(new.jwk().unwrap()).unwrap()
        );
        assert!(header.get("nonce").is_none() && header.get("kid").is_none());
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&inner.payload).unwrap()).unwrap();
        assert_eq!(
            payload["oldKey"],
            serde_json::to_value(old.jwk().unwrap()).unwrap()
        );
        assert_eq!(payload["account"], account.as_str());
        let outer = sign_request(
            old,
            RequestIdentity::Kid {
                kid: account.as_str(),
            },
            "fresh_nonce",
            endpoint,
            &serde_json::to_vec(&inner).unwrap(),
        )
        .unwrap();
        verify_account_jws(old, &outer);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&outer.payload).unwrap(),
            serde_json::to_vec(&inner).unwrap()
        );
    }
}

#[test]
fn malformed_public_keys_and_unsupported_or_truncated_private_keys_are_rejected() {
    for algorithm in [
        KeyAlgorithm::EcdsaP256,
        KeyAlgorithm::EcdsaP384,
        KeyAlgorithm::EcdsaP521,
    ] {
        for bytes in [vec![], vec![4; 65], vec![0; 97], vec![4; 133]] {
            assert!(Jwk::from_sec1(algorithm, &bytes).is_err());
        }
    }
    assert!(Jwk::from_sec1(KeyAlgorithm::Ed25519, &[4; 65]).is_err());
    assert!(Jwk::from_rsa_der(b"not DER").is_err());
    for bytes in [vec![], vec![0; 31], vec![0; 33]] {
        assert!(Jwk::from_ed25519(&bytes).is_err());
    }
    for algorithm in [
        KeyAlgorithm::EcdsaP256,
        KeyAlgorithm::EcdsaP384,
        KeyAlgorithm::EcdsaP521,
        KeyAlgorithm::Ed25519,
        KeyAlgorithm::Rsa2048,
    ] {
        let key = AccountKey::generate(algorithm).unwrap();
        let bytes = key.to_pkcs8().unwrap();
        let mut trailing = bytes.to_vec();
        trailing.extend_from_slice(b"extra");
        assert!(AccountKey::from_pkcs8(&trailing).is_err());
        for end in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert!(AccountKey::from_pkcs8(&bytes[..end]).is_err());
        }
    }
}

#[test]
fn independently_generated_keys_signatures_and_unsupported_algorithms_obey_jose_boundaries() {
    use aws_lc_rs::signature;
    #[derive(serde::Deserialize)]
    struct Fixture {
        algorithm: Option<KeyAlgorithm>,
        pkcs8: String,
        message: String,
        signature: Option<String>,
        jwk: Option<serde_json::Value>,
    }
    // Public throwaway keys/signatures produced with Python cryptography/OpenSSL,
    // independently of the AWS-LC implementation. Never use them as credentials.
    // Unsupported cases are RSA-1024, secp256k1 and Ed448, not damaged encodings.
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("fixtures/account-keys.json")).unwrap();
    for fixture in fixtures {
        let bytes = URL_SAFE_NO_PAD.decode(fixture.pkcs8).unwrap();
        let Some(algorithm) = fixture.algorithm else {
            assert!(AccountKey::from_pkcs8(&bytes).is_err());
            continue;
        };
        let key = AccountKey::from_pkcs8(&bytes).unwrap();
        assert_eq!(key.algorithm(), algorithm);
        assert_eq!(
            serde_json::to_value(key.jwk().unwrap()).unwrap(),
            fixture.jwk.unwrap()
        );
        let verifier: &dyn signature::VerificationAlgorithm = match algorithm {
            KeyAlgorithm::EcdsaP256 => &signature::ECDSA_P256_SHA256_FIXED,
            KeyAlgorithm::EcdsaP384 => &signature::ECDSA_P384_SHA384_FIXED,
            KeyAlgorithm::EcdsaP521 => &signature::ECDSA_P521_SHA512_FIXED,
            KeyAlgorithm::Ed25519 => &signature::ED25519,
            KeyAlgorithm::Rsa2048
            | KeyAlgorithm::Rsa3072
            | KeyAlgorithm::Rsa4096
            | KeyAlgorithm::Rsa8192 => &signature::RSA_PKCS1_2048_8192_SHA256,
        };
        let verifier = signature::UnparsedPublicKey::new(verifier, key.public_key());
        verifier
            .verify(
                fixture.message.as_bytes(),
                &URL_SAFE_NO_PAD.decode(fixture.signature.unwrap()).unwrap(),
            )
            .unwrap();
        verifier
            .verify(
                fixture.message.as_bytes(),
                &key.sign(fixture.message.as_bytes()).unwrap(),
            )
            .unwrap();
    }
}
