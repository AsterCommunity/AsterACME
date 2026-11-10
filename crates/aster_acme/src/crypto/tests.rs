//! Signature, identity and encoding boundaries.
use super::*;
use aws_lc_rs::signature::UnparsedPublicKey;

#[test]
fn key_change_inner_signature_binds_new_key_old_key_and_exact_account_url() {
    let old = AccountKey::generate().unwrap();
    let new = AccountKey::generate().unwrap();
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
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, new.0.public_key().as_ref())
        .verify(input.as_bytes(), &signature)
        .unwrap();
    assert!(
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, old.0.public_key().as_ref())
            .verify(input.as_bytes(), &signature)
            .is_err()
    );
}

#[test]
fn key_pkcs8_roundtrip_and_signatures_verify_with_raw_rs_format() {
    let key = AccountKey::generate().unwrap();
    let restored = AccountKey::from_pkcs8(&key.to_pkcs8().unwrap()).unwrap();
    assert_eq!(key.jwk().unwrap(), restored.jwk().unwrap());
    let signature = restored.sign(b"message").unwrap();
    assert_eq!(signature.len(), 64);
    let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.0.public_key().as_ref());
    verifier.verify(b"message", &signature).unwrap();
    assert!(verifier.verify(b"changed", &signature).is_err());
    for invalid in [b"".as_slice(), b"invalid", &[0; 32]] {
        assert!(AccountKey::from_pkcs8(invalid).is_err());
    }
}

#[test]
fn jwk_thumbprint_uses_only_sorted_required_members() {
    let key = AccountKey::generate().unwrap();
    let jwk = key.jwk().unwrap();
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk.x, jwk.y
    );
    assert_eq!(serde_json::to_string(&jwk).unwrap(), canonical);
    assert_eq!(
        jwk.thumbprint().unwrap(),
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical))
    );
    assert!(Es256Jwk::from_sec1(&[0; 65]).is_err());
}

#[test]
fn jws_jwk_and_kid_are_exclusive_and_post_as_get_is_empty() {
    let key = AccountKey::generate().unwrap();
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
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.0.public_key().as_ref())
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
    let key = AccountKey::generate().unwrap();
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
    assert_eq!(jwk.x, "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY");
    assert_eq!(jwk.y, "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU");
    let signature=URL_SAFE_NO_PAD.decode("dnzkwp_T0oBSkuyvKCs-qNoLOvuFMvoLlv58_Lpeq6ksJ3rP618VLmFi6kj4U0FtMu5N2ehjwobuEQqDfNrCIg").unwrap();
    let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.0.public_key().as_ref());
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
    for invalid in [
        vec![],
        vec![4; 65],
        key.0.public_key().as_ref()[..64].to_vec(),
    ] {
        assert!(Es256Jwk::from_sec1(&invalid).is_err());
    }
}
