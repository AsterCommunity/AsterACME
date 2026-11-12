//! Wire-contract tests compare literal JSON, independent of transport implementations.
use crate::{account::*, directory::Directory, jws::*, problem::Problem, url::AcmeUrl};
use aster_acme_core::protocol::AccountStatus;

#[test]
fn public_provider_names_serde_and_directories_have_one_registry() {
    use crate::directory::Provider;
    for (provider, name, url) in [
        (
            Provider::Letsencrypt,
            "letsencrypt",
            "https://acme-v02.api.letsencrypt.org/directory",
        ),
        (
            Provider::Zerossl,
            "zerossl",
            "https://acme.zerossl.com/v2/DV90",
        ),
        (
            Provider::Google,
            "google",
            "https://dv.acme-v02.api.pki.goog/directory",
        ),
    ] {
        assert_eq!(provider.name(), name);
        assert_eq!(Provider::from_name(name), Some(provider));
        assert_eq!(provider.directory(), url);
        assert!(AcmeUrl::new(url).is_ok());
        let encoded = serde_json::to_string(&provider).unwrap();
        assert_eq!(encoded, format!("\"{name}\""));
        assert_eq!(
            serde_json::from_str::<Provider>(&encoded).unwrap(),
            provider
        );
    }
    assert_eq!(Provider::ALL.len(), 3);
    assert_eq!(Provider::from_name("unknown"), None);
    assert!(serde_json::from_str::<Provider>(r#""unknown""#).is_err());
}

#[test]
fn request_shapes_omit_optional_fields_and_keep_lookup_separate() {
    assert_eq!(
        serde_json::to_string(&FindAccountRequest {
            only_return_existing: true
        })
        .unwrap(),
        r#"{"onlyReturnExisting":true}"#
    );
    let empty = NewAccountRequest {
        contact: None,
        terms_of_service_agreed: None,
        external_account_binding: None,
    };
    assert_eq!(serde_json::to_string(&empty).unwrap(), "{}");
    let contacts = vec!["mailto:a@example.com".into()];
    let request = NewAccountRequest {
        contact: Some(&contacts),
        terms_of_service_agreed: Some(true),
        external_account_binding: None,
    };
    assert_eq!(
        serde_json::to_string(&request).unwrap(),
        r#"{"contact":["mailto:a@example.com"],"termsOfServiceAgreed":true}"#
    );
    assert_eq!(
        serde_json::to_string(&AccountStatusRequest {
            status: AccountStatus::Deactivated
        })
        .unwrap(),
        r#"{"status":"deactivated"}"#
    );
}

#[test]
fn account_response_distinguishes_absent_empty_and_unknown_fields() {
    let absent: AccountObject =
        serde_json::from_str(r#"{"status":"future","extension":true}"#).unwrap();
    assert_eq!(absent.status, AccountStatus::Unknown("future".into()));
    assert_eq!(absent.contact, None);
    let empty: AccountObject = serde_json::from_str(r#"{"status":"valid","contact":[]}"#).unwrap();
    assert_eq!(empty.contact, Some(vec![]));
    for invalid in [
        "{}",
        r#"{"status":2}"#,
        r#"{"status":"valid","contact":"wrong"}"#,
    ] {
        assert!(serde_json::from_str::<AccountObject>(invalid).is_err());
    }
}

#[test]
fn headers_have_exclusive_identity_and_eab_has_no_nonce() {
    #[derive(serde::Serialize)]
    struct PublicKey {
        kty: &'static str,
    }
    let key = PublicKey { kty: "EC" };
    for identity in [
        RequestIdentity::Jwk { jwk: &key },
        RequestIdentity::Kid {
            kid: "https://ca.example/custom-account",
        },
    ] {
        let value = serde_json::to_value(ProtectedHeader {
            alg: crate::jws::SignatureAlgorithm::Es256,
            identity,
            nonce: "nonce",
            url: "https://ca.example/a%2fb",
        })
        .unwrap();
        assert_ne!(value.get("jwk").is_some(), value.get("kid").is_some());
        assert_eq!(value["url"], "https://ca.example/a%2fb");
    }
    assert_eq!(
        serde_json::to_string(&EabHeader {
            alg: "HS256",
            kid: "external",
            url: "https://ca.example/new"
        })
        .unwrap(),
        r#"{"alg":"HS256","kid":"external","url":"https://ca.example/new"}"#
    );
}

#[test]
fn directory_and_problem_parse_custom_endpoints_without_assumed_paths() {
    let directory: Directory = serde_json::from_str(r#"{"newNonce":"https://ca.example/custom/n%2fonce","newAccount":"https://other.example/api?new=account","meta":{"externalAccountRequired":true},"extension":true}"#).unwrap();
    assert_eq!(
        directory.new_nonce.as_str(),
        "https://ca.example/custom/n%2fonce"
    );
    assert_eq!(
        directory.new_account.as_str(),
        "https://other.example/api?new=account"
    );
    assert!(directory.meta.external_account_required);
    let problem: Problem = serde_json::from_str(r#"{"type":"urn:custom:problem","status":429,"subproblems":[{"type":"nested","detail":"why"}]}"#).unwrap();
    assert_eq!(problem.extensions["status"], 429);
    assert_eq!(problem.subproblems[0].detail.as_deref(), Some("why"));
}

#[test]
fn resource_urls_keep_exact_spelling_and_reject_unsafe_input() {
    let exact = "https://ca.example/a%2fb?x=%41";
    let url = AcmeUrl::new(exact).unwrap();
    assert_eq!(serde_json::to_string(&url).unwrap(), format!("\"{exact}\""));
    for invalid in [
        "relative",
        "http://ca.example/a",
        "https://ca.example/#fragment",
        " https://ca.example/",
        "https://ca.example/\n",
    ] {
        assert!(AcmeUrl::new(invalid).is_err());
    }
}

#[test]
fn method_specific_fields_do_not_make_unknown_challenges_require_dns01_tokens() {
    use crate::order::{AuthorizationObject, WireChallengeKind};
    let resource = serde_json::json!({"identifier":{"type":"dns","value":"example.com"},"status":"pending","expires":"2099-01-01T00:00:00Z","challenges":[
        {"type":"dns-persist-01","status":"pending","url":"https://ca.example/persist","issuer-domain-names":["letsencrypt.org"]},
        {"type":"dns-01","status":"pending","url":"https://ca.example/dns","token":"long-enough-opaque-token"},
        {"type":"future","status":"pending","url":"https://ca.example/future","token":{"extension":true}}
    ]});
    let parsed: AuthorizationObject = serde_json::from_value(resource.clone()).unwrap();
    assert!(
        matches!(&parsed.challenges[0].kind,WireChallengeKind::Unknown(value) if value=="dns-persist-01")
    );
    assert_eq!(
        parsed.challenges[0].parameters["issuer-domain-names"],
        serde_json::json!(["letsencrypt.org"])
    );
    assert_eq!(
        serde_json::to_value(&parsed).unwrap()["challenges"][0]["issuer-domain-names"],
        resource["challenges"][0]["issuer-domain-names"]
    );
    assert!(!parsed.challenges[0].parameters.contains_key("token"));
    assert_eq!(
        parsed.challenges[1].parameters["token"],
        "long-enough-opaque-token"
    );
    assert_eq!(
        parsed.challenges[2].parameters["token"],
        resource["challenges"][2]["token"]
    );
    for key in ["type", "url", "status"] {
        let mut invalid = resource.clone();
        invalid["challenges"][0]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(serde_json::from_value::<AuthorizationObject>(invalid).is_err());
    }
}

#[test]
fn exact_urls_reject_only_characters_reencoded_by_http_url_parsing() {
    // RFC 3986 permits the character; this is a transport serialization limit,
    // required to preserve RFC 8555 §6.4's exact signed server URL.
    assert_eq!(
        url::Url::parse("https://ca.example/order?x='a'")
            .unwrap()
            .query(),
        Some("x=%27a%27")
    );
    for value in [
        "https://ca.example/a b",
        "https://ca.example/a\\b",
        "https://ca.example/`",
        "https://ca.example/{x}",
        "https://ca.example/<x>",
        "https://ca.example/\"x",
        "https://ca.example/order?x='a'",
    ] {
        assert!(crate::url::AcmeUrl::new(value).is_err(), "{value}");
    }
    let value = "https://ca.example/%41?exact=%2f";
    assert_eq!(crate::url::AcmeUrl::new(value).unwrap().as_str(), value);
    for value in [
        "https://ca.example/order'quote",
        "https://ca.example/order?x=%27a%27",
    ] {
        assert_eq!(crate::url::AcmeUrl::new(value).unwrap().as_str(), value);
    }
}

#[test]
fn exact_urls_reject_dot_segment_normalization_without_reencoding_valid_paths() {
    for path in [
        "a/../order",
        "a/./order",
        "a/%2e%2e/order",
        "%2E/order",
        "a/.%2e/order",
    ] {
        assert!(crate::url::AcmeUrl::new(&format!("https://ca.example/{path}")).is_err());
    }
    for path in ["a%2fb", "order'quote", "x..y/order", "%252e%252e/order"] {
        assert!(crate::url::AcmeUrl::new(&format!("https://ca.example/{path}")).is_ok());
    }
}
