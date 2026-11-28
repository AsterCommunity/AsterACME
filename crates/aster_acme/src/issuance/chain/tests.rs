//! Alternate chain identity, matching and Link discovery boundaries.

use crate::issuance::chain::{
    ChainCandidate, ChainDecision, ChainIdentity, ChainName, ChainSelection, ChainSelector,
    chain_identity, dotted_oid, parse_alternate_links, rfc4514,
};
use aster_acme_protocol::url::AcmeUrl;
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair};
use x509_parser::prelude::FromDer as _;

fn certificate_pem(subject: impl FnOnce(&mut DistinguishedName)) -> Vec<u8> {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    let mut name = DistinguishedName::new();
    subject(&mut name);
    params.distinguished_name = name;
    let issuer = Issuer::new(params.clone(), KeyPair::generate().unwrap());
    let certificate = params.signed_by(&key, &issuer).unwrap();
    certificate.pem().into_bytes()
}

#[test]
fn chain_names_reject_empty_control_characters_and_oversized_values() {
    ChainName::new("C=US, O=ISRG, CN=ISRG Root X1").unwrap();
    assert!(ChainName::new("").is_err());
    assert!(ChainName::new("root\nx1").is_err());
    assert!(ChainName::new(&"x".repeat(513)).is_err());
    assert!(ChainName::new(&"x".repeat(512)).is_ok());
}

#[test]
fn chain_preferences_round_trip_through_serialization() {
    let default = ChainSelection::Default;
    let once = ChainSelection::Named {
        chain: ChainName::new("ISRG Root X1").unwrap(),
        remember: false,
    };
    let preferred = ChainSelection::Named {
        chain: ChainName::new("ISRG Root X2").unwrap(),
        remember: true,
    };
    for selection in [&default, &once, &preferred] {
        let encoded = serde_json::to_value(selection).unwrap();
        assert_eq!(
            serde_json::from_value::<ChainSelection>(encoded).unwrap(),
            *selection
        );
    }
    // Deserialization validates named values instead of trusting stored text.
    let invalid = serde_json::json!({"named": {"chain": "", "remember": true}});
    assert!(serde_json::from_value::<ChainSelection>(invalid).is_err());
    assert_eq!(
        serde_json::to_value(&default).unwrap(),
        serde_json::json!("default")
    );
}

#[test]
fn identities_match_exact_names_case_insensitively_and_common_names_as_fallback() {
    let identity = ChainIdentity {
        dn: "CN=ISRG Root X1,O=Internet Security Research Group,C=US".into(),
        common_name: Some("ISRG Root X1".into()),
        fingerprint_sha256: "ab".into(),
    };
    let exact = ChainName::new("CN=ISRG Root X1,O=Internet Security Research Group,C=US").unwrap();
    let insensitive =
        ChainName::new("cn=isrg root x1,o=internet security research group,c=us").unwrap();
    let common = ChainName::new("ISRG Root X1").unwrap();
    let padded = ChainName::new("  ISRG Root X1 ").unwrap();
    let unrelated = ChainName::new("ISRG Root X2").unwrap();
    let suffix = ChainName::new("CN=ISRG Root X1").unwrap();
    let unicode = ChainIdentity {
        dn: "CN=Étoile".into(),
        common_name: Some("Étoile".into()),
        fingerprint_sha256: "cd".into(),
    };
    for wanted in [&exact, &insensitive, &common, &padded] {
        assert!(identity.matches(wanted), "expected {wanted:?} to match");
    }
    for wanted in [&unrelated, &suffix] {
        assert!(
            !identity.matches(wanted),
            "expected {wanted:?} not to match"
        );
    }
    assert!(unicode.matches(&ChainName::new("étoile").unwrap()));
}

#[test]
fn serial_names_follow_rfc4514_order_and_abbreviations() {
    // ASN.1 order C, O, CN serializes reversed: CN first.
    let der = certificate_pem(|name| {
        name.push(DnType::CountryName, "US");
        name.push(DnType::OrganizationName, "Internet Security Research Group");
        name.push(DnType::CommonName, "ISRG Root X1");
    });
    let identity = chain_identity(&der).unwrap();
    assert_eq!(
        identity.dn,
        "CN=ISRG Root X1,O=Internet Security Research Group,C=US"
    );
    assert_eq!(identity.common_name.as_deref(), Some("ISRG Root X1"));
    assert_eq!(identity.fingerprint_sha256.len(), 64);
    assert!(
        identity
            .fingerprint_sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
}

#[test]
fn identities_reject_non_certificate_and_trailing_garbage_input() {
    assert!(chain_identity(b"not a certificate").is_err());
    let der = certificate_pem(|name| {
        name.push(DnType::CommonName, "leaf");
    });
    chain_identity(&der).unwrap();
    let mut trailing = der.clone();
    trailing.extend_from_slice(b"\x00\x01garbage");
    assert!(chain_identity(&trailing).is_err());
    let mut malformed_first =
        b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".to_vec();
    malformed_first.extend_from_slice(&der);
    assert!(chain_identity(&malformed_first).is_err());
}

#[test]
fn identities_describe_the_top_most_issuer_not_the_shared_leaf() {
    // Alternates share the leaf; only the chain tail distinguishes them.
    let leaf = certificate_pem(|name| {
        name.push(DnType::CommonName, "example.com");
    });
    let default_issuer = certificate_pem(|name| {
        name.push(DnType::CommonName, "Mock Default CA");
    });
    let alternate_issuer = certificate_pem(|name| {
        name.push(DnType::CommonName, "Mock Alternate CA");
    });
    let default_chain = [leaf.clone(), default_issuer.clone()].concat();
    let alternate_chain = [leaf, alternate_issuer.clone()].concat();
    let default_identity = chain_identity(&default_chain).unwrap();
    let alternate_identity = chain_identity(&alternate_chain).unwrap();
    assert_eq!(default_identity.dn, "CN=Mock Default CA");
    assert_eq!(alternate_identity.dn, "CN=Mock Alternate CA");
    assert_ne!(default_identity.dn, alternate_identity.dn);
    assert_ne!(
        default_identity.fingerprint_sha256,
        alternate_identity.fingerprint_sha256
    );
    assert_eq!(
        alternate_identity.common_name.as_deref(),
        Some("Mock Alternate CA")
    );
    // The tail wins even when a different certificate is prepended.
    assert_eq!(
        chain_identity(&[default_issuer, alternate_issuer].concat())
            .unwrap()
            .dn,
        "CN=Mock Alternate CA"
    );
}

#[test]
fn rfc4514_serializes_reversed_multi_valued_and_unknown_attributes() {
    use x509_parser::x509::X509Name;
    // Name ::= SEQUENCE OF SET OF { type, value }; hand-assemble two RDNs:
    // [SET{CN=leaf}, SET{O=org, C=us}] with a multi-valued second RDN and an
    // unrecognized OID in a third.
    let attribute = |oid: &[u8], value: &str| {
        let mut out = vec![0x30, 0];
        out.extend_from_slice(&[0x06, u8::try_from(oid.len()).unwrap()]);
        out.extend_from_slice(oid);
        let value = value.as_bytes();
        out.extend_from_slice(&[0x0c, u8::try_from(value.len()).unwrap()]);
        out.extend_from_slice(value);
        out[1] = u8::try_from(out.len() - 2).unwrap();
        out
    };
    let rdn = |attributes: Vec<Vec<u8>>| {
        let mut out = vec![0x31, 0];
        for attribute in attributes {
            out.extend_from_slice(&attribute);
        }
        out[1] = u8::try_from(out.len() - 2).unwrap();
        out
    };
    let mut name = vec![0x30, 0];
    name.extend(rdn(vec![attribute(&[0x55, 0x04, 0x03], "leaf.example")]));
    name.extend(rdn(vec![
        attribute(&[0x55, 0x04, 0x0a], "org"),
        attribute(&[0x55, 0x04, 0x06], "us"),
    ]));
    name.extend(rdn(vec![attribute(&[9], "private")]));
    name[1] = u8::try_from(name.len() - 2).unwrap();
    let (rest, parsed) = X509Name::from_der(&name).unwrap();
    assert_eq!(rest, &[] as &[u8]);
    assert_eq!(
        rfc4514(&parsed),
        "0.9=#0C0770726976617465,O=org+C=us,CN=leaf.example"
    );
}

#[test]
fn rfc4514_escapes_special_leading_trailing_and_control_characters() {
    use x509_parser::x509::X509Name;
    let attribute = |value: &str| {
        let mut out = vec![0x30, 0];
        out.extend_from_slice(&[0x06, 3, 0x55, 0x04, 0x03]);
        let value = value.as_bytes();
        out.extend_from_slice(&[0x0c, u8::try_from(value.len()).unwrap()]);
        out.extend_from_slice(value);
        out[1] = u8::try_from(out.len() - 2).unwrap();
        out
    };
    let rdn = |attribute: Vec<u8>| {
        let mut out = vec![0x31, 0];
        out.extend_from_slice(&attribute);
        out[1] = u8::try_from(out.len() - 2).unwrap();
        out
    };
    let mut name = vec![0x30, 0];
    name.extend(rdn(attribute("a,b+c\"d;e<f>g\\h")));
    name.extend(rdn(attribute(" leading")));
    name.extend(rdn(attribute("trailing ")));
    name.extend(rdn(attribute("ctrl\u{7}x")));
    name[1] = u8::try_from(name.len() - 2).unwrap();
    let (_, parsed) = X509Name::from_der(&name).unwrap();
    assert_eq!(
        rfc4514(&parsed),
        "CN=ctrl\\07x,CN=trailing\\ ,CN=\\ leading,CN=a\\,b\\+c\\\"d\\;e\\<f\\>g\\\\h"
    );
}

#[test]
fn dotted_oids_decode_single_multi_byte_and_high_arcs() {
    assert_eq!(dotted_oid(&[0x55, 0x04, 0x03]), "2.5.4.3");
    assert_eq!(dotted_oid(&[9]), "0.9");
    // 1.2.840.113549.1.9.1 (emailAddress) exercises multi-byte arcs.
    assert_eq!(
        dotted_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01]),
        "1.2.840.113549.1.9.1"
    );
    // arc0=2 with arc1=999 packs 40*2+999=1079 into the first sub-identifier.
    assert_eq!(dotted_oid(&[0x88, 0x37]), "2.999");
    assert_eq!(dotted_oid(&[]), "");
    assert_eq!(
        dotted_oid(&[
            0x84, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
            0x80, 0x80, 0x80, 0x80, 0x50
        ]),
        "2.340282366920938463463374607431768211456"
    );
}

#[test]
fn alternate_links_keep_server_order_and_ignore_other_relations() {
    let certificate = AcmeUrl::new("https://ca.example/acme/cert/1").unwrap();
    let headers = |values: &[&str]| {
        let mut headers = reqwest::header::HeaderMap::new();
        for value in values {
            headers.append(reqwest::header::LINK, value.parse().unwrap());
        }
        headers
    };
    assert_eq!(
        parse_alternate_links(&headers(&[]), &certificate).unwrap(),
        []
    );

    let one = headers(&[r#"<https://ca.example/acme/alt/1>; rel="alternate""#]);
    let parsed = parse_alternate_links(&one, &certificate).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].as_str(), "https://ca.example/acme/alt/1");
    let relative = headers(&[r#"</acme/alt/1>; rel="alternate""#]);
    assert_eq!(
        parse_alternate_links(&relative, &certificate)
            .unwrap()
            .first()
            .map(AcmeUrl::as_str),
        Some("https://ca.example/acme/alt/1")
    );

    // Unquoted relation values and multiple comma-separated entries stay valid.
    let mixed = headers(&[
        r#"<https://ca.example/acme/alt/2>; rel=alternate, <https://ca.example/acme/up/1>; rel="up", <https://ca.example/acme/alt/3>; title="chain"; rel="alternate""#,
        r#"<https://ca.example/acme/alt/4>; rel="altern\ate""#,
    ]);
    let parsed = parse_alternate_links(&mixed, &certificate).unwrap();
    assert_eq!(
        parsed.iter().map(AcmeUrl::as_str).collect::<Vec<_>>(),
        [
            "https://ca.example/acme/alt/2",
            "https://ca.example/acme/alt/3",
            "https://ca.example/acme/alt/4"
        ]
    );

    // Several header fields preserve server order.
    let ordered = headers(&[
        r#"<https://ca.example/acme/alt/5>; rel="alternate""#,
        r#"<https://ca.example/acme/alt/4>; rel="alternate""#,
    ]);
    let parsed = parse_alternate_links(&ordered, &certificate).unwrap();
    assert_eq!(parsed[0].as_str(), "https://ca.example/acme/alt/5");
    assert_eq!(parsed[1].as_str(), "https://ca.example/acme/alt/4");
}

#[test]
fn hostile_links_are_dropped_or_fail_closed() {
    let certificate = AcmeUrl::new("https://ca.example/acme/cert/1").unwrap();
    let headers = |values: &[&str]| {
        let mut headers = reqwest::header::HeaderMap::new();
        for value in values {
            headers.append(reqwest::header::LINK, value.parse().unwrap());
        }
        headers
    };
    // Non-HTTP, credential-carrying and malformed entries are dropped; relative
    // references are resolved against the certificate URL.
    let hostile = headers(&[
        r#"</acme/alt/1>; rel="alternate""#,
        r#"<ftp://ca.example/alt>; rel="alternate""#,
        r#"<https://user@ca.example/alt>; rel="alternate""#,
        r#"<https://[invalid>; rel="alternate""#,
        r#"<https://ca.example/acme/alt/ok>; rel="alternate""#,
    ]);
    let parsed = parse_alternate_links(&hostile, &certificate).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].as_str(), "https://ca.example/acme/alt/1");
    assert_eq!(parsed[1].as_str(), "https://ca.example/acme/alt/ok");

    // A self-referencing URL would loop the fetch.
    let looping = headers(&[r#"<https://ca.example/acme/cert/1>; rel="alternate""#]);
    assert_eq!(parse_alternate_links(&looping, &certificate).unwrap(), []);

    // Duplicates collapse instead of fetching twice.
    let duplicated = headers(&[
        r#"<https://ca.example/acme/alt/1>; rel="alternate""#,
        r#"<https://ca.example/acme/alt/1>; rel="alternate""#,
    ]);
    assert_eq!(
        parse_alternate_links(&duplicated, &certificate)
            .unwrap()
            .len(),
        1
    );

    // Beyond the defensive ceiling the whole response fails closed: a broken
    // CA must not silently pick a subset of its own advertisement.
    let ceiling: Vec<String> = (0..=8)
        .map(|index| format!(r#"<https://ca.example/acme/alt/{index}>; rel="alternate""#))
        .collect();
    let over = headers(&ceiling.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(parse_alternate_links(&over, &certificate).is_err());
    let within: Vec<String> = ceiling[..8].to_vec();
    assert_eq!(
        parse_alternate_links(
            &headers(&within.iter().map(String::as_str).collect::<Vec<_>>()),
            &certificate
        )
        .unwrap()
        .len(),
        8
    );
}

#[test]
fn non_string_header_values_are_ignored() {
    let certificate = AcmeUrl::new("https://ca.example/acme/cert/1").unwrap();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::LINK,
        reqwest::header::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
    );
    assert_eq!(parse_alternate_links(&headers, &certificate).unwrap(), []);
}

#[test]
fn selector_decisions_and_candidates_stay_plain_data() {
    // The trait is an object-safe product contract; exercise the decision values
    // that the service maps onto chains.
    struct PickSecond;
    impl ChainSelector for PickSecond {
        fn select(
            &self,
            _requested: Option<&ChainName>,
            candidates: &[ChainCandidate],
            _: &crate::solver::ExecutionContext,
        ) -> Result<ChainDecision, crate::issuance::IssueError> {
            assert_eq!(candidates.len(), 2);
            assert!(candidates[0].is_default);
            assert!(!candidates[1].is_default);
            Ok(ChainDecision::Selected {
                index: 1,
                remember: true,
            })
        }
    }
    let candidates = vec![
        ChainCandidate {
            is_default: true,
            identity: ChainIdentity {
                dn: "CN=R11".into(),
                common_name: Some("R11".into()),
                fingerprint_sha256: "01".into(),
            },
        },
        ChainCandidate {
            is_default: false,
            identity: ChainIdentity {
                dn: "CN=E6".into(),
                common_name: Some("E6".into()),
                fingerprint_sha256: "02".into(),
            },
        },
    ];
    let selector: Box<dyn ChainSelector> = Box::new(PickSecond);
    assert_eq!(
        selector
            .select(
                None,
                &candidates,
                &crate::solver::ExecutionContext {
                    cancellation: tokio_util::sync::CancellationToken::new(),
                    deadline: std::time::Instant::now()
                }
            )
            .unwrap(),
        ChainDecision::Selected {
            index: 1,
            remember: true,
        }
    );
    let identity = ChainIdentity {
        dn: "CN=R11".into(),
        common_name: Some("R11".into()),
        fingerprint_sha256: "01".into(),
    };
    let encoded = serde_json::to_string(&identity).unwrap();
    assert_eq!(
        serde_json::from_str::<ChainIdentity>(&encoded).unwrap(),
        identity
    );
}

#[test]
fn chain_names_decode_printable_and_bmp_subjects_and_keep_escaped_space() {
    use rcgen::DnValue;
    let pem = certificate_pem(|name| {
        name.push(
            DnType::OrganizationName,
            DnValue::BmpString("CA".try_into().unwrap()),
        );
        name.push(
            DnType::CommonName,
            DnValue::PrintableString("Root ".try_into().unwrap()),
        );
    });
    let identity = chain_identity(&pem).unwrap();
    assert_eq!(identity.dn, r"CN=Root\ ,O=CA");
    assert_eq!(identity.common_name.as_deref(), Some("Root "));
    assert!(identity.matches(&ChainName::new("root").unwrap()));
    let pem = certificate_pem(|name| name.push(DnType::CommonName, "Root "));
    let identity = chain_identity(&pem).unwrap();
    assert_eq!(identity.dn, r"CN=Root\ ");
    assert!(identity.matches(&ChainName::new(&identity.dn).unwrap()));
}

#[test]
fn link_grammar_preserves_targets_and_uses_only_the_first_rel() {
    let certificate = AcmeUrl::new("https://ca.example/cert").unwrap();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.append(reqwest::header::LINK, r#"<https://ca.example/up>; title="alternate"; rel=up, <https://ca.example/dup>; rel=up; rel=alternate, <https://ca.example/other>; rel=alternate; anchor="/different""#.parse().unwrap());
    headers.append(reqwest::header::LINK, r#"<https://ca.example/a,b;c>; title="a, b; \"quoted\""; ReL="describedby ALTERNATE", <https://ca.example/final>; rel=alternate"#.parse().unwrap());
    headers.append(
        reqwest::header::LINK,
        r#"<https://ca.example/unclosed>; rel="alternate"#.parse().unwrap(),
    );
    let targets = parse_alternate_links(&headers, &certificate).unwrap();
    assert_eq!(
        targets.iter().map(AcmeUrl::as_str).collect::<Vec<_>>(),
        ["https://ca.example/a,b;c", "https://ca.example/final"]
    );
}
