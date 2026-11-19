//! Input, method selection, response derivation and solver contract boundary tests.
use aster_acme_protocol::order::{WireChallengeKind, WireIdentifier};

use base64::Engine as _;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::{challenge::*, identifier::*, solver::*};

const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const THUMBPRINT: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

#[test]
fn dns_names_normalize_without_trimming_invalid_whitespace() {
    for (input, expected) in [
        ("EXAMPLE.COM.", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        (
            "_acme-challenge.Example.COM.",
            "_acme-challenge.example.com",
        ),
        ("a", "a"),
    ] {
        let name = DnsName::new(input).unwrap();
        assert_eq!(name.as_str(), expected);
        let serialized = serde_json::to_string(&name).unwrap();
        assert_eq!(serde_json::from_str::<DnsName>(&serialized).unwrap(), name);
    }
    for invalid in [
        "",
        ".",
        "..",
        "a..b",
        "example.com..",
        "-a.example",
        "a-.example",
        "a/b",
        "a:b",
        "*.example",
        "a b",
        " example.com",
        "example.com\n",
        "a\0b",
    ] {
        assert!(DnsName::new(invalid).is_err(), "accepted {invalid:?}");
        assert!(serde_json::from_value::<DnsName>(json!(invalid)).is_err());
    }
}

#[test]
fn dns_length_boundaries_apply_after_ascii_normalization() {
    let label = "a".repeat(63);
    assert!(DnsName::new(&label).is_ok());
    assert!(DnsName::new(&"a".repeat(64)).is_err());
    let max = format!("{label}.{label}.{label}.{}", "b".repeat(61));
    assert_eq!(max.len(), 253);
    assert!(DnsName::new(&max).is_ok());
    assert!(DnsName::new(&format!("{max}.")).is_ok());
    assert!(DnsName::new(&format!("{max}b")).is_err());
    // Unicode labels may be short in characters but too long once encoded as A-labels.
    assert!(DnsName::new(&format!("{}.example", "é".repeat(64))).is_err());
}

#[test]
fn certificate_identifiers_keep_wildcard_semantics_and_reject_non_dns_inputs() {
    let dns = DnsIdentifier::new("*.BÜCHER.Example.").unwrap();
    assert!(dns.is_wildcard());
    assert_eq!(dns.name().as_str(), "xn--bcher-kva.example");
    assert_eq!(dns.value(), "*.xn--bcher-kva.example");
    assert_eq!(
        serde_json::from_value::<DnsIdentifier>(json!(dns.value())).unwrap(),
        dns
    );
    for invalid in [
        "*",
        "*.*.example.com",
        "foo.*.example.com",
        "_acme-challenge.example.com",
        "127.0.0.1",
        "::1",
        "[::1]",
        "*.127.0.0.1",
        "https://example.com",
    ] {
        assert!(DnsIdentifier::new(invalid).is_err(), "accepted {invalid}");
        assert!(serde_json::from_value::<DnsIdentifier>(json!(invalid)).is_err());
    }
}

#[test]
fn wildcard_length_includes_its_prefix() {
    let label = "a".repeat(63);
    let maximum = format!("{label}.{label}.{label}.{}", "b".repeat(59));
    assert_eq!(maximum.len(), 251);
    assert!(DnsIdentifier::new(&format!("*.{maximum}")).is_ok());
    assert!(DnsIdentifier::new(&format!("*.{maximum}b")).is_err());
    assert!(DnsIdentifier::new(&format!("{maximum}bb")).is_ok());
}

#[test]
fn wire_identifiers_preserve_unknown_types_and_handle_authorization_wildcards() {
    let unknown: WireIdentifier =
        serde_json::from_value(json!({"type":"future", "value":"opaque"})).unwrap();
    assert_eq!(
        serde_json::to_value(&unknown).unwrap(),
        json!({"type":"future", "value":"opaque"})
    );
    assert!(matches!(
        Identifier::try_from(unknown),
        Err(IdentifierError::UnsupportedType(_))
    ));
    for wildcard in [false, true] {
        let identifier = authorization_identifier(
            WireIdentifier {
                kind: "dns".into(),
                value: "Example.COM".into(),
                extensions: std::collections::BTreeMap::new(),
            },
            wildcard,
        )
        .unwrap();
        let wire = WireIdentifier::from(&identifier);
        assert_eq!(
            wire.value,
            if wildcard {
                "*.example.com"
            } else {
                "example.com"
            }
        );
    }
    for wildcard in [false, true] {
        assert_eq!(
            authorization_identifier(
                WireIdentifier {
                    kind: "dns".into(),
                    value: "*.example.com".into(),
                    extensions: std::collections::BTreeMap::new(),
                },
                wildcard
            ),
            Err(IdentifierError::WildcardAuthorizationValue)
        );
    }
    assert!(serde_json::from_value::<WireIdentifier>(json!({"type":"dns"})).is_err());
}

#[test]
fn known_and_unknown_challenge_methods_use_exact_wire_strings() {
    for (wire, kind) in [
        ("http-01", ChallengeKind::Http01),
        ("dns-01", ChallengeKind::Dns01),
        ("dns-persist-01", ChallengeKind::DnsPersist01),
        ("tls-alpn-01", ChallengeKind::TlsAlpn01),
    ] {
        let parsed: WireChallengeKind = serde_json::from_value(json!(wire)).unwrap();
        assert_eq!(crate::challenge::known_method(&parsed), Some(kind));
        assert_eq!(serde_json::to_value(parsed).unwrap(), json!(wire));
        assert_eq!(serde_json::to_value(kind).unwrap(), json!(wire));
        assert_eq!(
            serde_json::from_value::<ChallengeKind>(json!(wire)).unwrap(),
            kind
        );
    }
    for wire in ["dns-02", "DNS-01", "", "http01"] {
        let parsed: WireChallengeKind = serde_json::from_value(json!(wire)).unwrap();
        assert_eq!(crate::challenge::known_method(&parsed), None);
        assert_eq!(serde_json::to_value(parsed).unwrap(), json!(wire));
        assert!(serde_json::from_value::<ChallengeKind>(json!(wire)).is_err());
    }
}

#[test]
fn selection_exhaustively_intersects_policy_offer_capability_and_wildcard() {
    let methods = [
        ChallengeKind::Http01,
        ChallengeKind::Dns01,
        ChallengeKind::TlsAlpn01,
        ChallengeKind::DnsPersist01,
    ];
    let wires = [
        WireChallengeKind::Http01,
        WireChallengeKind::Dns01,
        WireChallengeKind::TlsAlpn01,
        WireChallengeKind::DnsPersist01,
    ];
    let dns_wildcard_cases = [false, true];
    let ip_cases = [false, true];
    for wildcard in dns_wildcard_cases {
        for with_ip in ip_cases {
            let dns = Identifier::Dns(
                DnsIdentifier::new(if wildcard {
                    "*.example.com"
                } else {
                    "example.com"
                })
                .unwrap(),
            );
            let ip = Identifier::Ip(IpIdentifier::new("2001:db8::1").unwrap());
            let identifier = if with_ip { &ip } else { &dns };
            for offer_mask in 0_u8..16 {
                let mut offered: Vec<_> = wires
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| offer_mask & (1 << i) != 0)
                    .map(|(_, wire)| wire.clone())
                    .collect();
                offered.push(WireChallengeKind::Unknown("future".into()));
                for support_mask in 0_u8..16 {
                    let supported: Vec<_> = methods
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| support_mask & (1 << i) != 0)
                        .map(|(_, method)| *method)
                        .collect();
                    for (i, method) in methods.iter().enumerate() {
                        let eligible = offer_mask & (1 << i) != 0
                            && support_mask & (1 << i) != 0
                            && method.validates_identifier(identifier)
                            && (!identifier.is_wildcard() || method.supports_wildcards());
                        let selected = ChallengePolicy::Require(*method)
                            .select(identifier, &offered, &supported);
                        assert_eq!(
                            selected,
                            if eligible {
                                Ok(*method)
                            } else {
                                Err(ChallengeError::NoCompatibleChallenge)
                            }
                        );
                    }
                    // Caller priority takes precedence over the order of the CA's offers.
                    let preference = [
                        ChallengeKind::TlsAlpn01,
                        ChallengeKind::Dns01,
                        ChallengeKind::Http01,
                        ChallengeKind::DnsPersist01,
                    ];
                    let expected = preference
                        .into_iter()
                        .find(|method| {
                            let i = methods.iter().position(|m| m == method).unwrap();
                            offer_mask & (1 << i) != 0
                                && support_mask & (1 << i) != 0
                                && method.validates_identifier(identifier)
                                && (!identifier.is_wildcard() || method.supports_wildcards())
                        })
                        .ok_or(ChallengeError::NoCompatibleChallenge);
                    assert_eq!(
                        ChallengePolicy::Prefer(
                            ChallengePreferences::new(preference.to_vec()).unwrap()
                        )
                        .select(identifier, &offered, &supported),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn preference_lists_are_nonempty_and_duplicate_free() {
    assert_eq!(
        ChallengePreferences::new(vec![]),
        Err(ChallengeError::InvalidPreferences)
    );
    assert_eq!(
        ChallengePreferences::new(vec![
            ChallengeKind::Dns01,
            ChallengeKind::Http01,
            ChallengeKind::Dns01
        ]),
        Err(ChallengeError::InvalidPreferences)
    );
    assert_eq!(
        ChallengePreferences::new(vec![ChallengeKind::Dns01])
            .unwrap()
            .methods(),
        &[ChallengeKind::Dns01]
    );
}

#[test]
fn token_and_thumbprint_validate_alphabet_padding_length_and_canonical_bits() {
    let token = ChallengeToken::new(TOKEN).unwrap();
    assert_eq!(token.as_str(), TOKEN);
    for invalid in [
        "",
        "AA",
        "AAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAA=",
        "../../etc/passwd",
        "AAAAAAAAAAAAAAAAAAAAA+",
        "AAAAAAAAAAAAAAAAAAAAA/",
        "AAAAAAAAAAAAAAAAAAAAAA\n",
    ] {
        assert_eq!(
            ChallengeToken::new(invalid),
            Err(ChallengeError::InvalidToken),
            "accepted {invalid:?}"
        );
    }
    // RFC tokens are opaque alphabet-constrained strings, not encoded byte arrays.
    for valid in [
        "AAAAAAAAAAAAAAAAAAAAAB",
        "aaaaaaaaaaaaaaaaaaaaaaa",
        "______________________",
        "----------------------",
    ] {
        assert_eq!(ChallengeToken::new(valid).unwrap().as_str(), valid);
    }
    assert!(ChallengeToken::new(&"a".repeat(21)).is_err());
    assert!(ChallengeToken::new(&"a".repeat(22)).is_ok());
    let auth = KeyAuthorization::new(&token, THUMBPRINT).unwrap();
    assert_eq!(auth.as_str(), format!("{TOKEN}.{THUMBPRINT}"));
    for invalid in [
        "",
        TOKEN,
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF",
    ] {
        assert_eq!(
            KeyAuthorization::new(&token, invalid),
            Err(ChallengeError::InvalidThumbprint)
        );
    }
}

#[test]
fn materials_bind_the_account_and_token_to_the_correct_response() {
    use crate::challenge::{
        dns01::Dns01Record, http01::Http01Response, tls_alpn01::TlsAlpn01Response,
    };
    let token = ChallengeToken::new(TOKEN).unwrap();
    let dns = Identifier::Dns(DnsIdentifier::new("example.com").unwrap());
    let wildcard = Identifier::Dns(DnsIdentifier::new("*.example.com").unwrap());
    let dns_for_record = DnsIdentifier::new("example.com").unwrap();
    let record = Dns01Record::derive(&dns_for_record, &token, THUMBPRINT).unwrap();
    assert_eq!(
        ChallengeMaterial::Dns01(record.clone()).kind(),
        ChallengeKind::Dns01
    );
    assert_eq!(record.record_name.as_str(), "_acme-challenge.example.com");
    // Independently computed SHA-256/base64url fixture.
    assert_eq!(
        record.txt_value,
        "zkPLeQfwjDL3HGjmMfjWh4_NsuFxkEKquc65DVPQTuQ"
    );
    let wildcard_for_record = DnsIdentifier::new("*.example.com").unwrap();
    assert_eq!(
        record,
        Dns01Record::derive(&wildcard_for_record, &token, THUMBPRINT).unwrap()
    );
    let response = Http01Response::derive(&dns, &token, THUMBPRINT).unwrap();
    assert_eq!(
        ChallengeMaterial::Http01(response.clone()).kind(),
        ChallengeKind::Http01
    );
    assert_eq!(response.identifier, dns);
    assert_eq!(response.token, token);
    assert_eq!(
        response.key_authorization.as_str(),
        format!("{TOKEN}.{THUMBPRINT}")
    );
    let response = TlsAlpn01Response::derive(&dns, &token, THUMBPRINT).unwrap();
    assert_eq!(
        ChallengeMaterial::TlsAlpn01(response.clone()).kind(),
        ChallengeKind::TlsAlpn01
    );
    assert_eq!(response.identifier, dns);
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(response.authorization_digest),
        record.txt_value
    );
    assert_eq!(
        Http01Response::derive(&wildcard, &token, THUMBPRINT),
        Err(ChallengeError::WildcardMethod)
    );
    assert_eq!(
        TlsAlpn01Response::derive(&wildcard, &token, THUMBPRINT),
        Err(ChallengeError::WildcardMethod)
    );
    assert!(Dns01Record::derive(&dns_for_record, &token, "invalid").is_err());
    // RFC 8738: IP identifiers derive HTTP-01/TLS-ALPN-01 material but never DNS records.
    let ipv4 = Identifier::Ip(IpIdentifier::new("192.0.2.1").unwrap());
    let response = Http01Response::derive(&ipv4, &token, THUMBPRINT).unwrap();
    assert_eq!(response.host(), "192.0.2.1");
    let ipv6 = Identifier::Ip(IpIdentifier::new("2001:DB8::1").unwrap());
    let response = Http01Response::derive(&ipv6, &token, THUMBPRINT).unwrap();
    assert_eq!(response.identifier.value(), "2001:db8::1");
    assert_eq!(response.host(), "[2001:db8::1]");
    let response = TlsAlpn01Response::derive(&ipv4, &token, THUMBPRINT).unwrap();
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(response.authorization_digest),
        record.txt_value
    );
    assert_eq!(response.sni_name(), "1.2.0.192.in-addr.arpa");
}

#[test]
fn solver_context_distinguishes_cancellation_and_deadline() {
    let context = ExecutionContext {
        cancellation: CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(60),
    };
    assert!(context.check().is_ok());
    context.cancellation.cancel();
    assert!(matches!(context.check(), Err(SolverError::Cancelled)));
    let expired = ExecutionContext {
        cancellation: CancellationToken::new(),
        deadline: Instant::now(),
    };
    assert!(matches!(
        expired.check(),
        Err(SolverError::DeadlineExceeded)
    ));
}

#[test]
fn validation_requirements_roundtrip_without_a_parallel_unused_receipt_schema() {
    use crate::issuance::ValidationRequirement;
    let values = [
        ValidationRequirement::Dns01 {
            name: "_acme-challenge.example.com".into(),
            value: "digest".into(),
        },
        ValidationRequirement::Http01 {
            url: "http://example.com/.well-known/acme-challenge/token".into(),
            path: "/.well-known/acme-challenge/token".into(),
            content: "key.authorization".into(),
        },
        ValidationRequirement::TlsAlpn01 {
            identifier: "example.com".into(),
            digest: [1; 32],
        },
    ];
    for requirement in values {
        let json = serde_json::to_value(&requirement).unwrap();
        assert_eq!(
            serde_json::from_value::<ValidationRequirement>(json).unwrap(),
            requirement
        );
    }
    assert!(serde_json::from_value::<ValidationRequirement>(json!({"method":"unknown"})).is_err());
    assert!(
        serde_json::from_value::<ValidationRequirement>(
            json!({"method":"http-01","url":"http://example.com"})
        )
        .is_err()
    );
    accepts_solver(None);
}

fn accepts_solver(_solver: Option<&dyn ChallengeSolver>) {}

#[test]
fn url_host_ipv4_aliases_are_never_dns_certificate_identifiers() {
    for host in [
        "127.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "127.0.0.1",
        "*.127.1",
    ] {
        assert!(
            crate::identifier::DnsIdentifier::new(host).is_err(),
            "{host}"
        );
    }
    for host in ["127.example.com", "example.com", "*.example.com"] {
        assert!(crate::identifier::DnsIdentifier::new(host).is_ok());
    }
}

#[test]
fn ip_identifiers_canonicalize_and_compare_by_address_not_text() {
    for (input, canonical) in [
        ("192.0.2.1", "192.0.2.1"),
        ("2001:DB8::1", "2001:db8::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("2001:db8:0:0:0:0:0:1", "2001:db8::1"),
        ("::ffff:192.0.2.1", "::ffff:192.0.2.1"),
        ("::FFFF:192.0.2.128", "::ffff:192.0.2.128"),
        ("::1", "::1"),
        ("::", "::"),
    ] {
        let identifier = IpIdentifier::new(input).unwrap();
        assert_eq!(identifier.value(), canonical, "normalized {input}");
        // Different textual forms of one address are the same identifier.
        assert_eq!(identifier, IpIdentifier::new(canonical).unwrap());
        let serialized = serde_json::to_string(&identifier).unwrap();
        assert_eq!(
            serde_json::from_str::<IpIdentifier>(&serialized).unwrap(),
            identifier
        );
    }
    for invalid in [
        "",
        "example.com",
        "192.0.2.1:80",
        "[2001:db8::1]:443",
        "[2001:db8::1]",
        "fe80::1%eth0",
        "fe80::1%25eth0",
        "01.2.3.4",
        "1.2.3.4.5",
        "1.2.3",
        "256.0.2.1",
        "2001:db8::1::2",
        "2001:db8::g",
        " 192.0.2.1",
        "192.0.2.1 ",
        "192.0.2.1/24",
        "*.192.0.2.1",
        "2001:db8::1 ",
    ] {
        assert!(IpIdentifier::new(invalid).is_err(), "accepted {invalid:?}");
        assert!(serde_json::from_value::<IpIdentifier>(json!(invalid)).is_err());
    }
    // Canonical values are stable identifiers: reversed or aliased spellings
    // never create a second authorization for the same address.
    let set = [
        IpIdentifier::new("2001:db8:0:0:0:0:0:1").unwrap(),
        IpIdentifier::new("2001:db8::1").unwrap(),
    ];
    assert_eq!(set[0], set[1]);
    assert_eq!(
        set.iter().collect::<std::collections::HashSet<_>>().len(),
        1
    );
}

#[test]
fn reverse_names_follow_in_addr_and_ip6_arpa_nibble_order() {
    assert_eq!(
        IpIdentifier::new("192.0.2.1").unwrap().reverse_name(),
        "1.2.0.192.in-addr.arpa"
    );
    assert_eq!(
        IpIdentifier::new("127.0.0.1").unwrap().reverse_name(),
        "1.0.0.127.in-addr.arpa"
    );
    // RFC 8738 section 6 worked example for 2001:db8::1.
    assert_eq!(
        IpIdentifier::new("2001:db8::1").unwrap().reverse_name(),
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    );
    assert_eq!(
        IpIdentifier::new("::1").unwrap().reverse_name(),
        format!("1{}.ip6.arpa", ".0".repeat(31))
    );
    // The all-zero address still expands to 32 nibbles.
    let zero = IpIdentifier::new("::").unwrap().reverse_name();
    assert_eq!(zero.len(), 32 * 2 - 1 + ".ip6.arpa".len());
    assert!(zero.ends_with(".ip6.arpa"));
    assert_eq!(zero.split('.').count(), 34);
}

#[test]
fn parsed_identifiers_route_ip_literals_first_and_keep_dns_semantics() {
    // Exact IP literals become IP identifiers.
    for value in ["192.0.2.1", "::1", "2001:db8::1"] {
        assert!(
            matches!(Identifier::new(value), Ok(Identifier::Ip(_))),
            "expected IP for {value}"
        );
    }
    // Numeric-looking dotted quads that are not canonical IPv4 are rejected by
    // both channels: DnsIdentifier treats WHATWG-parseable hosts as addresses,
    // and the strict IP parser rejects the spelling. The CLI keeps the intent
    // split (-d versus --ip) so neither channel silently reinterprets it.
    assert!(Identifier::new("01.2.3.4").is_err());
    assert!(DnsIdentifier::new("01.2.3.4").is_err());
    // A five-label numeric name has no IPv4 form at all and stays a DNS name.
    let five_labels = Identifier::new("1.2.3.4.5").unwrap();
    assert!(matches!(five_labels, Identifier::Dns(_)));
    // DNS round trips keep their kind: identifiers that came from a DNS
    // identifier value never re-parse as IP.
    let dns = DnsIdentifier::new("example.com").unwrap();
    assert_eq!(
        Identifier::try_from(Identifier::Dns(dns).value()).unwrap(),
        Identifier::Dns(DnsIdentifier::new("example.com").unwrap())
    );
    // Values that are neither kind report the DNS error.
    assert!(Identifier::new("not a name").is_err());
    // Wire identifiers keep exact kind strings.
    let wire = WireIdentifier::from(&Identifier::Ip(IpIdentifier::new("2001:db8::1").unwrap()));
    assert_eq!(wire.kind, "ip");
    assert_eq!(wire.value, "2001:db8::1");
    let parsed = Identifier::try_from(wire).unwrap();
    assert_eq!(parsed.value(), "2001:db8::1");
    let wire = WireIdentifier::from(&Identifier::Dns(
        DnsIdentifier::new("Example.COM.").unwrap(),
    ));
    assert_eq!(wire.kind, "dns");
    assert_eq!(wire.value, "example.com");
}

#[test]
fn ip_authorizations_reject_wildcard_flags_and_dns_keep_base_semantics() {
    assert_eq!(
        authorization_identifier(
            WireIdentifier {
                kind: "ip".into(),
                value: "192.0.2.1".into(),
                extensions: std::collections::BTreeMap::new(),
            },
            true,
        ),
        Err(IdentifierError::WildcardIpAuthorization)
    );
    assert_eq!(
        authorization_identifier(
            WireIdentifier {
                kind: "ip".into(),
                value: "2001:db8::1".into(),
                extensions: std::collections::BTreeMap::new(),
            },
            false,
        )
        .unwrap()
        .value(),
        "2001:db8::1"
    );
    // Non-canonical wire values are accepted by parsed address, not text.
    assert_eq!(
        authorization_identifier(
            WireIdentifier {
                kind: "ip".into(),
                value: "2001:0db8:0000::1".into(),
                extensions: std::collections::BTreeMap::new(),
            },
            false,
        )
        .unwrap()
        .value(),
        "2001:db8::1"
    );
    // Zone IDs and ports never reach an authorization identifier.
    for value in ["fe80::1%eth0", "192.0.2.1:80", "[2001:db8::1]"] {
        assert!(
            authorization_identifier(
                WireIdentifier {
                    kind: "ip".into(),
                    value: value.into(),
                    extensions: std::collections::BTreeMap::new(),
                },
                false,
            )
            .is_err(),
            "accepted {value:?}"
        );
    }
}
