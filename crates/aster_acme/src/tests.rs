//! Input, method selection, response derivation and solver contract boundary tests.

use base64::Engine as _;
use serde_json::json;
use std::{
    num::NonZeroU32,
    time::{Duration, Instant},
};
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
                    value: "*.example.com".into()
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
        ("tls-alpn-01", ChallengeKind::TlsAlpn01),
    ] {
        let parsed: WireChallengeKind = serde_json::from_value(json!(wire)).unwrap();
        assert_eq!(parsed.known(), Some(kind));
        assert_eq!(serde_json::to_value(parsed).unwrap(), json!(wire));
        assert_eq!(serde_json::to_value(kind).unwrap(), json!(wire));
        assert_eq!(
            serde_json::from_value::<ChallengeKind>(json!(wire)).unwrap(),
            kind
        );
    }
    for wire in ["dns-02", "DNS-01", "", "http01"] {
        let parsed: WireChallengeKind = serde_json::from_value(json!(wire)).unwrap();
        assert_eq!(parsed.known(), None);
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
    ];
    let wires = [
        WireChallengeKind::Http01,
        WireChallengeKind::Dns01,
        WireChallengeKind::TlsAlpn01,
    ];
    for wildcard in [false, true] {
        let dns = DnsIdentifier::new(if wildcard {
            "*.example.com"
        } else {
            "example.com"
        })
        .unwrap();
        for offer_mask in 0_u8..8 {
            let mut offered: Vec<_> = wires
                .iter()
                .enumerate()
                .filter(|(i, _)| offer_mask & (1 << i) != 0)
                .map(|(_, wire)| wire.clone())
                .collect();
            offered.push(WireChallengeKind::Unknown("future".into()));
            for support_mask in 0_u8..8 {
                let supported: Vec<_> = methods
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| support_mask & (1 << i) != 0)
                    .map(|(_, method)| *method)
                    .collect();
                for (i, method) in methods.iter().enumerate() {
                    let eligible = offer_mask & (1 << i) != 0
                        && support_mask & (1 << i) != 0
                        && (!wildcard || *method == ChallengeKind::Dns01);
                    let selected =
                        ChallengePolicy::Require(*method).select(&dns, &offered, &supported);
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
                ];
                let expected = preference
                    .into_iter()
                    .find(|method| {
                        let i = methods.iter().position(|m| m == method).unwrap();
                        offer_mask & (1 << i) != 0
                            && support_mask & (1 << i) != 0
                            && (!wildcard || *method == ChallengeKind::Dns01)
                    })
                    .ok_or(ChallengeError::NoCompatibleChallenge);
                assert_eq!(
                    ChallengePolicy::Prefer(
                        ChallengePreferences::new(preference.to_vec()).unwrap()
                    )
                    .select(&dns, &offered, &supported),
                    expected
                );
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
    let token = ChallengeToken::new(TOKEN).unwrap();
    let dns = DnsIdentifier::new("example.com").unwrap();
    let wildcard = DnsIdentifier::new("*.example.com").unwrap();
    let material =
        ChallengeMaterial::derive(ChallengeKind::Dns01, &dns, &token, THUMBPRINT).unwrap();
    assert_eq!(material.kind(), ChallengeKind::Dns01);
    let ChallengeMaterial::Dns01 {
        record_name,
        txt_value,
    } = &material
    else {
        panic!("wrong material")
    };
    assert_eq!(record_name.as_str(), "_acme-challenge.example.com");
    // Independently computed SHA-256/base64url fixture, not generated by code under test.
    assert_eq!(txt_value, "zkPLeQfwjDL3HGjmMfjWh4_NsuFxkEKquc65DVPQTuQ");
    assert_eq!(
        material,
        ChallengeMaterial::derive(ChallengeKind::Dns01, &wildcard, &token, THUMBPRINT).unwrap()
    );
    let http = ChallengeMaterial::derive(ChallengeKind::Http01, &dns, &token, THUMBPRINT).unwrap();
    let ChallengeMaterial::Http01 {
        identifier,
        token: published_token,
        key_authorization,
    } = http
    else {
        panic!("wrong material")
    };
    assert_eq!(identifier, dns);
    assert_eq!(published_token, token);
    assert_eq!(key_authorization.as_str(), format!("{TOKEN}.{THUMBPRINT}"));
    let tls =
        ChallengeMaterial::derive(ChallengeKind::TlsAlpn01, &dns, &token, THUMBPRINT).unwrap();
    let ChallengeMaterial::TlsAlpn01 {
        identifier,
        authorization_digest,
    } = tls
    else {
        panic!("wrong material")
    };
    assert_eq!(identifier, dns);
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(authorization_digest),
        *txt_value
    );
    for method in [ChallengeKind::Http01, ChallengeKind::TlsAlpn01] {
        assert_eq!(
            ChallengeMaterial::derive(method, &wildcard, &token, THUMBPRINT),
            Err(ChallengeError::WildcardMethod)
        );
    }
    assert!(ChallengeMaterial::derive(ChallengeKind::Dns01, &dns, &token, "invalid").is_err());
}

#[test]
fn derived_txt_owner_must_fit_dns_name_limit() {
    let label = "a".repeat(63);
    let token = ChallengeToken::new(TOKEN).unwrap();
    // Prefix adds 16 bytes: a 237-byte base fits, a 238-byte base does not.
    for (last_len, accepted) in [(45, true), (46, false)] {
        let base = format!("{label}.{label}.{label}.{}", "b".repeat(last_len));
        let dns = DnsIdentifier::new(&base).unwrap();
        assert_eq!(
            ChallengeMaterial::derive(ChallengeKind::Dns01, &dns, &token, THUMBPRINT).is_ok(),
            accepted
        );
    }
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
fn receipts_preserve_recovery_information_but_redact_debug_output() {
    let receipt = PreparedChallenge {
        kind: ChallengeKind::Dns01,
        solver_id: "provider-v1".into(),
        config_ref: "config-ref".into(),
        schema_version: NonZeroU32::new(1).unwrap(),
        operation_id: "operation-1".into(),
        preparation_id: "prepare-1".into(),
        ownership: ResourceOwnership::Created,
        state: json!({"record_id":"private-record-id", "zone":"private-zone"}),
    };
    let json = serde_json::to_value(&receipt).unwrap();
    let decoded: PreparedChallenge = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), json);
    let debug = format!("{receipt:?}");
    for private in [
        "private-record-id",
        "private-zone",
        "config-ref",
        "operation-1",
        "prepare-1",
    ] {
        assert!(!debug.contains(private));
    }
    let mut invalid = json;
    invalid["schema_version"] = json!(0);
    assert!(serde_json::from_value::<PreparedChallenge>(invalid).is_err());
    // Compile-time guarantee: the public async interface supports injectable trait objects.
    accepts_solver(None);
}

fn accepts_solver(_solver: Option<&dyn ChallengeSolver>) {}
