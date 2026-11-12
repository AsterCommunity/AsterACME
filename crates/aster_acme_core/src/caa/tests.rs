//! RFC rule matrix: additive records, wildcards, parameters and unknown extensions.
use crate::caa::*;
fn p(tag: &str, value: &str) -> Property {
    Property {
        critical: false,
        tag: tag.into(),
        value: value.as_bytes().into(),
    }
}
fn request(wildcard: bool) -> Request<'static> {
    Request {
        issuers: &[],
        account_uri: Some("https://ca.example/account/1"),
        method: "dns-01",
        wildcard,
    }
}
#[test]
fn issuer_alternatives_additive_authorizations_and_empty_values() {
    let issuers = vec!["ca.example".into(), "alias.example".into()];
    let r = Request {
        issuers: &issuers,
        ..request(false)
    };
    for (properties, expected) in [
        (vec![], Observation::Unrestricted),
        (
            vec![p("iodef", "mailto:ops@example.com")],
            Observation::Unrestricted,
        ),
        (vec![p("future", "opaque")], Observation::Unrestricted),
        (vec![p("issue", "ca.example")], Observation::Matches),
        (vec![p("issue", "ALIAS.EXAMPLE")], Observation::Matches),
        (vec![p("issue", ";")], Observation::NoMatch),
        (vec![p("issue", "")], Observation::NoMatch),
        (vec![p("issue", "%%%%%")], Observation::NoMatch),
        (vec![p("issue", "-ca.example")], Observation::NoMatch),
        (
            vec![p("issue", ";"), p("issue", "ca.example")],
            Observation::Matches,
        ),
        (vec![p("issue", "other.example")], Observation::NoMatch),
        (vec![p("ISSUE", " \tca.example\t ")], Observation::Matches),
    ] {
        assert_eq!(evaluate(&properties, &r), expected, "{properties:?}");
    }
    assert_eq!(
        evaluate(&[p("issue", "ca.example")], &request(false)),
        Observation::Unknown
    );
}
#[test]
fn wildcard_precedence_stops_at_the_effective_rrset() {
    let issuers = vec!["ca.example".into()];
    for wildcard in [false, true] {
        let r = Request {
            issuers: &issuers,
            ..request(wildcard)
        };
        assert_eq!(
            evaluate(&[p("issue", "ca.example")], &r),
            Observation::Matches
        );
        assert_eq!(
            evaluate(&[p("issuewild", ";")], &r),
            if wildcard {
                Observation::NoMatch
            } else {
                Observation::Unrestricted
            }
        );
        assert_eq!(
            evaluate(
                &[p("issue", "ca.example"), p("issuewild", "other.example")],
                &r
            ),
            if wildcard {
                Observation::NoMatch
            } else {
                Observation::Matches
            }
        );
        assert_eq!(
            evaluate(&[p("issue", ";"), p("issuewild", "ca.example")], &r),
            if wildcard {
                Observation::Matches
            } else {
                Observation::NoMatch
            }
        );
    }
}
#[test]
fn critical_properties_are_unknown_without_claiming_ca_capability() {
    let issuers = vec!["ca.example".into()];
    let r = Request {
        issuers: &issuers,
        ..request(false)
    };
    let unknown = Property {
        critical: true,
        ..p("future", "x")
    };
    assert_eq!(
        evaluate(&[p("issue", "ca.example"), unknown], &r),
        Observation::Unknown
    );
    assert_eq!(
        evaluate(
            &[Property {
                critical: true,
                ..p("issue", "ca.example")
            }],
            &r
        ),
        Observation::Matches
    );
    assert_eq!(
        evaluate(
            &[Property {
                value: vec![255],
                ..p("issue", "")
            }],
            &r
        ),
        Observation::NoMatch
    );
}
#[test]
fn rfc8657_parameters_apply_per_record_and_do_not_become_global_restrictions() {
    let issuers = vec!["ca.example".into()];
    let r = Request {
        issuers: &issuers,
        ..request(false)
    };
    for (value, expected) in [
        (
            "ca.example; accounturi=https://ca.example/account/1; validationmethods=http-01,dns-01",
            Observation::Matches,
        ),
        (
            "ca.example; accounturi=https://ca.example/account/2",
            Observation::NoMatch,
        ),
        (
            "ca.example; validationmethods=http-01",
            Observation::NoMatch,
        ),
        ("ca.example; validationmethods=", Observation::NoMatch),
        (
            "ca.example; validationmethods=dns-01; validationmethods=dns-01",
            Observation::NoMatch,
        ),
        (
            "ca.example; accounturi=https://ca.example/account/1; accounturi=https://ca.example/account/1",
            Observation::NoMatch,
        ),
        ("ca.example; future=opaque", Observation::Unknown),
        ("ca.example; malformed", Observation::NoMatch),
        (
            "ca.example; validationmethods=dns-01,",
            Observation::NoMatch,
        ),
    ] {
        assert_eq!(evaluate(&[p("issue", value)], &r), expected, "{value}");
    }
    assert_eq!(
        evaluate(
            &[
                p(
                    "issue",
                    "ca.example; accounturi=https://ca.example/account/2"
                ),
                p("issue", "ca.example")
            ],
            &r
        ),
        Observation::Matches
    );
    assert_eq!(
        evaluate(
            &[p(
                "issue",
                "ca.example; accounturi=https://ca.example/account/1"
            )],
            &Request {
                account_uri: None,
                ..r
            }
        ),
        Observation::Unknown
    );
}
