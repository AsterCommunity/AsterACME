//! Method capability and response-identity contracts, independent of transport.
use crate::challenge::{ChallengeKind, PublicationAccountProof, PublicationLifetime};
use aster_acme_protocol::{directory::DirectoryMeta, order::ChallengeObject};
use serde_json::json;

fn methods() -> [ChallengeKind; 4] {
    [
        ChallengeKind::Dns01,
        ChallengeKind::DnsPersist01,
        ChallengeKind::Http01,
        ChallengeKind::TlsAlpn01,
    ]
}

fn challenge(kind: ChallengeKind) -> ChallengeObject {
    let mut value =
        json!({"type":kind,"url":"https://ca.example/challenge/%2f", "status":"pending"});
    match kind {
        ChallengeKind::DnsPersist01 => value["issuerDomainNames"] = json!(["ca.example"]),
        ChallengeKind::Dns01 | ChallengeKind::Http01 | ChallengeKind::TlsAlpn01 => {
            value["token"] = json!("long-enough-opaque-challenge-token");
        }
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn directory_admission_lifetime_and_account_proof_are_explicit_for_every_method() {
    let absent = DirectoryMeta::default();
    let present: DirectoryMeta =
        serde_json::from_value(json!({"accountHashPrefix":"https://ca.example/hash/"})).unwrap();
    for (kind, lifetime, proof, wildcard) in [
        (
            ChallengeKind::Dns01,
            PublicationLifetime::Temporary,
            PublicationAccountProof::NotRequired,
            true,
        ),
        (
            ChallengeKind::DnsPersist01,
            PublicationLifetime::Persistent,
            PublicationAccountProof::ActiveAccount,
            true,
        ),
        (
            ChallengeKind::Http01,
            PublicationLifetime::Temporary,
            PublicationAccountProof::NotRequired,
            false,
        ),
        (
            ChallengeKind::TlsAlpn01,
            PublicationLifetime::Temporary,
            PublicationAccountProof::NotRequired,
            false,
        ),
    ] {
        assert_eq!(kind.publication_lifetime(), lifetime);
        assert_eq!(kind.publication_account_proof(), proof);
        assert_eq!(kind.supports_wildcards(), wildcard);
        assert_eq!(
            kind.validate_directory(&absent).is_ok(),
            kind != ChallengeKind::DnsPersist01
        );
        assert!(kind.validate_directory(&present).is_ok());
    }
}

#[test]
fn response_identity_allows_status_and_unknown_extensions_but_never_retargets_material() {
    for kind in methods() {
        let expected = challenge(kind);
        let mut observed = expected.clone();
        observed.status = aster_acme_core::protocol::ChallengeStatus::Processing;
        observed
            .parameters
            .insert("future".into(), json!({"opaque":true}));
        assert!(kind.matches_response(&expected, &observed));
        observed.url =
            aster_acme_protocol::url::AcmeUrl::new("https://ca.example/challenge/%2F").unwrap();
        assert!(!kind.matches_response(&expected, &observed));
        for different in methods().into_iter().filter(|other| *other != kind) {
            assert!(!kind.matches_response(&expected, &challenge(different)));
        }
        let identity = match kind {
            ChallengeKind::DnsPersist01 => "issuerDomainNames",
            ChallengeKind::Dns01 | ChallengeKind::Http01 | ChallengeKind::TlsAlpn01 => "token",
        };
        let mut missing = expected.clone();
        missing.parameters.remove(identity);
        assert!(!kind.matches_response(&expected, &missing));
        let mut changed = expected.clone();
        changed.parameters.insert(identity.into(), json!("changed"));
        assert!(!kind.matches_response(&expected, &changed));
    }
}

#[test]
fn retained_snapshots_filter_temporary_wrong_method_and_duplicate_material() {
    use crate::issuance::{IssueRecord, RenewalPredecessor, ValidationRequirement};
    let persistent=ValidationRequirement::DnsPersist01 { record:crate::challenge::dns_persist::DnsPersistRecord {
        name:crate::identifier::DnsName::new("_validation-persist.example.com").unwrap(),
        value:"ca.example; accounturi=https://ca.example/hash/sha-256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    }};
    let temporary = ValidationRequirement::Http01 {
        url: "http://example.com/path".into(),
        path: "/path".into(),
        content: "token.thumb".into(),
    };
    let mut record:IssueRecord=serde_json::from_value(json!({
        "key_algorithm":"ecdsa-p256","challenge":"dns-persist-01","solver_config":{},"solver_id":"dns_persist","operation_id":"a".repeat(43),"name":"web",
        "created_at":"2026-11-14T00:00:00Z","account_name":"default","account_id":"stable","account_thumbprint":"key",
        "directory":"https://ca.example/directory","account_url":"https://ca.example/acct/123","identifiers":["example.com"],
        "phase":"completed","new_order_intent_saved":true,"authorizations":[],"finalize_submitted":"submitted"
    })).unwrap();
    record.renewal_of = Some(RenewalPredecessor {
        operation_id: "previous".into(),
        certificate_id: None,
        retained_validation: vec![persistent.clone(), temporary, persistent.clone()],
    });
    assert_eq!(record.retained_validation_requirements(), vec![persistent]);
    record.challenge = ChallengeKind::Http01;
    assert_eq!(
        record.retained_validation_requirements(),
        Vec::<ValidationRequirement>::new()
    );
    record.challenge = ChallengeKind::Dns01;
    assert_eq!(
        record.retained_validation_requirements(),
        Vec::<ValidationRequirement>::new()
    );
}

#[test]
fn persist_ack_issuers_are_validated_as_order_independent_sets() {
    let mut expected = challenge(ChallengeKind::DnsPersist01);
    expected.parameters.insert(
        "issuerDomainNames".into(),
        json!(["one.example", "two.example"]),
    );
    let mut observed = expected.clone();
    observed.parameters.insert(
        "issuerDomainNames".into(),
        json!(["two.example", "one.example"]),
    );
    assert!(ChallengeKind::DnsPersist01.matches_response(&expected, &observed));
    for values in [
        json!([]),
        json!(["One.example", "two.example"]),
        json!(["one.example.", "two.example"]),
        json!(["other.example", "one.example"]),
        json!([12, "one.example"]),
    ] {
        observed
            .parameters
            .insert("issuerDomainNames".into(), values);
        assert!(!ChallengeKind::DnsPersist01.matches_response(&expected, &observed));
    }
}
