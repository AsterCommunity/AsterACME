use crate::challenge::dns_persist::*;
use aster_acme_protocol::order::{ChallengeObject, WireChallengeKind};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;

const THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

fn meta() -> DirectoryMeta {
    serde_json::from_value(json!({
        "issuerDomainNames": ["authority.example"],
        "accountHashPrefix": "https://ca.example/account-hash/",
        "caaIdentities": ["AUTHORITY.EXAMPLE.", "extra.example"]
    }))
    .unwrap()
}

fn parameters() -> DnsPersistParameters {
    DnsPersistParameters {
        issuer_domain_names: vec!["authority.example".into(), "extra.example".into()],
    }
}

fn derive(
    domain: &str,
    meta: &DirectoryMeta,
    parameters: &DnsPersistParameters,
) -> Result<DnsPersistRecord, ChallengeError> {
    DnsPersistRecord::derive(
        &DnsIdentifier::new(domain).unwrap(),
        &AcmeUrl::new("https://ca.example/acct/123").unwrap(),
        THUMBPRINT,
        meta,
        parameters,
        &[],
    )
}

#[test]
fn draft02_hash_vector_uses_registered_sha256_and_no_token_or_cleartext_account() {
    let record = derive("EXAMPLE.COM.", &meta(), &parameters()).unwrap();
    assert_eq!(record.name.as_str(), "_validation-persist.example.com");
    assert_eq!(
        record.value,
        "authority.example; accounturi=https://ca.example/account-hash/sha-256/5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw"
    );
    assert!(!record.value.contains("acct/123"));
    assert_ne!(
        record.value,
        derive("other.example", &meta(), &parameters())
            .unwrap()
            .value
    );
    assert_ne!(
        record.value,
        DnsPersistRecord::derive(
            &DnsIdentifier::new("example.com").unwrap(),
            &AcmeUrl::new("https://ca.example/acct/%31%32%33").unwrap(),
            THUMBPRINT,
            &meta(),
            &parameters(),
            &[]
        )
        .unwrap()
        .value
    );
    assert_eq!(
        record,
        DnsPersistRecord::provision(
            &DnsIdentifier::new("example.com").unwrap(),
            &AcmeUrl::new("https://ca.example/acct/123").unwrap(),
            THUMBPRINT,
            &meta()
        )
        .unwrap()
    );
}

#[test]
fn wildcard_scope_is_explicit_and_hash_remains_bound_to_record_owner() {
    let base = derive("example.com", &meta(), &parameters()).unwrap();
    let wildcard = derive("*.example.com", &meta(), &parameters()).unwrap();
    assert_eq!(base.name, wildcard.name);
    assert_eq!(wildcard.value, format!("{}; policy=wildcard", base.value));
    assert_ne!(
        wildcard.value,
        derive("*.sub.example.com", &meta(), &parameters())
            .unwrap()
            .value
    );
}

#[test]
fn selected_issuer_array_is_strict_but_invalid_directory_baseline_is_unavailable() {
    for names in [
        vec![],
        vec!["authority.example".into(); 11],
        vec!["AUTHORITY.EXAMPLE".into()],
        vec!["authority.example.".into()],
        vec!["ü.example".into()],
        vec!["_issuer.example".into()],
        vec!["*.example".into()],
        vec!["bad..example".into()],
        vec![format!("{}.example", "a".repeat(64))],
        vec![format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63)
        )],
    ] {
        assert!(
            derive(
                "example.com",
                &meta(),
                &DnsPersistParameters {
                    issuer_domain_names: names.clone()
                }
            )
            .is_err(),
            "accepted {names:?}"
        );
    }
    for baseline in [
        json!(null),
        json!([]),
        json!(5),
        json!(["UPPER.EXAMPLE"]),
        json!([42]),
    ] {
        let mut raw = serde_json::to_value(meta()).unwrap();
        raw["issuerDomainNames"] = baseline;
        let directory: DirectoryMeta = serde_json::from_value(raw).unwrap();
        assert!(derive("example.com", &directory, &parameters()).is_ok());
        assert!(
            DnsPersistRecord::provision(
                &DnsIdentifier::new("example.com").unwrap(),
                &AcmeUrl::new("https://ca.example/acct/123").unwrap(),
                THUMBPRINT,
                &directory
            )
            .is_err()
        );
    }
}

#[test]
fn directory_and_challenge_sets_are_checked_without_requiring_caa_metadata() {
    let mut directory = meta();
    assert!(
        derive(
            "example.com",
            &directory,
            &DnsPersistParameters {
                issuer_domain_names: vec!["extra.example".into()]
            }
        )
        .is_err()
    );
    assert!(
        derive(
            "example.com",
            &directory,
            &DnsPersistParameters {
                issuer_domain_names: vec!["authority.example".into(), "outside.example".into()]
            }
        )
        .is_err()
    );
    for caa in [
        json!(null),
        json!(42),
        json!([]),
        json!([3]),
        json!(["bad..example"]),
    ] {
        let mut raw = serde_json::to_value(&directory).unwrap();
        raw["caaIdentities"] = caa;
        let metadata: DirectoryMeta = serde_json::from_value(raw).unwrap();
        assert!(derive("example.com", &metadata, &parameters()).is_ok());
    }
    directory.caa_identities.clear();
    assert!(derive("example.com", &directory, &parameters()).is_ok());
    directory.issuer_domain_names = None;
    assert!(derive("example.com", &directory, &parameters()).is_ok());
}

#[test]
fn legacy_spelling_is_retained_but_not_executed_as_draft02() {
    let challenge: ChallengeObject = serde_json::from_value(json!({
        "type":"dns-persist-01", "url":"https://ca.example/challenge", "status":"pending",
        "issuer-domain-names":["authority.example"], "future": {"opaque": true}
    }))
    .unwrap();
    assert_eq!(challenge.kind, WireChallengeKind::DnsPersist01);
    assert!(challenge.dns_persist_parameters().is_err());
    assert_eq!(challenge.parameters["future"], json!({"opaque":true}));
}

#[test]
fn missing_or_injectable_prefix_and_invalid_thumbprints_are_rejected() {
    for prefix in [
        None,
        Some("relative/"),
        Some("https://ca.example/%GG/"),
        Some("https://ca.example/%4"),
        Some("https://ca.example/;policy=wildcard"),
        Some("https://ca.example/\n"),
        Some("https://ca.example/ü/"),
        Some("https://ca.example/\"quoted/"),
        Some("https://ca.example/\\path/"),
    ] {
        let mut directory = meta();
        directory.account_hash_prefix = prefix.map(str::to_owned);
        assert!(derive("example.com", &directory, &parameters()).is_err());
    }
    for thumbprint in [
        "",
        "invalid",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ] {
        assert!(
            DnsPersistRecord::derive(
                &DnsIdentifier::new("example.com").unwrap(),
                &AcmeUrl::new("https://ca.example/acct/123").unwrap(),
                thumbprint,
                &meta(),
                &parameters(),
                &[]
            )
            .is_err()
        );
    }
}

#[test]
fn renewal_reuses_published_binding_across_rollover_and_issuer_reordering() {
    let previous = derive("*.example.com", &meta(), &parameters()).unwrap();
    let mut reordered = parameters();
    reordered.issuer_domain_names.reverse();
    let renewed = DnsPersistRecord::derive(
        &DnsIdentifier::new("*.example.com").unwrap(),
        &AcmeUrl::new("https://ca.example/acct/123").unwrap(),
        &URL_SAFE_NO_PAD.encode([9; 32]),
        &meta(),
        &reordered,
        std::slice::from_ref(&previous),
    )
    .unwrap();
    assert_eq!(renewed, previous);
    let bare = derive("example.com", &meta(), &parameters()).unwrap();
    let wildcard = DnsPersistRecord::derive(
        &DnsIdentifier::new("*.example.com").unwrap(),
        &AcmeUrl::new("https://ca.example/acct/123").unwrap(),
        THUMBPRINT,
        &meta(),
        &parameters(),
        &[bare],
    )
    .unwrap();
    assert_eq!(wildcard, previous);
    let mut changed = meta();
    changed.account_hash_prefix = Some("https://ca.example/new-hash/".into());
    let renewed = DnsPersistRecord::derive(
        &DnsIdentifier::new("*.example.com").unwrap(),
        &AcmeUrl::new("https://ca.example/acct/123").unwrap(),
        THUMBPRINT,
        &changed,
        &parameters(),
        &[previous],
    )
    .unwrap();
    assert!(renewed.value.contains("/new-hash/sha-256/"));
}

#[test]
fn long_txt_records_use_multiple_strings_and_respect_dns_size_limits() {
    let mut directory = meta();
    directory.account_hash_prefix = Some(format!("https://ca.example/{}/", "a".repeat(600)));
    let record = derive("example.com", &directory, &parameters()).unwrap();
    let presentation = record.presentation_value();
    let chunks = presentation
        .strip_prefix('"')
        .unwrap()
        .strip_suffix('"')
        .unwrap()
        .split("\" \"")
        .collect::<Vec<_>>();
    assert!(chunks.len() > 1);
    assert!(chunks.iter().all(|part| part.len() <= 255));
    assert_eq!(chunks.concat(), record.value);
    directory.account_hash_prefix = Some(format!("https://ca.example/{}/", "a".repeat(65535)));
    assert!(derive("example.com", &directory, &parameters()).is_err());
    let domain = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(50)
    );
    assert!(DnsIdentifier::new(&domain).is_ok());
    assert!(derive(&domain, &meta(), &parameters()).is_err());
}

#[test]
fn confirmed_snapshot_retains_wildcard_when_only_base_authorization_needs_refresh() {
    use crate::issuance::{IssueRecord, RenewalPredecessor, ValidationRequirement};
    let retained = |record| ValidationRequirement::DnsPersist01 { record };
    let base = derive("example.com", &meta(), &parameters()).unwrap();
    let wildcard = derive("*.example.com", &meta(), &parameters()).unwrap();
    let mut operation: IssueRecord = serde_json::from_value(json!({
        "key_algorithm":"ecdsa-p256", "challenge":"dns-persist-01", "solver_config":{}, "solver_id":"dns_persist",
        "operation_id":"a".repeat(43), "name":"web", "created_at":"2026-11-14T00:00:00Z",
        "account_name":"default", "account_id":"stable", "account_thumbprint":THUMBPRINT,
        "directory":"https://ca.example/directory", "account_url":"https://ca.example/acct/123",
        "identifiers":["example.com", "*.example.com"], "phase":"completed", "new_order_intent_saved":true,
        "authorizations":[], "finalize_submitted":"submitted"
    })).unwrap();
    operation.renewal_of = Some(RenewalPredecessor {
        operation_id: "previous".into(),
        certificate_id: None,
        retained_validation: vec![retained(base.clone()), retained(wildcard.clone())],
    });
    // A CA can skip challenges by returning valid authorization or a ready order.
    assert_eq!(
        operation.retained_validation_requirements(),
        vec![retained(base.clone()), retained(wildcard.clone())]
    );
    let mut changed = base.clone();
    changed.value = changed.value.replace("account-hash", "new-prefix");
    operation.authorizations = vec![serde_json::from_value(json!({
        "url":"https://ca.example/authz", "resource":{"identifier":{"type":"dns", "value":"example.com"},
        "status":"valid", "expires":"2099-01-01T00:00:00Z", "challenges":[]},
        "challenge_url":"https://ca.example/challenge", "validation_requirement":{"method":"dns-persist-01", "name":changed.name, "value":changed.value},
        "cleanup_pending":false, "acknowledgement":"submitted"
    })).unwrap()];
    assert_eq!(
        operation.retained_validation_requirements(),
        vec![retained(changed), retained(wildcard)]
    );
}

#[test]
fn issuer_count_name_and_prefixed_owner_accept_the_exact_limits_only() {
    let mut directory = meta();
    directory.caa_identities.clear();
    directory.issuer_domain_names = None;
    let ten = DnsPersistParameters {
        issuer_domain_names: (0..10).map(|index| format!("ca{index}.example")).collect(),
    };
    assert!(derive("example.com", &directory, &ten).is_ok());
    let label = "a".repeat(63);
    for (last, accepted) in [(61, true), (62, false)] {
        let parameters = DnsPersistParameters {
            issuer_domain_names: vec![format!("{label}.{label}.{label}.{}", "b".repeat(last))],
        };
        assert_eq!(
            derive("example.com", &directory, &parameters).is_ok(),
            accepted
        );
    }
    for (last, accepted) in [(41, true), (42, false)] {
        let domain = format!("{label}.{label}.{label}.{}", "b".repeat(last));
        assert_eq!(derive(&domain, &meta(), &parameters()).is_ok(), accepted);
    }
}

#[test]
fn txt_string_and_total_rdata_boundaries_are_measured_in_octets() {
    let mut directory = meta();
    directory.account_hash_prefix = Some("https://ca.example/".into());
    let overhead = derive("example.com", &directory, &parameters())
        .unwrap()
        .value
        .len();
    for (length, strings) in [(254, 1), (255, 1), (256, 2), (65_279, 256)] {
        directory.account_hash_prefix = Some(format!(
            "https://ca.example/{}",
            "a".repeat(length - overhead)
        ));
        let record = derive("example.com", &directory, &parameters()).unwrap();
        assert_eq!(record.value.len(), length);
        let presentation = record.presentation_value();
        let chunks = presentation
            .strip_prefix('"')
            .unwrap()
            .strip_suffix('"')
            .unwrap()
            .split("\" \"")
            .collect::<Vec<_>>();
        assert_eq!(chunks.len(), strings);
        assert!(chunks.iter().all(|part| part.len() <= 255));
        assert_eq!(chunks.concat(), record.value);
    }
    directory.account_hash_prefix = Some(format!(
        "https://ca.example/{}",
        "a".repeat(65_280 - overhead)
    ));
    assert!(derive("example.com", &directory, &parameters()).is_err());
}

#[test]
fn malformed_retained_uri_is_not_reused_as_published_material() {
    let valid = derive("example.com", &meta(), &parameters()).unwrap();
    for broken in [
        "authority.example; accounturi=wrong".into(),
        valid.value.replace("sha-256/", "sha-1/"),
        valid
            .value
            .replace("5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw", "bad"),
        valid.value.replace("authority.example;", "other.example;"),
    ] {
        let mut previous = valid.clone();
        previous.value = broken;
        assert_eq!(
            DnsPersistRecord::derive(
                &DnsIdentifier::new("example.com").unwrap(),
                &AcmeUrl::new("https://ca.example/acct/123").unwrap(),
                THUMBPRINT,
                &meta(),
                &parameters(),
                &[previous]
            )
            .unwrap(),
            valid
        );
    }
}
