use crate::identifier::{DnsIdentifier, Identifier, IpIdentifier};
use crate::issuance::*;

mod failed;

#[test]
fn generated_management_names_keep_a_bounded_prefix_and_lowercase_random_suffix() {
    let long = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    for value in ["example.com", "*.example.com", long.as_str()] {
        let domain = Identifier::Dns(DnsIdentifier::new(value).unwrap());
        let name = CertificateName::generated(&domain).unwrap();
        let (prefix, suffix) = name.as_str().rsplit_once('-').unwrap();
        assert_eq!(suffix.len(), 8);
        assert!(
            suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let expected = if let Some(base) = value.strip_prefix("*.") {
            format!("wildcard-{base}")
        } else {
            value.to_owned()
        };
        assert!(expected.starts_with(prefix));
        assert!(name.as_str().len() <= 250);
        assert_eq!(domain.value(), value);
    }
}

#[test]
fn generated_names_turn_ip_primaries_into_portable_ip_prefixed_components() {
    for (input, expected_prefix) in [
        ("192.0.2.1", "ip-192.0.2.1"),
        ("2001:db8::1", "ip-2001-db8--1"),
        ("::1", "ip---1"),
    ] {
        let primary = Identifier::Ip(IpIdentifier::new(input).unwrap());
        let name = CertificateName::generated(&primary).unwrap();
        let (prefix, suffix) = name.as_str().rsplit_once('-').unwrap();
        assert_eq!(suffix.len(), 8);
        assert!(
            suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(prefix, expected_prefix, "slug for {input}");
        assert!(aster_acme_core::local_name::valid_component(prefix));
    }
    // Colons never reach the filesystem through the fallback prefix either.
    let primary = Identifier::Ip(IpIdentifier::new("::1").unwrap());
    let name = CertificateName::generated(&primary).unwrap();
    assert!(!name.as_str().contains(':'));
}

#[test]
fn protocol_method_validation_prevents_http_wildcards_before_material_or_network() {
    let mut request = IssueRequest {
        name: CertificateName::new("web").unwrap(),
        identifiers: vec![Identifier::Dns(
            DnsIdentifier::new("*.example.com").unwrap(),
        )],
        profile: None,
        key_algorithm: crate::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
        account_name: "default".into(),
        challenge: crate::challenge::ChallengeKind::Http01,
        solver_id: "webroot".into(),
        solver_config: serde_json::Value::Object(serde_json::Map::default()),
    };
    assert!(matches!(
        request.validate(),
        Err(IssueError::Challenge(
            crate::challenge::ChallengeError::WildcardMethod
        ))
    ));
    request.challenge = crate::challenge::ChallengeKind::Dns01;
    request.validate().unwrap();
    request.identifiers.push(request.identifiers[0].clone());
    assert!(request.validate().is_err());
    request.identifiers.clear();
    assert!(request.validate().is_err());
}

#[test]
fn dns_methods_reject_ip_identifiers_and_http_methods_accept_mixed_sans_before_any_network() {
    let mut request = IssueRequest {
        name: CertificateName::new("ip").unwrap(),
        identifiers: vec![
            Identifier::Ip(IpIdentifier::new("192.0.2.1").unwrap()),
            Identifier::Ip(IpIdentifier::new("2001:db8::1").unwrap()),
        ],
        profile: None,
        key_algorithm: crate::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
        account_name: "default".into(),
        challenge: crate::challenge::ChallengeKind::Dns01,
        solver_id: "manual_dns".into(),
        solver_config: serde_json::Value::Object(serde_json::Map::default()),
    };
    assert!(request.validate().is_err());
    request.challenge = crate::challenge::ChallengeKind::DnsPersist01;
    assert!(request.validate().is_err());
    request.challenge = crate::challenge::ChallengeKind::Http01;
    request.validate().unwrap();
    request.challenge = crate::challenge::ChallengeKind::TlsAlpn01;
    request.validate().unwrap();
    // Mixed DNS/IP SANs are valid for HTTP-capable methods, including TLS-ALPN.
    request.identifiers.insert(
        0,
        Identifier::Dns(DnsIdentifier::new("example.com").unwrap()),
    );
    request.challenge = crate::challenge::ChallengeKind::Http01;
    request.validate().unwrap();
    request.challenge = crate::challenge::ChallengeKind::TlsAlpn01;
    request.validate().unwrap();
    // Duplicate canonical addresses are rejected before any side effect.
    request.identifiers.push(Identifier::Ip(
        IpIdentifier::new("2001:db8:0:0:0:0:0:1").unwrap(),
    ));
    assert!(request.validate().is_err());
}
#[test]
fn only_complete_error_responses_become_durable_failure_evidence() {
    assert!(RequestFailure::from_error(&IssueError::Cancelled).is_none());
    assert!(RequestFailure::from_error(&IssueError::CreationUncertain).is_none());
    assert!(RequestFailure::from_error(&IssueError::InvalidInput("malformed response")).is_none());
}

#[cfg(test)]
mod name_boundaries {
    #[test]
    fn certificate_name_reserves_lock_suffix_space() {
        assert!(crate::issuance::CertificateName::new(&"a".repeat(250)).is_ok());
        for length in [251, 252, 253, 254, 255] {
            assert!(crate::issuance::CertificateName::new(&"a".repeat(length)).is_err());
        }
    }
}

#[test]
fn certificate_profile_names_are_bounded_and_become_resume_identity() {
    let definition = |profile: Option<&str>| IssueRequest {
        name: CertificateName::new("web").unwrap(),
        identifiers: vec![crate::identifier::Identifier::Dns(
            crate::identifier::DnsIdentifier::new("example.com").unwrap(),
        )],
        key_algorithm: crate::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
        account_name: "default".into(),
        challenge: crate::challenge::ChallengeKind::Http01,
        solver_id: "webroot".into(),
        solver_config: serde_json::Value::Object(serde_json::Map::default()),
        profile: profile.map(str::to_owned),
    };
    for invalid in [
        Some(""),
        Some(&"x".repeat(65)[..]),
        Some("short\nlived"),
        Some("short\u{0}lived"),
    ] {
        assert!(
            definition(invalid).validate().is_err(),
            "accepted {invalid:?}"
        );
    }
    definition(Some("shortlived")).validate().unwrap();
    definition(None).validate().unwrap();
    // The selection is part of the resume identity: a changed profile is a
    // different certificate definition and never silently reuses an order.
    let record_profile = |profile: Option<&str>| {
        let request = definition(profile);
        IssueRecord {
            challenge: request.challenge,
            solver_config: request.solver_config.clone(),
            is_in_use: false,
            deployment_count: None,
            renewal_of: None,
            solver_id: request.solver_id.clone(),
            operation_id: "a".repeat(43),
            name: request.name.clone(),
            created_at: time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            account_name: request.account_name.clone(),
            account_id: "stable".into(),
            directory: aster_acme_protocol::url::AcmeUrl::new("https://ca.example/directory")
                .unwrap(),
            account_url: aster_acme_protocol::url::AcmeUrl::new("https://ca.example/acct/1")
                .unwrap(),
            account_thumbprint: "A".repeat(43),
            key_algorithm: request.key_algorithm,
            profile: request.profile.clone(),
            identifiers: request.identifiers.clone(),
            phase: aster_acme_core::workflow::IssuancePhase::Authorizing,
            new_order_intent_saved: true,
            creation_failure: None,
            submitted_replaces: None,
            order_url: None,
            order: None,
            authorizations: Vec::new(),
            finalize_submitted: aster_acme_core::workflow::SubmissionState::NotSubmitted,
            finalize_rejection: None,
            next_poll_at: None,
            poll_wait_source: None,
            revocation: crate::revocation::RevocationRecord::default(),
            renewal: None,
            renewal_retry: None,
        }
    };
    let saved = record_profile(Some("shortlived"));
    let account = crate::account::AccountRecord {
        key_algorithm: crate::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
        user_agent: None,
        times: crate::account::AccountTimes::default(),
        account_id: "stable".into(),
        directory_url: aster_acme_protocol::url::AcmeUrl::new("https://ca.example/directory")
            .unwrap(),
        key_thumbprint: "A".repeat(43),
        account_url: Some(
            aster_acme_protocol::url::AcmeUrl::new("https://ca.example/acct/1").unwrap(),
        ),
        contacts: Vec::new(),
        server_contacts: None,
        last_status: Some(aster_acme_core::protocol::AccountStatus::Valid),
        deactivation: aster_acme_core::account::DeactivationState::NotRequested,
        key_rotation: None,
        accepted_terms_url: None,
        preferred_profile: None,
        auto_accept_terms_updates: false,
        state: aster_acme_core::account::AccountRecordState::Registered,
    };
    assert!(saved.matches_unfinished_request(
        &definition(Some("shortlived")),
        &account,
        time::OffsetDateTime::from_unix_timestamp(1_800_000_001).unwrap()
    ));
    assert!(!saved.matches_unfinished_request(
        &definition(None),
        &account,
        time::OffsetDateTime::from_unix_timestamp(1_800_000_001).unwrap()
    ));
}
