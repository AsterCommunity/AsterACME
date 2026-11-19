use crate::identifier::DnsIdentifier;
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
        let domain = DnsIdentifier::new(value).unwrap();
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
fn protocol_method_validation_prevents_http_wildcards_before_material_or_network() {
    let mut request = IssueRequest {
        name: CertificateName::new("web").unwrap(),
        identifiers: vec![DnsIdentifier::new("*.example.com").unwrap()],
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
