//! Pure authorization selection and material preparation; no transport or publication.
use crate::{
    challenge::{
        ChallengeKind, ChallengeMaterial, ChallengeToken, PublicationLifetime,
        dns_persist::DnsPersistRecord, dns01::Dns01Record, http01::Http01Response,
        tls_alpn01::TlsAlpn01Response,
    },
    identifier::{Identifier, authorization_identifier},
    issuance::{IssueError, IssueRecord, ValidationRequirement},
};
use aster_acme_core::{
    machine::{AuthorizationAction, authorization_action},
    protocol::ChallengeStatus,
    workflow::SubmissionState,
};
use aster_acme_protocol::{directory::DirectoryMeta, order::ChallengeObject, url::AcmeUrl};

pub(super) fn prepare(
    record: &mut IssueRecord,
    meta: &DirectoryMeta,
    now: time::OffsetDateTime,
) -> Result<Vec<ValidationRequirement>, IssueError> {
    let materials = AuthorizationMaterials {
        method: record.challenge,
        directory: meta,
        account_url: &record.account_url,
        account_thumbprint: &record.account_thumbprint,
        retained: record
            .renewal_of
            .as_ref()
            .map_or(&[][..], |previous| previous.retained_validation.as_slice()),
    };
    let mut outstanding = Vec::new();
    for auth in &mut record.authorizations {
        if auth.resource.expires.is_some_and(|expires| expires <= now) {
            return Err(IssueError::Expired);
        }
        match authorization_action(&auth.resource.status)? {
            AuthorizationAction::AlreadyValid => {}
            AuthorizationAction::ResolveChallenge => {
                let challenge = match &auth.challenge_url {
                    Some(url) => auth
                        .resource
                        .challenges
                        .iter()
                        .find(|challenge| challenge.url == *url),
                    None => auth.resource.challenges.iter().find(|challenge| {
                        crate::challenge::known_method(&challenge.kind) == Some(record.challenge)
                    }),
                }
                .ok_or(IssueError::InvalidInput(
                    "CA did not offer the selected challenge method",
                ))?;
                if crate::challenge::known_method(&challenge.kind) != Some(record.challenge) {
                    return Err(IssueError::InvalidInput("saved challenge method changed"));
                }
                let Identifier::Dns(identifier) = authorization_identifier(
                    auth.resource.identifier.clone(),
                    auth.resource.wildcard,
                )?;
                let requirement = materials.derive(
                    &identifier,
                    challenge,
                    auth.validation_requirement.as_ref(),
                )?;
                if auth
                    .validation_requirement
                    .as_ref()
                    .is_some_and(|previous| previous != &requirement)
                {
                    return Err(IssueError::InvalidInput("saved challenge material changed"));
                }
                auth.challenge_url = Some(challenge.url.clone());
                auth.validation_requirement = Some(requirement.clone());
                auth.cleanup_pending =
                    requirement.kind().publication_lifetime() == PublicationLifetime::Temporary;
                match &challenge.status {
                    ChallengeStatus::Pending => {
                        if matches!(auth.acknowledgement, SubmissionState::NotSubmitted) {
                            outstanding.push(requirement);
                        }
                    }
                    ChallengeStatus::Processing | ChallengeStatus::Valid => {}
                    ChallengeStatus::Invalid => {
                        return Err(IssueError::AuthorizationFailed {
                            status: auth.resource.status.clone(),
                            problem: challenge.error.clone().map(Box::new),
                        });
                    }
                    ChallengeStatus::Unknown(_) => {
                        return Err(IssueError::InvalidInput("unsupported challenge state"));
                    }
                }
            }
        }
    }

    Ok(outstanding)
}

/// Immutable protocol inputs shared by every authorization in this order.
struct AuthorizationMaterials<'a> {
    method: ChallengeKind,
    directory: &'a DirectoryMeta,
    account_url: &'a AcmeUrl,
    account_thumbprint: &'a str,
    retained: &'a [ValidationRequirement],
}

impl AuthorizationMaterials<'_> {
    fn derive(
        &self,
        identifier: &crate::identifier::DnsIdentifier,
        challenge: &ChallengeObject,
        saved: Option<&ValidationRequirement>,
    ) -> Result<ValidationRequirement, IssueError> {
        let material = match self.method {
            ChallengeKind::DnsPersist01 => {
                let parameters = challenge.dns_persist_parameters().map_err(|_| {
                    IssueError::InvalidInput(
                        "selected dns-persist-01 omitted draft-02 issuerDomainNames",
                    )
                })?;
                ChallengeMaterial::DnsPersist01(DnsPersistRecord::derive(
                    identifier,
                    self.account_url,
                    self.account_thumbprint,
                    self.directory,
                    &parameters,
                    &saved
                        .into_iter()
                        .chain(self.retained.iter())
                        .filter_map(|requirement| match requirement {
                            ValidationRequirement::DnsPersist01 { record } => Some(record.clone()),
                            ValidationRequirement::Dns01 { .. }
                            | ValidationRequirement::Http01 { .. }
                            | ValidationRequirement::TlsAlpn01 { .. } => None,
                        })
                        .collect::<Vec<_>>(),
                )?)
            }
            ChallengeKind::Dns01 => ChallengeMaterial::Dns01(Dns01Record::derive(
                identifier,
                &token(challenge)?,
                self.account_thumbprint,
            )?),
            ChallengeKind::Http01 => ChallengeMaterial::Http01(Http01Response::derive(
                identifier,
                &token(challenge)?,
                self.account_thumbprint,
            )?),
            ChallengeKind::TlsAlpn01 => ChallengeMaterial::TlsAlpn01(TlsAlpn01Response::derive(
                identifier,
                &token(challenge)?,
                self.account_thumbprint,
            )?),
        };
        Ok(ValidationRequirement::from_material(material))
    }
}

fn token(challenge: &ChallengeObject) -> Result<ChallengeToken, IssueError> {
    let value = challenge
        .parameters
        .get("token")
        .and_then(serde_json::Value::as_str)
        .ok_or(IssueError::InvalidInput(
            "selected challenge omitted its required string token",
        ))?;
    Ok(ChallengeToken::new(value)?)
}

#[cfg(test)]
mod tests {
    use crate::{
        challenge::ChallengeKind,
        issuance::{IssueError, IssueRecord, authorization::prepare},
    };
    use aster_acme_protocol::directory::DirectoryMeta;
    use serde_json::json;

    fn record(method: ChallengeKind, expires: time::OffsetDateTime) -> IssueRecord {
        let mut challenge =
            json!({"type":method,"url":"https://ca.example/challenge","status":"pending"});
        match method {
            ChallengeKind::DnsPersist01 => challenge["issuerDomainNames"] = json!(["ca.example"]),
            ChallengeKind::Dns01 | ChallengeKind::Http01 | ChallengeKind::TlsAlpn01 => {
                challenge["token"] = json!("long-enough-opaque-challenge-token");
            }
        }
        serde_json::from_value(json!({
            "key_algorithm":"ecdsa-p256","challenge":method,"solver_config":{},"solver_id":"test","operation_id":"a".repeat(43),"name":"web",
            "created_at":"2026-11-14T00:00:00Z","account_name":"default","account_id":"stable","account_thumbprint":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "directory":"https://ca.example/directory","account_url":"https://ca.example/acct/123","identifiers":["example.com"],
            "phase":"authorizing","new_order_intent_saved":true,"finalize_submitted":"not_submitted",
            "authorizations":[{"url":"https://ca.example/auth","resource":{"identifier":{"type":"dns","value":"example.com"},
                "status":"pending","expires":expires.format(&time::format_description::well_known::Rfc3339).unwrap(),"challenges":[challenge]},
                "challenge_url":null,"validation_requirement":null,"cleanup_pending":false,"acknowledgement":"not_submitted"}]
        })).unwrap()
    }

    #[test]
    fn authorization_expiry_is_deterministic_at_the_exact_instant_for_every_method() {
        let now = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let directory: DirectoryMeta =
            serde_json::from_value(json!({"accountHashPrefix":"https://ca.example/hash/"}))
                .unwrap();
        for method in [
            ChallengeKind::Dns01,
            ChallengeKind::DnsPersist01,
            ChallengeKind::Http01,
            ChallengeKind::TlsAlpn01,
        ] {
            for delta in [-1, 0, 1] {
                let mut record = record(method, now + time::Duration::nanoseconds(delta));
                let result = prepare(&mut record, &directory, now);
                if delta <= 0 {
                    assert!(matches!(result, Err(IssueError::Expired)));
                    assert_eq!(record.authorizations[0].validation_requirement, None);
                } else {
                    assert_eq!(result.unwrap()[0].kind(), method);
                    assert_eq!(
                        record.authorizations[0].cleanup_pending,
                        method.publication_lifetime()
                            == crate::challenge::PublicationLifetime::Temporary
                    );
                }
            }
        }
    }
}
