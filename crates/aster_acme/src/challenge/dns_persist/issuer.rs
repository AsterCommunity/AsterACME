//! Issuer normalization, directory/challenge set relations and selection for draft-02.
use crate::{
    challenge::{ChallengeError, dns_persist::invalid},
    identifier::DnsIdentifier,
};
use aster_acme_protocol::{directory::DirectoryMeta, order::DnsPersistParameters};

pub(super) fn select<'a>(
    meta: &'a DirectoryMeta,
    parameters: &'a DnsPersistParameters,
) -> Result<&'a str, ChallengeError> {
    let issuers = &parameters.issuer_domain_names;
    if !valid_issuers(issuers) {
        return Err(invalid(
            "issuerDomainNames must contain 1-10 lowercase A-label names",
        ));
    }
    let baseline = meta
        .issuer_domain_names
        .as_ref()
        .filter(|names| valid_issuers(names));
    if baseline.is_some_and(|names| names.iter().any(|name| !issuers.contains(name))) {
        return Err(invalid(
            "challenge omitted a directory issuerDomainNames entry",
        ));
    }
    if let Some(caa) = normalized_caa(&meta.caa_identities)
        && issuers.iter().any(|name| !caa.contains(name))
    {
        return Err(invalid(
            "challenge issuerDomainNames is not a subset of caaIdentities",
        ));
    }
    Ok(baseline
        .and_then(|names| names.first())
        .unwrap_or(&issuers[0]))
}

pub(super) fn preprovisioning_issuers(meta: &DirectoryMeta) -> Result<&[String], ChallengeError> {
    meta.issuer_domain_names
        .as_deref()
        .filter(|names| valid_issuers(names))
        .ok_or_else(|| invalid("directory issuerDomainNames is unavailable for pre-provisioning"))
}

fn valid_issuers(names: &[String]) -> bool {
    (1..=10).contains(&names.len())
        && names.iter().all(|name| {
            DnsIdentifier::new(name).is_ok_and(|identifier| {
                !identifier.is_wildcard() && identifier.name().as_str() == name
            })
        })
}

fn normalized_caa(names: &[String]) -> Option<Vec<String>> {
    if names.is_empty() {
        return None;
    }
    names
        .iter()
        .map(|name| {
            let identifier = DnsIdentifier::new(name).ok()?;
            (!identifier.is_wildcard()).then(|| identifier.name().as_str().to_owned())
        })
        .collect()
}

/// Compare validated issuer sets; draft-02 section 7.6 makes order insignificant.
pub(crate) fn same_set(left: &[String], right: &[String]) -> bool {
    valid_issuers(left)
        && valid_issuers(right)
        && left.iter().collect::<std::collections::BTreeSet<_>>()
            == right.iter().collect::<std::collections::BTreeSet<_>>()
}
