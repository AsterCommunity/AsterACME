//! Persistent, domain-bound TXT records for draft-ietf-acme-dns-persist-02.
//! No DNS mutation or ACME request occurs here. Callers must authenticate the
//! account before handing publication instructions to an external DNS operator.

use aster_acme_protocol::{directory::DirectoryMeta, order::DnsPersistParameters, url::AcmeUrl};
use serde::{Deserialize, Serialize};

use crate::{
    challenge::ChallengeError,
    identifier::{DnsIdentifier, DnsName},
};

pub(crate) mod account_uri;
pub(crate) mod issuer;

/// Public persistent publication. Keep it until the operator revokes DNS authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPersistRecord {
    /// TXT owner, including `_validation-persist`, with no trailing dot.
    pub name: DnsName,
    /// Logical RDATA, without presentation quotes or chunk boundaries.
    pub value: String,
}

impl DnsPersistRecord {
    /// Derive a draft-02 record without a challenge token. Prefer an unchanged
    /// record from the confirmed predecessor, including after account key rollover.
    /// `previous` must belong to the same account URL and managed definition.
    ///
    /// # Errors
    /// Rejects malformed challenge parameters, inconsistent issuer metadata,
    /// invalid hash prefixes/thumbprints, and oversized DNS owners or RDATA.
    pub fn derive(
        identifier: &DnsIdentifier,
        account_url: &AcmeUrl,
        jwk_thumbprint: &str,
        meta: &DirectoryMeta,
        parameters: &DnsPersistParameters,
        previous: &[Self],
    ) -> Result<Self, ChallengeError> {
        let issuer = issuer::select(meta, parameters)?;
        let prefix = account_uri::validate_prefix(meta)?;
        let name = DnsName::new(&format!(
            "_validation-persist.{}",
            identifier.name().as_str()
        ))?;
        for record in previous {
            if record.name == name
                && record.reusable(
                    &parameters.issuer_domain_names,
                    prefix,
                    identifier.is_wildcard(),
                )
            {
                return Ok(record.clone());
            }
        }
        let hashed_uri = account_uri::derive(identifier, account_url, jwk_thumbprint, prefix)?;
        let policy = if identifier.is_wildcard() {
            "; policy=wildcard"
        } else {
            ""
        };
        let value = format!("{issuer}; accounturi={hashed_uri}{policy}");
        if value.len() + value.len().div_ceil(255) > usize::from(u16::MAX) {
            return Err(invalid("TXT RDATA exceeds the DNS size limit"));
        }
        Ok(Self { name, value })
    }

    /// Construct pre-provisioning instructions from a conforming directory baseline.
    /// Account ownership must be verified with an authenticated POST-as-GET before
    /// delegating publication, per draft-02 section 4.5.
    ///
    /// # Errors
    /// Rejects missing/nonconforming directory issuers and invalid derivation inputs.
    pub fn provision(
        identifier: &DnsIdentifier,
        account_url: &AcmeUrl,
        jwk_thumbprint: &str,
        meta: &DirectoryMeta,
    ) -> Result<Self, ChallengeError> {
        let issuers = issuer::preprovisioning_issuers(meta)?;
        Self::derive(
            identifier,
            account_url,
            jwk_thumbprint,
            meta,
            &DnsPersistParameters {
                issuer_domain_names: issuers.to_vec(),
            },
            &[],
        )
    }

    /// Zone-file presentation: concatenate these quoted strings within one TXT RR.
    /// Each string contains at most 255 octets before escaping.
    #[must_use]
    pub fn presentation_value(&self) -> String {
        let mut chunks = Vec::new();
        let mut chunk = String::new();
        for character in self.value.chars() {
            if chunk.len() + character.len_utf8() > 255 {
                chunks.push(chunk);
                chunk = String::new();
            }
            chunk.push(character);
        }
        chunks.push(chunk);
        chunks
            .into_iter()
            .map(|chunk| format!("\"{}\"", chunk.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Scope identity is owned here, alongside the canonical TXT representation.
    pub(crate) fn same_scope(&self, other: &Self) -> bool {
        self.name == other.name
            && self.value.ends_with("; policy=wildcard")
                == other.value.ends_with("; policy=wildcard")
    }

    fn reusable(&self, issuers: &[String], prefix: &str, wildcard: bool) -> bool {
        let Some((issuer, value)) = self.value.split_once("; accounturi=") else {
            return false;
        };
        let (value, wildcard_policy) = value
            .strip_suffix("; policy=wildcard")
            .map_or((value, false), |value| (value, true));
        issuers.iter().any(|name| name == issuer)
            && (!wildcard || wildcard_policy)
            && account_uri::matches_prefix(value, prefix)
    }
}

fn invalid(reason: &'static str) -> ChallengeError {
    ChallengeError::InvalidDnsPersist(reason)
}

#[cfg(test)]
mod tests;
