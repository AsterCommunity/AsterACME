//! System-DNS CAA observations (RFC 8659 §3). No issuance gate or DNS mutation.
use crate::{
    dns::empty_answer,
    resolver::{self, InitializationError},
};
use aster_acme_core::caa::{Observation, Property, Request, evaluate};
use async_trait::async_trait;
use hickory_resolver::proto::rr::{RData, RecordType};

pub mod order;

/// Optional runner adapter; all issuer/account/method inputs are explicit.
pub struct Caa<'a> {
    lookup: &'a dyn Lookup,
    request: Request<'a>,
}
impl<'a> Caa<'a> {
    /// Construct without DNS IO. Unknown CA extension support stays advisory.
    #[must_use]
    pub const fn new(lookup: &'a dyn Lookup, request: Request<'a>) -> Self {
        Self { lookup, request }
    }
}
#[async_trait]
impl aster_acme::precheck::Check for Caa<'_> {
    type Input = String;
    type Output = Report;
    async fn observe(
        &self,
        input: &String,
        _: &aster_acme::solver::ExecutionContext,
    ) -> Result<Report, aster_acme::precheck::Failure> {
        if self.request.issuers.is_empty() {
            return Err(aster_acme::precheck::Failure::Unavailable {
                reason: "CA directory does not advertise caaIdentities".into(),
            });
        }
        check(self.lookup, input, &self.request)
            .await
            .map_err(|_| aster_acme::precheck::Failure::LookupFailed)
    }
}

/// One effective `RRset` and the original name at which tree climbing stopped.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    /// Requested DNS name, including wildcard spelling for diagnostics.
    pub identifier: String,
    /// Search name where the first nonempty CAA response was returned.
    pub source: Option<String>,
    /// Effective records, retaining unknown values and critical flags.
    pub properties: Vec<Property>,
    /// Local result, never permission to issue or a reason to stop.
    pub observation: Observation,
}

/// Recursive lookup includes alias chasing. Errors must not become empty `RRset`s.
#[async_trait]
pub trait Lookup: Send + Sync {
    /// Query one absolute owner name, following DNS aliases per RFC 1034.
    /// # Errors
    /// Reports DNS failures, including alias loops and DNSSEC failures.
    async fn lookup(&self, name: &str) -> Result<Vec<Property>, LookupError>;
}
/// DNS observation failed; intentionally excludes response data and credentials.
#[derive(Debug, thiserror::Error)]
#[error("local CAA DNS lookup failed")]
pub struct LookupError;

/// Production adapter uses the platform's recursive DNS configuration.
pub struct SystemLookup(hickory_resolver::TokioResolver);
impl SystemLookup {
    /// Initialize a system resolver without contacting DNS.
    /// # Errors
    /// Preserves the failed initialization stage and underlying resolver cause.
    pub fn new() -> Result<Self, InitializationError> {
        Ok(Self(resolver::system()?))
    }
}
#[async_trait]
impl Lookup for SystemLookup {
    async fn lookup(&self, name: &str) -> Result<Vec<Property>, LookupError> {
        match self.0.lookup(name, RecordType::CAA).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::CAA(caa) => Some(Property {
                        critical: caa.issuer_critical,
                        tag: caa.tag.clone(),
                        value: caa.value.clone(),
                    }),
                    _ => None,
                })
                .collect()),
            Err(error) if empty_answer(&error) => Ok(Vec::new()),
            Err(_) => Err(LookupError),
        }
    }
}

/// Find the first nonempty `RRset`. Alias chasing belongs to each DNS query;
/// only the original identifier's parent chain is searched (RFC 8659 §3).
/// # Errors
/// Reports invalid identifiers and DNS failures; caller bounds time/cancellation.
pub async fn check(
    lookup: &dyn Lookup,
    identifier: &str,
    request: &Request<'_>,
) -> Result<Report, LookupError> {
    let name = identifier.strip_prefix("*.").unwrap_or(identifier);
    let normalized = aster_acme::identifier::DnsIdentifier::new(name)
        .map_err(|_| LookupError)?
        .value();
    let mut owner = normalized.as_str();
    let request = Request {
        wildcard: identifier.starts_with("*."),
        issuers: request.issuers,
        account_uri: request.account_uri,
        method: request.method,
    };
    loop {
        let properties = lookup.lookup(&format!("{owner}.")).await?;
        if !properties.is_empty() {
            return Ok(Report {
                identifier: identifier.into(),
                source: Some(owner.into()),
                observation: evaluate(&properties, &request),
                properties,
            });
        }
        match owner.split_once('.') {
            Some((_, parent)) => owner = parent,
            None => {
                return Ok(Report {
                    identifier: identifier.into(),
                    source: None,
                    properties,
                    observation: Observation::Unrestricted,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests;
