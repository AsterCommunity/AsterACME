//! DNS lookup port and bounded, label-aware CNAME routing.
use crate::ProviderExecution;
use async_trait::async_trait;
use std::collections::BTreeSet;
use thiserror::Error;

/// Maximum number of CNAME links in one publication route.
pub const MAX_CNAME_LINKS: usize = 8;

/// Resolver observation failure, preserving the initialization/query cause.
#[derive(Debug, Error)]
#[error("{stage}: {cause}")]
pub struct LookupError {
    /// Safe operation stage, without provider custom data.
    pub stage: &'static str,
    /// Original resolver cause.
    #[source]
    pub cause: Box<dyn std::error::Error + Send + Sync>,
}

/// DNS observations used by routing and propagation; no DNS writes.
#[async_trait]
pub trait DnsLookup: Send + Sync {
    /// One CNAME target at the queried owner, or a confirmed negative answer.
    async fn cname(&self, name: &str) -> Result<Option<String>, LookupError>;
    /// Logical TXT values, concatenating chunks within each RR only.
    async fn txt(&self, name: &str) -> Result<Vec<Vec<u8>>, LookupError>;
}

/// Normalize an ASCII DNS owner, accepting underscores in service labels.
/// # Errors
/// Rejects empty/root names, wildcards, non-ASCII and malformed/oversized labels.
pub fn absolute_name(name: &str) -> Result<String, RouteError> {
    let value = name.strip_suffix('.').unwrap_or(name);
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(RouteError::InvalidName);
    }
    Ok(format!("{}.", value.to_ascii_lowercase()))
}

/// Empty zone lists allow any valid owner; configured suffixes match whole DNS labels.
#[must_use]
pub fn allowed_zone(name: &str, zones: &[String]) -> bool {
    let Ok(name) = absolute_name(name) else {
        return false;
    };
    if zones.is_empty() {
        return true;
    }
    zones
        .iter()
        .filter_map(|zone| absolute_name(zone).ok())
        .any(|zone| name == zone || name.ends_with(&format!(".{zone}")))
}

/// Resolve once, then freeze the resulting route before provider mutation.
/// # Errors
/// Reports DNS failures, loop/depth boundaries, denied zones, and interruption.
pub async fn resolve(
    lookup: &dyn DnsLookup,
    owner: &str,
    zones: &[String],
    execution: &ProviderExecution,
) -> Result<Vec<String>, RouteError> {
    let mut chain = vec![absolute_name(owner)?];
    let mut seen = BTreeSet::from([chain[0].clone()]);
    loop {
        check(execution)?;
        let current = chain.last().ok_or(RouteError::InvalidName)?;
        let next = tokio::select! {
            biased;
            () = execution.cancellation.cancelled() => return Err(RouteError::Interrupted),
            result = tokio::time::timeout_at(execution.deadline.into(), lookup.cname(current)) =>
                result.map_err(|_| RouteError::Interrupted)??,
        };
        let Some(target) = next else {
            if !allowed_zone(current, zones) {
                return Err(RouteError::ZoneNotAllowed);
            }
            return Ok(chain);
        };
        if chain.len() > MAX_CNAME_LINKS {
            return Err(RouteError::CnameChainTooLong);
        }
        let target = absolute_name(&target)?;
        if !seen.insert(target.clone()) {
            return Err(RouteError::CnameLoop);
        }
        chain.push(target);
    }
}

/// Check a saved route without consulting DNS again.
/// # Errors
/// Rejects invalid names, loops, denied targets or mismatched endpoints.
pub fn validate_chain(
    owner: &str,
    target: &str,
    chain: &[String],
    zones: &[String],
) -> Result<(), RouteError> {
    if chain.is_empty() || chain.len() > MAX_CNAME_LINKS + 1 {
        return Err(RouteError::CnameChainTooLong);
    }
    let canonical = chain
        .iter()
        .map(|name| absolute_name(name))
        .collect::<Result<Vec<_>, _>>()?;
    let unique = canonical.iter().collect::<BTreeSet<_>>();
    if canonical.first() != Some(&absolute_name(owner)?)
        || canonical.last() != Some(&absolute_name(target)?)
    {
        return Err(RouteError::InvalidName);
    }
    if unique.len() != chain.len() {
        return Err(RouteError::CnameLoop);
    }
    if !allowed_zone(target, zones) {
        return Err(RouteError::ZoneNotAllowed);
    }
    Ok(())
}

pub(crate) fn check(execution: &ProviderExecution) -> Result<(), RouteError> {
    if execution.cancellation.is_cancelled() || std::time::Instant::now() >= execution.deadline {
        return Err(RouteError::Interrupted);
    }
    Ok(())
}

/// Safe DNS routing failure; no credential context is attached.
#[derive(Debug, Error)]
pub enum RouteError {
    /// Invalid DNS owner.
    #[error("invalid DNS challenge owner")]
    InvalidName,
    /// Resolver observation failed.
    #[error(transparent)]
    Lookup(#[from] LookupError),
    /// Cancellation or deadline.
    #[error("DNS route resolution interrupted")]
    Interrupted,
    /// Repeated CNAME owner.
    #[error("CNAME delegation contains a loop")]
    CnameLoop,
    /// CNAME depth exceeded.
    #[error("CNAME delegation exceeds eight links")]
    CnameChainTooLong,
    /// Unconfigured publication zone.
    #[error("publication target is outside the provider profile's allowed DNS zones")]
    ZoneNotAllowed,
}
