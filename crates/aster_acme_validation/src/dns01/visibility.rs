//! Hickory-based DNS TXT visibility checks without publication or deletion.

use aster_acme::solver::ChallengeSolver;
use aster_acme::{
    issuance::{IssueError, ValidationRequirement},
    solver::ExecutionContext,
};
use async_trait::async_trait;
use hickory_resolver::Resolver;

/// System recursive resolver visibility check. It publishes/deletes no DNS resources.
/// Successful local resolution is readiness evidence, never proof of CA authorization.
pub struct DnsVisibility;

#[async_trait]
impl ChallengeSolver for DnsVisibility {
    fn kind(&self) -> aster_acme::challenge::ChallengeKind {
        aster_acme::challenge::ChallengeKind::Dns01
    }
    async fn ready(
        &self,
        records: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        let resolver = Resolver::builder_tokio()
            .map_err(|_| IssueError::InvalidInput("cannot load system DNS configuration"))?
            .build()
            .map_err(|_| IssueError::InvalidInput("cannot initialize DNS resolver"))?;
        for requirement in records {
            let ValidationRequirement::Dns01 { name, value } = requirement else {
                return Err(IssueError::InvalidInput(
                    "DNS visibility received another validation method",
                ));
            };
            let lookup = tokio::select! {
                biased;
                ()=execution.cancellation.cancelled()=>return Err(IssueError::Interrupted),
                result=tokio::time::timeout_at(tokio::time::Instant::from_std(execution.deadline),resolver.txt_lookup(format!("{name}.")))=>result.map_err(|_|IssueError::Interrupted)?,
            };
            if !observe_lookup(lookup, value)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

pub(crate) fn observe_lookup(
    lookup: Result<hickory_resolver::lookup::Lookup, hickory_resolver::net::NetError>,
    expected: &str,
) -> Result<bool, IssueError> {
    match lookup {
        Ok(lookup) => Ok(txt_value_present(lookup.answers(), expected)),
        Err(error) if crate::dns::empty_answer(&error) => Ok(false),
        Err(_) => Err(IssueError::InvalidInput("local DNS TXT lookup failed")),
    }
}

// A TXT RR can contain several character strings; concatenate within that RR only.
// Distinct RRs at one owner must not be concatenated or treated as replacements.
pub(crate) fn txt_value_present(
    records: &[hickory_resolver::proto::rr::Record],
    expected: &str,
) -> bool {
    records.iter().any(|record| match &record.data {
        hickory_resolver::proto::rr::RData::TXT(txt) => txt
            .txt_data
            .iter()
            .flat_map(|part| part.iter().copied())
            .eq(expected.bytes()),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use crate::dns01::visibility::*;
    use std::time::{Duration, Instant};
    use tokio_util::sync::CancellationToken;

    #[test]
    fn txt_chunks_join_within_one_record_and_multiple_values_coexist() {
        use hickory_resolver::proto::rr::{Name, RData, Record, rdata::TXT};
        let owner = Name::from_ascii("_acme-challenge.example.com.").unwrap();
        let records = [
            Record::from_rdata(
                owner.clone(),
                30,
                RData::TXT(TXT::new(vec!["first".into(), "-value".into()])),
            ),
            Record::from_rdata(owner, 30, RData::TXT(TXT::new(vec!["second-value".into()]))),
        ];
        assert!(txt_value_present(&records, "first-value"));
        assert!(txt_value_present(&records, "second-value"));
        assert!(!txt_value_present(&records, "first-valuesecond-value"));
        assert!(!txt_value_present(&records, "missing"));
        assert!(!txt_value_present(&[], "missing"));
    }

    #[tokio::test]
    async fn cancellation_and_deadline_prevent_resolver_work() {
        let cancelled = ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(1),
        };
        cancelled.cancellation.cancel();
        assert!(matches!(
            DnsVisibility.ready(&[], &cancelled).await,
            Err(IssueError::Interrupted)
        ));
        let expired = ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now(),
        };
        assert!(matches!(
            DnsVisibility.ready(&[], &expired).await,
            Err(IssueError::Interrupted)
        ));
    }
}
