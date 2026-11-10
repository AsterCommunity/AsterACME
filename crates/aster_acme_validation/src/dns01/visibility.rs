//! Hickory-based DNS TXT visibility checks without publication or deletion.

use aster_acme::{
    issuance::{DnsReadiness, DnsRequirement, IssueError},
    solver::ExecutionContext,
};
use async_trait::async_trait;
use hickory_resolver::Resolver;

/// System recursive resolver visibility check. It publishes/deletes no DNS resources.
/// Successful local resolution is readiness evidence, never proof of CA authorization.
pub struct DnsVisibility;

#[async_trait]
impl DnsReadiness for DnsVisibility {
    async fn ready(
        &self,
        records: &[DnsRequirement],
        skip_dns_check: bool,
        execution: &ExecutionContext,
    ) -> Result<bool, IssueError> {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        if skip_dns_check {
            return Ok(true);
        }
        let resolver = Resolver::builder_tokio()
            .map_err(|_| IssueError::InvalidInput("cannot load system DNS configuration"))?
            .build()
            .map_err(|_| IssueError::InvalidInput("cannot initialize DNS resolver"))?;
        for requirement in records {
            let lookup = tokio::select! {
                biased;
                ()=execution.cancellation.cancelled()=>return Err(IssueError::Interrupted),
                result=tokio::time::timeout_at(tokio::time::Instant::from_std(execution.deadline),resolver.txt_lookup(format!("{}.",requirement.name)))=>result.map_err(|_|IssueError::Interrupted)?,
            };
            match lookup {
                Ok(lookup) => {
                    if !txt_value_present(lookup.answers(), &requirement.value) {
                        return Ok(false);
                    }
                }
                Err(error) if error.is_no_records_found() || error.is_nx_domain() => {
                    return Ok(false);
                }
                Err(_) => {
                    return Err(IssueError::InvalidInput(
                        "DNS TXT lookup failed; retry or explicitly bypass local visibility with --skip-dns-check",
                    ));
                }
            }
        }
        Ok(true)
    }
}

// A TXT RR can contain several character strings; concatenate within that RR only.
// Distinct RRs at one owner must not be concatenated or treated as replacements.
fn txt_value_present(records: &[hickory_resolver::proto::rr::Record], expected: &str) -> bool {
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
    use super::*;
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
    async fn force_skips_resolver_but_never_cancellation_or_deadline() {
        let execution = ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let records = [DnsRequirement {
            name: "_acme-challenge.example.invalid".into(),
            value: "not-published".into(),
        }];
        assert!(
            DnsVisibility
                .ready(&records, true, &execution)
                .await
                .unwrap()
        );
        execution.cancellation.cancel();
        assert!(matches!(
            DnsVisibility.ready(&records, true, &execution).await,
            Err(IssueError::Interrupted)
        ));
        let expired = ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now(),
        };
        assert!(matches!(
            DnsVisibility.ready(&records, true, &expired).await,
            Err(IssueError::Interrupted)
        ));
    }
}
