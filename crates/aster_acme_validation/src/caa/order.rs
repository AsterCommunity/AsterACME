//! CAA adapter for the composed workflow; no library-to-adapter dependency cycle.
use crate::caa::{Caa, Lookup, Report, SystemLookup};
use aster_acme::{
    issuance::IssueRecord,
    precheck::{Error, Failure, Observation, Report as StageReport, Runner, order::BeforeOrder},
    solver::ExecutionContext,
};
use aster_acme_core::caa::Request;
use aster_acme_protocol::directory::Directory;
use async_trait::async_trait;

/// Optional CAA stage. System DNS is initialized only when the stage is run.
#[derive(Default)]
pub struct OrderCaa<'a> {
    lookup: Option<&'a dyn Lookup>,
    runner: Runner,
}
impl<'a> OrderCaa<'a> {
    /// Inject application DNS and a chosen budget without triggering IO.
    #[must_use]
    pub const fn new(lookup: &'a dyn Lookup, runner: Runner) -> Self {
        Self {
            lookup: Some(lookup),
            runner,
        }
    }
}
#[async_trait]
impl BeforeOrder for OrderCaa<'_> {
    type Output = Report;
    async fn check(
        &self,
        directory: &Directory,
        record: &IssueRecord,
        execution: &ExecutionContext,
    ) -> Result<StageReport<Report>, Error> {
        execution.check().map_err(|_| Error::Interrupted)?;
        // RFC 8659 CAA applies to DNS names only. IP identifiers keep their
        // input index with an explicit unsupported observation so reports stay
        // aligned with the requested identifiers.
        let dns_slots = record
            .identifiers
            .iter()
            .map(aster_acme::identifier::Identifier::as_dns)
            .collect::<Vec<_>>();
        let names = dns_slots
            .iter()
            .flatten()
            .map(|dns| dns.value())
            .collect::<Vec<_>>();
        if directory.meta.caa_identities.is_empty() {
            return Ok(unavailable(
                dns_slots.len(),
                "CA directory does not advertise caaIdentities",
            ));
        }
        let system;
        let lookup = if let Some(lookup) = self.lookup {
            lookup
        } else {
            system = match SystemLookup::new() {
                Ok(lookup) => lookup,
                Err(error) => return Ok(unavailable(dns_slots.len(), &error.to_string())),
            };
            &system
        };
        let method = record.challenge.name().to_ascii_lowercase();
        let checker = Caa::new(
            lookup,
            Request {
                issuers: &directory.meta.caa_identities,
                account_uri: Some(record.account_url.as_str()),
                method: &method,
                wildcard: false,
            },
        );
        let dns_report = self.runner.run(&checker, &names, execution).await?;
        let mut dns_observations = dns_report.observations.into_iter();
        let mut next = dns_observations.next();
        let mut observations = Vec::with_capacity(dns_slots.len());
        for (index, slot) in dns_slots.iter().enumerate() {
            match slot {
                Some(_) => {
                    let Some(mut observation) = next.take() else {
                        break;
                    };
                    observation.index = index;
                    observations.push(observation);
                    next = dns_observations.next();
                }
                None => observations.push(aster_acme::precheck::Observation {
                    index,
                    result: Err(aster_acme::precheck::Failure::UnsupportedInput),
                }),
            }
        }
        Ok(StageReport { observations })
    }
}
fn unavailable(count: usize, reason: &str) -> StageReport<Report> {
    StageReport {
        observations: (0..count)
            .map(|index| Observation {
                index,
                result: Err(Failure::Unavailable {
                    reason: reason.to_owned(),
                }),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests;
