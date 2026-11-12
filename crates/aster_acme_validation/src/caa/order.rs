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
        let names = record
            .identifiers
            .iter()
            .map(aster_acme::identifier::DnsIdentifier::value)
            .collect::<Vec<_>>();
        if directory.meta.caa_identities.is_empty() {
            return Ok(unavailable(names.len()));
        }
        let system;
        let lookup = if let Some(lookup) = self.lookup {
            lookup
        } else {
            system = match SystemLookup::new() {
                Ok(lookup) => lookup,
                Err(_) => return Ok(unavailable(names.len())),
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
        self.runner.run(&checker, &names, execution).await
    }
}
fn unavailable(count: usize) -> StageReport<Report> {
    StageReport {
        observations: (0..count)
            .map(|index| Observation {
                index,
                result: Err(Failure::Unavailable),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests;
