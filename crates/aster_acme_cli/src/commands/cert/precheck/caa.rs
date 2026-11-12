//! Before-newOrder CAA advice. No local result can reject or mutate issuance.
use crate::commands::cert::progress::Progress;
use crate::common::output::MessageKind;
use aster_acme::issuance::IssueRecord;
use aster_acme::precheck::{Failure, Runner};
use aster_acme_core::caa::Observation;

pub(in crate::commands::cert) struct Display<'a> {
    record: &'a IssueRecord,
    progress: &'a Progress,
}
impl<'a> Display<'a> {
    pub(in crate::commands::cert) const fn new(
        record: &'a IssueRecord,
        progress: &'a Progress,
    ) -> Self {
        Self { record, progress }
    }
}
impl aster_acme::precheck::order::Observer<aster_acme_validation::caa::Report> for Display<'_> {
    fn starting(&self) {
        self.progress.output.progress(
            MessageKind::Info,
            &format!(
                "Checking local CAA policy (advisory, up to {} seconds; CA decides)",
                Runner::default().timeout().as_secs()
            ),
        );
    }
    fn observed(&self, report: &aster_acme::precheck::Report<aster_acme_validation::caa::Report>) {
        for item in &report.observations {
            let name = self.record.identifiers.get(item.index).map_or_else(
                || "unknown".into(),
                aster_acme::identifier::DnsIdentifier::value,
            );
            match &item.result {
                Ok(report) => render(report, self.progress),
                Err(Failure::TimedOut | Failure::NotChecked) => self.progress.output.progress(MessageKind::Warning, &format!("CAA {name}: CAA precheck timed out; result unknown, continuing to CA")),
                Err(Failure::Unavailable) => self.progress.output.progress(MessageKind::Warning, &format!("CAA {name}: inconclusive (missing caaIdentities or unavailable local resolver); CA will perform its own CAA check")),
                Err(Failure::LookupFailed | Failure::UnsupportedInput) => self.progress.output.progress(MessageKind::Warning, &format!("CAA {name}: DNS lookup failed; result unknown, continuing to CA")),
            }
        }
    }
}

fn render(report: &aster_acme_validation::caa::Report, progress: &Progress) {
    let (kind, detail) = match report.observation {
        Observation::Unrestricted => (
            MessageKind::Info,
            "no applicable issuer restriction observed",
        ),
        Observation::Matches => (
            MessageKind::Info,
            "a CAA record matches the advertised CA and known request inputs",
        ),
        Observation::NoMatch => (
            MessageKind::Warning,
            "no CAA record matches the advertised CA/account/method; check CAA configuration",
        ),
        Observation::Unknown => (
            MessageKind::Warning,
            "CAA result is inconclusive: unknown critical property or CA-specific parameters",
        ),
    };
    progress.output.progress(
        kind,
        &format!(
            "CAA {}: {detail}; source: {}; CA makes the final decision",
            report.identifier,
            report.source.as_deref().unwrap_or("no CAA RRset")
        ),
    );
    for property in &report.properties {
        tracing::debug!(identifier = %report.identifier, source = ?report.source, critical = property.critical, tag = %crate::common::output::safe(&property.tag), value = %crate::common::output::safe(&String::from_utf8_lossy(&property.value)), "Observed CAA property (local DNS; extension support is CA-dependent)");
    }
}

#[cfg(test)]
mod tests;
