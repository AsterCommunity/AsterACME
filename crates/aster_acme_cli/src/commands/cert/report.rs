//! Certificate command outcomes, independent of terminal rendering and batch traversal.
use aster_acme::issuance::{IssueOutcome, IssueRecord};
use serde::Serialize;

/// Shared single-certificate result; scheduling without work is a successful outcome.
pub(super) enum CertificateResult {
    Issuance(IssueOutcome),
    NotDue(Box<IssueRecord>),
}

/// One deterministic inventory entry in a batch, including unattempted entries after cancellation.
pub(super) struct RenewalEntry {
    pub(super) name: String,
    pub(super) result: RenewalResult,
}

pub(super) enum RenewalResult {
    Outcome(CertificateResult),
    Skipped(SkipReason),
    Failed {
        message: String,
        hint: Option<String>,
    },
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SkipReason {
    NoInUseCertificate,
    BatchCancelled,
}

impl SkipReason {
    pub(super) const fn message(self) -> &'static str {
        match self {
            Self::NoInUseCertificate => "no in-use certificate; complete an initial issuance first",
            Self::BatchCancelled => "not attempted after batch cancellation",
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub(super) struct RenewalSummary {
    pub(super) completed: usize,
    pub(super) action_required: usize,
    pub(super) not_due: usize,
    pub(super) skipped: usize,
    pub(super) failed: usize,
    pub(super) cancelled: usize,
}

/// Snapshot counts for one concise progress announcement; transactions still
/// recheck the live selection and due time under their certificate lease.
pub(super) struct RenewalWork {
    pub(super) scheduled: usize,
    pub(super) not_due: usize,
}

impl RenewalWork {
    pub(super) fn from_records(
        records: &[IssueRecord],
        immediate: bool,
        now: time::OffsetDateTime,
    ) -> Self {
        use aster_acme_core::renewal::{RenewalDecision, renewal_decision};
        let mut work = Self {
            scheduled: 0,
            not_due: 0,
        };
        for record in records.iter().filter(|record| record.is_in_use) {
            let Some(plan) = &record.renewal else {
                continue;
            };
            let pending = records.iter().any(|candidate| {
                candidate.unfinished()
                    && candidate
                        .renewal_of
                        .as_ref()
                        .is_some_and(|previous| previous.operation_id == record.operation_id)
            });
            match renewal_decision(
                pending,
                record.revocation.state,
                plan.renew_at.unix_timestamp(),
                now.unix_timestamp(),
                immediate,
            ) {
                RenewalDecision::Start | RenewalDecision::Resume => work.scheduled += 1,
                RenewalDecision::NotDue => work.not_due += 1,
                RenewalDecision::RevocationUncertain => {}
            }
        }
        work
    }
}

/// Shared JSON status and process disposition; renderers never infer another outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BatchDisposition {
    Completed,
    ActionRequired,
    PartialFailure,
    Cancelled,
}

pub(super) struct RenewalBatch {
    pub(super) entries: Vec<RenewalEntry>,
    pub(super) cancelled: bool,
}

impl RenewalBatch {
    pub(super) fn was_cancelled(&self) -> bool {
        self.cancelled
            || self.entries.iter().any(|entry| {
                matches!(
                    entry.result,
                    RenewalResult::Cancelled | RenewalResult::Skipped(SkipReason::BatchCancelled)
                )
            })
    }

    pub(super) fn disposition(&self) -> BatchDisposition {
        let summary = self.summary();
        match (
            self.was_cancelled(),
            summary.failed,
            summary.action_required,
        ) {
            (true, _, _) => BatchDisposition::Cancelled,
            (false, 1.., _) => BatchDisposition::PartialFailure,
            (false, 0, 1..) => BatchDisposition::ActionRequired,
            (false, 0, 0) => BatchDisposition::Completed,
        }
    }

    pub(super) fn summary(&self) -> RenewalSummary {
        let mut summary = RenewalSummary::default();
        for entry in &self.entries {
            match &entry.result {
                RenewalResult::Outcome(CertificateResult::Issuance(IssueOutcome::Completed {
                    ..
                })) => summary.completed += 1,
                RenewalResult::Outcome(CertificateResult::Issuance(
                    IssueOutcome::ActionRequired { .. },
                )) => summary.action_required += 1,
                RenewalResult::Outcome(CertificateResult::NotDue(_)) => summary.not_due += 1,
                RenewalResult::Skipped(_) => summary.skipped += 1,
                RenewalResult::Failed { .. } => summary.failed += 1,
                RenewalResult::Cancelled => summary.cancelled += 1,
            }
        }
        summary
    }
}
