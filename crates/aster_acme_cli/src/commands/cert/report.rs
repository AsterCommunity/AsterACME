//! Certificate command outcomes, independent of terminal rendering and batch traversal.
use aster_acme::issuance::{IssueOutcome, IssueRecord};
use serde::Serialize;

pub(crate) enum CertificateReport {
    Result {
        result: CertificateResult,
        data_dir: std::path::PathBuf,
    },
    Batch {
        report: RenewalBatch,
        data_dir: std::path::PathBuf,
    },
    List(Vec<IssueRecord>),
    Show {
        record: Box<IssueRecord>,
        verified: bool,
        view: super::render::DetailView,
    },
    Revoked(Box<IssueRecord>),
    Removed {
        name: String,
        scope: aster_acme_cli_storage::issuance::removal::RemovalScope,
        ids: Vec<String>,
        in_use_removed: bool,
    },
    Deployment(DeploymentReport),
    DeploymentDetails {
        name: String,
        binding: Box<aster_acme_cli_storage::issuance::DeploymentBinding>,
    },
    DeploymentUpdated {
        name: String,
        binding: Box<aster_acme_cli_storage::issuance::DeploymentBinding>,
    },
    DeploymentRemoved {
        name: String,
        id: String,
    },
}

pub(crate) struct DeploymentReport {
    pub(crate) name: String,
    pub(crate) entries: Vec<aster_acme_cli_storage::issuance::DeploymentBinding>,
    pub(crate) events: Vec<DeploymentEvent>,
    pub(crate) attempted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DeploymentEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) deployment: Option<String>,
    #[serde(rename = "level")]
    pub(super) kind: crate::common::output::MessageKind,
    pub(super) message: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeploymentExecution {
    pub(super) binding: aster_acme_cli_storage::issuance::DeploymentBinding,
    pub(super) events: Vec<DeploymentEvent>,
}

impl CertificateReport {
    pub(crate) fn exit_status(&self) -> crate::common::session::ExitStatus {
        use crate::common::session::ExitStatus;
        match self {
            Self::Batch { report, .. } => match report.disposition() {
                BatchDisposition::Cancelled => ExitStatus::Cancelled,
                BatchDisposition::PartialFailure => ExitStatus::Failed,
                BatchDisposition::Completed | BatchDisposition::ActionRequired => {
                    ExitStatus::Success
                }
            },
            Self::Deployment(report)
                if report.attempted
                    && (report
                        .events
                        .iter()
                        .any(|event| event.kind == crate::common::output::MessageKind::Error)
                        || report.entries.iter().any(|entry| {
                            entry.phase
                                != aster_acme_cli_storage::issuance::DeploymentPhase::Deployed
                        })) =>
            {
                ExitStatus::Failed
            }
            Self::Result {
                result:
                    CertificateResult::Issued {
                        deployments,
                        deployment_events,
                        ..
                    },
                ..
            } if deployment_events
                .iter()
                .any(|event| event.kind == crate::common::output::MessageKind::Error)
                || deployments.iter().any(|entry| {
                    entry.phase != aster_acme_cli_storage::issuance::DeploymentPhase::Deployed
                }) =>
            {
                ExitStatus::Failed
            }
            Self::Result { .. }
            | Self::Deployment(_)
            | Self::DeploymentDetails { .. }
            | Self::DeploymentUpdated { .. }
            | Self::DeploymentRemoved { .. }
            | Self::List(_)
            | Self::Show { .. }
            | Self::Revoked(_)
            | Self::Removed { .. } => ExitStatus::Success,
        }
    }
}

/// Shared single-certificate result; scheduling without work is a successful outcome.
pub(crate) enum CertificateResult {
    Issuance(IssueOutcome),
    Issued {
        outcome: IssueOutcome,
        deployments: Vec<aster_acme_cli_storage::issuance::DeploymentBinding>,
        deployment_events: Vec<DeploymentEvent>,
    },
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
    ManualValidation,
}

impl SkipReason {
    pub(super) const fn message(self) -> &'static str {
        match self {
            Self::NoInUseCertificate => "no in-use certificate; complete an initial issuance first",
            Self::BatchCancelled => "not attempted after batch cancellation",
            Self::ManualValidation => {
                "saved validation method requires user action; automatic renewal skipped"
            }
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

pub(crate) struct RenewalBatch {
    pub(super) entries: Vec<RenewalEntry>,
    pub(super) cancelled: bool,
}

impl RenewalBatch {
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            entries: Vec::new(),
            cancelled: false,
        }
    }

    pub(crate) fn cancelled() -> Self {
        Self {
            entries: Vec::new(),
            cancelled: true,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn was_cancelled(&self) -> bool {
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

    pub(crate) fn has_failures(&self) -> bool {
        self.summary().failed > 0
    }

    pub(super) fn summary(&self) -> RenewalSummary {
        let mut summary = RenewalSummary::default();
        for entry in &self.entries {
            match &entry.result {
                RenewalResult::Outcome(CertificateResult::Issued {
                    outcome: IssueOutcome::Completed { .. },
                    deployments,
                    deployment_events,
                }) if deployment_events
                    .iter()
                    .any(|event| event.kind == crate::common::output::MessageKind::Error)
                    || deployments.iter().any(|entry| {
                        entry.phase != aster_acme_cli_storage::issuance::DeploymentPhase::Deployed
                    }) =>
                {
                    summary.failed += 1;
                }
                RenewalResult::Outcome(
                    CertificateResult::Issuance(IssueOutcome::Completed { .. })
                    | CertificateResult::Issued {
                        outcome: IssueOutcome::Completed { .. },
                        ..
                    },
                ) => summary.completed += 1,
                RenewalResult::Outcome(
                    CertificateResult::Issuance(IssueOutcome::ActionRequired { .. })
                    | CertificateResult::Issued {
                        outcome: IssueOutcome::ActionRequired { .. },
                        ..
                    },
                ) => summary.action_required += 1,
                RenewalResult::Outcome(CertificateResult::NotDue(_)) => summary.not_due += 1,
                RenewalResult::Skipped(_) => summary.skipped += 1,
                RenewalResult::Failed { .. } => summary.failed += 1,
                RenewalResult::Cancelled => summary.cancelled += 1,
            }
        }
        summary
    }
}
