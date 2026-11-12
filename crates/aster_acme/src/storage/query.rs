//! Typed storage queries and pure local-record predicates shared by adapters.
use crate::{
    account::AccountRecord,
    issuance::{CertificateName, IssueRecord, IssueRequest},
};
use aster_acme_core::workflow::IssuancePhase;

/// Per-certificate inventory projection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IssueView {
    /// Every generation.
    #[default]
    All,
    /// Current generation, otherwise newest unfinished, otherwise newest historical.
    Managed,
    /// Current generation, otherwise all unfinished generations for inspection.
    CurrentOrUnfinished,
}

/// Complete definition matching with an explicit evaluation time.
#[derive(Clone)]
pub struct SimilarIssue {
    /// Requested certificate definition.
    pub request: IssueRequest,
    /// Account identity used for the request.
    pub account: AccountRecord,
    /// Local time for expiry evaluation.
    pub now: time::OffsetDateTime,
}

/// Typed local issuance snapshot filters, combined with AND semantics.
///
/// Filters are combined with AND semantics. `None` means that dimension is unrestricted;
/// the default query enumerates the full managed inventory.
#[derive(Clone, Default)]
pub struct IssueQuery {
    /// Per-name projection, applied before state filters.
    pub view: IssueView,
    /// Restrict to recoverable candidates; expiry is checked again at execution.
    pub resumable: Option<bool>,
    /// Match a saved unfinished request against the full desired definition.
    pub similar: Option<SimilarIssue>,
    /// Restrict records to one managed certificate.
    pub name: Option<CertificateName>,
    /// Restrict records to one exact issuance generation.
    pub operation_id: Option<String>,
    /// Restrict to current (`true`) or historical (`false`) generations.
    pub in_use: Option<bool>,
    /// Restrict to an exact local execution phase.
    pub phase: Option<IssuancePhase>,
    /// Restrict to completed (`false`) or unfinished (`true`) records.
    pub unfinished: Option<bool>,
    /// Restrict to one saved certificate revocation state.
    pub revocation: Option<aster_acme_core::revocation::RevocationState>,
}

impl IssueQuery {
    /// Evaluate state predicates on an identified local snapshot. Names and operation IDs
    /// can be used by adapters to prune paths before reading journals.
    #[must_use]
    pub fn matches(&self, record: &IssueRecord) -> bool {
        self.name.as_ref().is_none_or(|name| record.name == *name)
            && self
                .operation_id
                .as_deref()
                .is_none_or(|id| record.operation_id == id)
            && self.in_use.is_none_or(|value| record.is_in_use == value)
            && self.phase.is_none_or(|phase| record.phase == phase)
            && self
                .unfinished
                .is_none_or(|value| record.unfinished() == value)
            && self
                .revocation
                .is_none_or(|state| record.revocation.state == state)
            && self
                .resumable
                .is_none_or(|value| record.resume_candidate() == value)
            && self.similar.as_ref().is_none_or(|similar| {
                record.matches_unfinished_request(&similar.request, &similar.account, similar.now)
            })
    }
}

/// Local account metadata filters. Every populated field is combined with AND semantics.
#[derive(Debug, Clone, Default)]
pub struct AccountQuery {
    /// Local operation eligibility, evaluated through the core lifecycle decision.
    pub operation: Option<aster_acme_core::account::AccountOperation>,
    /// Exact local name; adapters can read this account directly.
    pub name: Option<String>,
    /// Exact saved CA directory URL.
    pub directory: Option<aster_acme_protocol::url::AcmeUrl>,
    /// Saved account stage.
    pub state: Option<aster_acme_core::account::AccountRecordState>,
    /// Local lifecycle eligibility, not a fresh CA observation.
    pub usable: Option<bool>,
}

impl AccountQuery {
    /// Check metadata without loading its private key or contacting a CA.
    #[must_use]
    pub fn matches(&self, name: &str, record: &AccountRecord) -> bool {
        self.matches_fields(
            name,
            &record.directory_url,
            record.state,
            record.is_usable(),
        ) && self
            .operation
            .is_none_or(|operation| record.action(operation).is_ok())
    }

    /// Evaluate scalar catalog predicates. Operation eligibility requires the full record
    /// and is applied by `matches` before returning a projected catalog entry.
    #[must_use]
    pub fn matches_fields(
        &self,
        name: &str,
        directory: &aster_acme_protocol::url::AcmeUrl,
        state: aster_acme_core::account::AccountRecordState,
        usable: bool,
    ) -> bool {
        self.name.as_deref().is_none_or(|wanted| wanted == name)
            && self.directory.as_ref().is_none_or(|url| directory == url)
            && self.state.is_none_or(|wanted| state == wanted)
            && self.usable.is_none_or(|wanted| usable == wanted)
    }
}

impl IssueView {
    /// Select local versions per managed name without promoting a historical version.
    ///
    /// # Errors
    /// Rejects inconsistent snapshots with multiple current versions for one name.
    pub fn project(
        self,
        records: Vec<IssueRecord>,
    ) -> Result<Vec<IssueRecord>, crate::issuance::IssueError> {
        let mut grouped = std::collections::BTreeMap::<String, Vec<IssueRecord>>::new();
        for record in records {
            grouped
                .entry(record.name.as_str().to_owned())
                .or_default()
                .push(record);
        }
        let mut selected = Vec::new();
        for mut versions in grouped.into_values() {
            if versions.iter().filter(|record| record.is_in_use).count() > 1 {
                return Err(crate::issuance::IssueError::InvalidInput(
                    "Multiple in_use versions found for one managed certificate.",
                ));
            }
            versions.sort_by(|a, b| {
                b.is_in_use
                    .cmp(&a.is_in_use)
                    .then_with(|| b.unfinished().cmp(&a.unfinished()))
                    .then(b.created_at.cmp(&a.created_at))
                    .then(a.operation_id.cmp(&b.operation_id))
            });
            match self {
                Self::All => {}
                Self::Managed => versions.truncate(1),
                Self::CurrentOrUnfinished => {
                    if versions.iter().any(|r| r.is_in_use) {
                        versions.retain(|r| r.is_in_use);
                    } else {
                        versions.retain(IssueRecord::unfinished);
                    }
                }
            }
            selected.extend(versions);
        }
        Ok(selected)
    }
}
