//! Record reconciliation, marking, and exact owned-record cleanup.
use crate::provider::common::{
    individual::{
        api::{IndividualApi, Page, Record, RecordMarking, valid_id},
        lifecycle::{MAX_SNAPSHOT, Operation, Phase, Stage, invalid_checkpoint, not_owned},
    },
    rpc::{error, invalid},
};
use aster_acme_dns::{
    CleanupStatus, ProviderError, ProviderErrorCode, PublicationReceipt, RecordOwnership,
    SideEffect,
    operation::{HttpResponse, ProviderAction, ProviderEffect, ProviderOutcome},
};
impl<A: IndividualApi> Operation<A> {
    pub(super) fn same_value(&self, record: &Record) -> Result<bool, ProviderError> {
        Ok(record.relative_name.eq_ignore_ascii_case(self.relative()?)
            && record.kind == "TXT"
            && record.value == self.record().value)
    }

    pub(super) fn listed(
        &mut self,
        response: HttpResponse,
        page: u32,
    ) -> Result<ProviderEffect, ProviderError> {
        let Page { entries, total } = self.api.records(response, &self.saved()?.zone, page)?;
        let more = self.has_more(page, entries.len(), total)?;
        for record in entries {
            if !valid_id(&record.id) || !self.seen.insert(record.id.clone()) {
                return Err(invalid(false));
            }
            let same = self.same_value(&record)?;
            if same {
                self.same_value.insert(record.id.clone());
                if self.same_value.len() > MAX_SNAPSHOT {
                    return Err(invalid(false));
                }
            }
            if A::MARKING == RecordMarking::Inline
                && record.marker.as_deref().is_some_and(|marker| {
                    self.api.owns_marker(marker, &self.record().publication_id)
                })
            {
                if !same || self.marked.is_some() {
                    return Err(not_owned(true));
                }
                self.marked = Some(record);
            } else if A::MARKING == RecordMarking::Inline
                && same
                && record.enabled
                && record.default_line
                && record.ttl > 0
                && record
                    .marker
                    .as_ref()
                    .is_none_or(|marker| !self.api.is_publication_marker(marker))
            {
                self.borrowable = Some(record);
            }
        }
        if more {
            let request = self
                .api
                .list(&self.saved()?.zone, self.relative()?, page + 1)?;
            return Ok(self.http(request, Stage::List(page + 1)));
        }
        let uncertain = matches!(self.saved()?.phase, Phase::CreateIntent);
        if let Some(record) = self.marked.take() {
            if !uncertain || self.same_value.len() != 1 {
                return Err(not_owned(uncertain));
            }
            // Re-read the exact ID before giving a receipt or acknowledging the challenge.
            return self.save_created(record.id);
        }
        if uncertain {
            if A::MARKING == RecordMarking::Inline
                && let Some(until) = self.read_retry.next()
            {
                self.seen.clear();
                self.same_value.clear();
                self.marked = None;
                self.borrowable = None;
                self.total = None;
                self.stage = Stage::Reconcile;
                return Ok(ProviderEffect::WaitUntil(until));
            }
            return Err(not_owned(true));
        }
        if !self.same_value.is_empty() {
            let outcome = if self.same_value.len() == 1 {
                self.borrowable
                    .take()
                    .map(|record| self.receipt(record, RecordOwnership::Preexisting))
            } else {
                None
            };
            let result = outcome.ok_or_else(|| {
                error(
                    ProviderErrorCode::RecordConflict,
                    "an existing TXT value is reserved by another publication or operator",
                    SideEffect::None,
                )
            });
            let ids = std::mem::take(&mut self.same_value);
            return self.checkpoint(Phase::Preexisting { ids }, Stage::Finish(result));
        }
        let request = self.api.create(
            &self.saved()?.zone,
            self.relative()?,
            self.record(),
            &self.marker,
            self.minimum_ttl,
        )?;
        self.checkpoint(Phase::CreateIntent, Stage::Send(request))
    }

    pub(super) fn save_created(&mut self, id: String) -> Result<ProviderEffect, ProviderError> {
        if !valid_id(&id) {
            return Err(invalid(true));
        }
        let phase = if A::MARKING == RecordMarking::AfterCreate {
            Phase::RemarkIntent { id }
        } else {
            Phase::Created { id }
        };
        self.checkpoint(phase, Stage::Start)
    }

    pub(super) fn inspected(
        &mut self,
        response: HttpResponse,
    ) -> Result<ProviderEffect, ProviderError> {
        let saved = self.saved()?;
        let (Phase::Created { id }
        | Phase::Marked { id }
        | Phase::RemarkIntent { id }
        | Phase::DeleteIntent { id }) = &saved.phase
        else {
            return Err(invalid_checkpoint());
        };
        let record = self.api.inspected(response, &saved.zone)?;
        let cleanup = matches!(self.action, ProviderAction::Cleanup(_));
        let Some(record) = record else {
            if !cleanup && let Some(until) = self.read_retry.next() {
                self.stage = Stage::Reconcile;
                return Ok(ProviderEffect::WaitUntil(until));
            }
            return if cleanup {
                Ok(ProviderEffect::Complete(ProviderOutcome::Cleaned(
                    CleanupStatus::AlreadyAbsent,
                )))
            } else {
                Err(not_owned(true))
            };
        };
        if &record.id != id
            || !self.same_value(&record)?
            || !record.default_line
            || ((A::MARKING == RecordMarking::Inline
                || matches!(
                    saved.phase,
                    Phase::Marked { .. } | Phase::DeleteIntent { .. }
                ))
                && !record.marker.as_deref().is_some_and(|marker| {
                    self.api.owns_marker(marker, &self.record().publication_id)
                }))
        {
            return Err(not_owned(!cleanup));
        }
        if matches!(saved.phase, Phase::RemarkIntent { .. }) {
            let remark_id = match &saved.phase {
                Phase::RemarkIntent { id } => id.clone(),
                _ => return Err(invalid_checkpoint()),
            };
            if record
                .marker
                .as_deref()
                .is_some_and(|marker| self.api.owns_marker(marker, &self.record().publication_id))
            {
                return self.checkpoint(Phase::Marked { id: remark_id }, Stage::Start);
            }
            if record
                .marker
                .as_deref()
                .is_some_and(|marker| !marker.is_empty())
            {
                return Err(not_owned(true));
            }
            let request = self.api.set_remark(&remark_id, &self.marker)?;
            return self.checkpoint(
                Phase::RemarkIntent { id: remark_id },
                Stage::RemarkSend(request),
            );
        }
        if cleanup {
            let request = self.api.delete(&saved.zone, id)?;
            return self.checkpoint(Phase::DeleteIntent { id: record.id }, Stage::Send(request));
        }
        if !record.enabled || record.ttl == 0 {
            return Err(not_owned(true));
        }
        Ok(ProviderEffect::Complete(
            self.receipt(record, RecordOwnership::Created),
        ))
    }

    pub(super) fn remarked(
        &mut self,
        response: HttpResponse,
    ) -> Result<ProviderEffect, ProviderError> {
        self.api.remarked(response)?;
        let id = match &self.saved()?.phase {
            Phase::RemarkIntent { id } => id.clone(),
            _ => return Err(invalid_checkpoint()),
        };
        self.checkpoint(Phase::Marked { id }, Stage::Start)
    }

    pub(super) fn receipt(&self, record: Record, ownership: RecordOwnership) -> ProviderOutcome {
        ProviderOutcome::Presented(PublicationReceipt {
            record_id: record.id,
            ownership,
            record_name: self.record().name.clone(),
            cname_chain: self.record().cname_chain.clone(),
            effective_ttl_seconds: Some(record.ttl),
        })
    }
}
