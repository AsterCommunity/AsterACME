//! Shared lifecycle for vendors that create and delete individual DNS records.
use crate::provider::{
    retry::ReadRetry,
    rpc::{error, invalid, transport},
};
use aster_acme_dns::{
    CleanupStatus, DnsRecord, ProviderError, ProviderErrorCode, PublicationReceipt,
    RecordOwnership, SideEffect,
    backend::configuration_error,
    operation::{
        HttpRequest, HttpResponse, OperationFactory, ProviderAction, ProviderEffect, ProviderEvent,
        ProviderOperation, ProviderOutcome, RecoveryState,
    },
    routing::absolute_name,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc, time::Duration};

pub(super) const PAGE_SIZE: u32 = 100;
const MAX_PAGES: u32 = 100;
const MAX_SNAPSHOT: usize = 1000;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Zone {
    pub id: String,
    pub name: String, // Absolute normalized owner.
}

impl Zone {
    pub(super) fn new(id: String, name: &str) -> Result<Self, ProviderError> {
        if id.is_empty()
            || id.len() > 80
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(invalid(false));
        }
        Ok(Self {
            id,
            name: absolute_name(name).map_err(|_| invalid(false))?,
        })
    }

    pub(super) fn relative<'a>(&self, owner: &'a str) -> Option<&'a str> {
        if owner == self.name {
            Some("@")
        } else {
            owner.strip_suffix(&self.name)?.strip_suffix('.')
        }
    }
}

pub(super) struct Record {
    pub id: String,
    pub relative_name: String,
    pub kind: String,
    pub value: String,
    pub marker: Option<String>,
    pub ttl: u32,
    pub enabled: bool,
    pub default_line: bool,
}

pub(super) struct Page<T> {
    pub entries: Vec<T>,
    pub total: u32,
}

pub(super) trait IndividualApi: Send + Sync {
    const MARKED: bool;
    fn discover(&self, page: u32) -> Result<HttpRequest, ProviderError>;
    fn zones(&self, response: HttpResponse, page: u32) -> Result<Page<Zone>, ProviderError>;
    fn verify_zone(&self, _zone: &Zone) -> Result<Option<HttpRequest>, ProviderError> {
        Ok(None)
    }
    fn checked_zone(&self, _response: HttpResponse, _zone: &Zone) -> Result<u32, ProviderError> {
        Err(invalid(false))
    }
    fn list(&self, zone: &Zone, relative: &str, page: u32) -> Result<HttpRequest, ProviderError>;
    fn records(
        &self,
        response: HttpResponse,
        zone: &Zone,
        page: u32,
    ) -> Result<Page<Record>, ProviderError>;
    fn inspect(&self, zone: &Zone, id: &str) -> Result<HttpRequest, ProviderError>;
    fn inspected(
        &self,
        response: HttpResponse,
        zone: &Zone,
    ) -> Result<Option<Record>, ProviderError>;
    fn create(
        &self,
        zone: &Zone,
        relative: &str,
        record: &DnsRecord,
        marker: &str,
        minimum_ttl: u32,
    ) -> Result<HttpRequest, ProviderError>;
    fn created(&self, response: HttpResponse) -> Result<String, ProviderError>;
    fn delete(&self, zone: &Zone, id: &str) -> Result<HttpRequest, ProviderError>;
    fn deleted(&self, response: HttpResponse, id: &str) -> Result<CleanupStatus, ProviderError>;
}

pub(super) struct IndividualFactory<A>(pub Arc<A>);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    zone: Zone,
    phase: Phase,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
enum Phase {
    Resolved,
    Preexisting { ids: BTreeSet<String> },
    CreateIntent,
    Rejected,
    Created { id: String },
    DeleteIntent { id: String },
}

enum Stage {
    Start,
    Zones(u32),
    VerifyZone,
    List(u32),
    Reconcile,
    Inspect,
    Send(HttpRequest),
    Created,
    Deleted,
    Finish(Result<ProviderOutcome, ProviderError>),
    Done,
}

struct Operation<A> {
    api: Arc<A>,
    action: ProviderAction,
    owner: String,
    marker: String,
    saved: Option<Checkpoint>,
    stage: Stage,
    best_zone: Option<Zone>,
    ambiguous_zone: bool,
    seen: BTreeSet<String>,
    same_value: BTreeSet<String>,
    marked: Option<Record>,
    borrowable: Option<Record>,
    total: Option<u32>,
    minimum_ttl: u32,
    read_retry: ReadRetry,
}

impl<A: IndividualApi + 'static> OperationFactory for IndividualFactory<A> {
    fn start(
        &self,
        action: ProviderAction,
        saved: Option<RecoveryState>,
    ) -> Result<Box<dyn ProviderOperation>, ProviderError> {
        let record = match &action {
            ProviderAction::Present(record) => record,
            ProviderAction::Cleanup(request) => &request.record,
        };
        let owner =
            absolute_name(&record.name).map_err(|_| configuration_error("invalid DNS owner"))?;
        if record.publication_id.is_empty()
            || record.publication_id.len() > 90
            || !record
                .publication_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || record.value.is_empty()
            || record.value.len() > 255
        {
            return Err(configuration_error(
                "invalid publication identity or TXT value",
            ));
        }
        let saved = saved
            .map(|state| {
                if state.version != 1 {
                    return Err(invalid_checkpoint());
                }
                let checkpoint: Checkpoint =
                    serde_json::from_value(state.data).map_err(|_| invalid_checkpoint())?;
                if Zone::new(checkpoint.zone.id.clone(), &checkpoint.zone.name)? != checkpoint.zone
                    || checkpoint.zone.relative(&owner).is_none()
                {
                    return Err(invalid_checkpoint());
                }
                let valid_phase = match &checkpoint.phase {
                    Phase::Preexisting { ids } => {
                        !ids.is_empty()
                            && ids.len() <= MAX_SNAPSHOT
                            && ids.iter().all(|id| valid_id(id))
                    }
                    Phase::Created { id } | Phase::DeleteIntent { id } => valid_id(id),
                    _ => true,
                };
                if !valid_phase {
                    return Err(invalid_checkpoint());
                }
                Ok(checkpoint)
            })
            .transpose()?;
        let phase = saved.as_ref().map(|saved| &saved.phase);
        match &action {
            ProviderAction::Present(_) if matches!(phase, Some(Phase::DeleteIntent { .. })) => {
                return Err(invalid_checkpoint());
            }
            ProviderAction::Cleanup(request) => {
                let receipt = &request.receipt;
                if request.publication_id != record.publication_id
                    || receipt.record_name != record.name
                    || receipt.cname_chain != record.cname_chain
                    || !valid_id(&receipt.record_id)
                {
                    return Err(configuration_error(
                        "DNS cleanup receipt does not match publication",
                    ));
                }
                if receipt.ownership == RecordOwnership::Created
                    && !matches!(phase, Some(Phase::Created { id } | Phase::DeleteIntent { id }) if id == &receipt.record_id)
                {
                    return Err(not_owned(false));
                }
            }
            ProviderAction::Present(_) => {}
        }
        let marker = format!("asteracme:{}", record.publication_id);
        Ok(Box::new(Operation {
            api: self.0.clone(),
            action,
            owner,
            marker,
            saved,
            stage: Stage::Start,
            best_zone: None,
            ambiguous_zone: false,
            seen: BTreeSet::new(),
            same_value: BTreeSet::new(),
            marked: None,
            borrowable: None,
            total: None,
            minimum_ttl: 0,
            read_retry: ReadRetry::new(6, Duration::from_secs(5)),
        }))
    }
}

impl<A: IndividualApi> Operation<A> {
    fn record(&self) -> &DnsRecord {
        match &self.action {
            ProviderAction::Present(record) => record,
            ProviderAction::Cleanup(request) => &request.record,
        }
    }

    fn saved(&self) -> Result<&Checkpoint, ProviderError> {
        self.saved.as_ref().ok_or_else(invalid_checkpoint)
    }

    fn relative(&self) -> Result<&str, ProviderError> {
        self.saved()?
            .zone
            .relative(&self.owner)
            .ok_or_else(invalid_checkpoint)
    }

    fn checkpoint(&mut self, phase: Phase, next: Stage) -> Result<ProviderEffect, ProviderError> {
        self.save(
            Checkpoint {
                zone: self.saved()?.zone.clone(),
                phase,
            },
            next,
        )
    }

    fn save(&mut self, saved: Checkpoint, next: Stage) -> Result<ProviderEffect, ProviderError> {
        let data = serde_json::to_value(&saved).map_err(|_| invalid_checkpoint())?;
        self.saved = Some(saved);
        self.stage = next;
        Ok(ProviderEffect::Checkpoint(RecoveryState {
            version: 1,
            data,
        }))
    }

    fn http(&mut self, request: HttpRequest, next: Stage) -> ProviderEffect {
        self.stage = next;
        ProviderEffect::Http(request)
    }

    fn discover(&mut self, page: u32) -> Result<ProviderEffect, ProviderError> {
        let request = self.api.discover(page)?;
        Ok(self.http(request, Stage::Zones(page)))
    }

    fn discovered(
        &mut self,
        response: HttpResponse,
        page: u32,
    ) -> Result<ProviderEffect, ProviderError> {
        let Page { entries, total } = self.api.zones(response, page)?;
        let more = self.has_more(page, entries.len(), total)?;
        for zone in entries {
            if !self.seen.insert(zone.id.clone()) {
                return Err(invalid(false));
            }
            if zone.relative(&self.owner).is_none() {
                continue;
            }
            let size = zone.name.len();
            match self
                .best_zone
                .as_ref()
                .map(|best| size.cmp(&best.name.len()))
            {
                None | Some(std::cmp::Ordering::Greater) => {
                    self.best_zone = Some(zone);
                    self.ambiguous_zone = false;
                }
                Some(std::cmp::Ordering::Equal) => self.ambiguous_zone = true,
                Some(std::cmp::Ordering::Less) => {}
            }
        }
        if more {
            return self.discover(page + 1);
        }
        if self.ambiguous_zone {
            return Err(error(
                ProviderErrorCode::ZoneAmbiguous,
                "multiple DNS zones match the publication target",
                SideEffect::None,
            ));
        }
        let zone = self.best_zone.take().ok_or_else(|| {
            error(
                ProviderErrorCode::ZoneNotFound,
                "no DNS zone contains the publication target",
                SideEffect::None,
            )
        })?;
        self.seen.clear();
        self.total = None;
        self.save(
            Checkpoint {
                zone,
                phase: Phase::Resolved,
            },
            Stage::Start,
        )
    }

    fn has_more(&mut self, page: u32, len: usize, total: u32) -> Result<bool, ProviderError> {
        let offset = (page - 1) * PAGE_SIZE;
        let expected = total.saturating_sub(offset).min(PAGE_SIZE);
        if total > MAX_PAGES * PAGE_SIZE
            || self.total.is_some_and(|previous| previous != total)
            || usize::try_from(expected).ok() != Some(len)
        {
            return Err(invalid(false));
        }
        self.total = Some(total);
        Ok(total > offset + PAGE_SIZE)
    }

    fn start(&mut self) -> Result<ProviderEffect, ProviderError> {
        if matches!(&self.action, ProviderAction::Cleanup(request) if request.receipt.ownership == RecordOwnership::Preexisting)
        {
            return Ok(ProviderEffect::Complete(ProviderOutcome::Cleaned(
                CleanupStatus::Retained,
            )));
        }
        if let Some(saved) = &self.saved {
            if let Some(request) = self.api.verify_zone(&saved.zone)? {
                return Ok(self.http(request, Stage::VerifyZone));
            }
            self.read()
        } else {
            self.discover(1)
        }
    }

    fn read(&mut self) -> Result<ProviderEffect, ProviderError> {
        let saved = self.saved()?;
        let (request, next) = match &saved.phase {
            Phase::Created { id } | Phase::DeleteIntent { id } => {
                (self.api.inspect(&saved.zone, id)?, Stage::Inspect)
            }
            _ => (
                self.api.list(&saved.zone, self.relative()?, 1)?,
                Stage::List(1),
            ),
        };
        Ok(self.http(request, next))
    }

    fn same_value(&self, record: &Record) -> Result<bool, ProviderError> {
        Ok(record.relative_name.eq_ignore_ascii_case(self.relative()?)
            && record.kind == "TXT"
            && record.value == self.record().value)
    }

    fn listed(
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
            if A::MARKED && record.marker.as_deref() == Some(&self.marker) {
                if !same || self.marked.is_some() {
                    return Err(not_owned(true));
                }
                self.marked = Some(record);
            } else if A::MARKED
                && same
                && record.enabled
                && record.default_line
                && record.ttl > 0
                && record
                    .marker
                    .as_ref()
                    .is_none_or(|marker| !marker.starts_with("asteracme:"))
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
            if A::MARKED
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

    fn save_created(&mut self, id: String) -> Result<ProviderEffect, ProviderError> {
        if !valid_id(&id) {
            return Err(invalid(true));
        }
        self.checkpoint(Phase::Created { id }, Stage::Start)
    }

    fn inspected(&mut self, response: HttpResponse) -> Result<ProviderEffect, ProviderError> {
        let saved = self.saved()?;
        let (Phase::Created { id } | Phase::DeleteIntent { id }) = &saved.phase else {
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
            || (A::MARKED && record.marker.as_deref() != Some(&self.marker))
        {
            return Err(not_owned(false));
        }
        if cleanup {
            let request = self.api.delete(&saved.zone, id)?;
            return self.checkpoint(Phase::DeleteIntent { id: record.id }, Stage::Send(request));
        }
        if !record.enabled || record.ttl == 0 {
            return Err(not_owned(false));
        }
        Ok(ProviderEffect::Complete(
            self.receipt(record, RecordOwnership::Created),
        ))
    }

    fn receipt(&self, record: Record, ownership: RecordOwnership) -> ProviderOutcome {
        ProviderOutcome::Presented(PublicationReceipt {
            record_id: record.id,
            ownership,
            record_name: self.record().name.clone(),
            cname_chain: self.record().cname_chain.clone(),
            effective_ttl_seconds: Some(record.ttl),
        })
    }
}

impl<A: IndividualApi> ProviderOperation for Operation<A> {
    fn advance(&mut self, event: ProviderEvent) -> Result<ProviderEffect, ProviderError> {
        match (std::mem::replace(&mut self.stage, Stage::Done), event) {
            (Stage::Start, ProviderEvent::Start | ProviderEvent::CheckpointSaved) => self.start(),
            (Stage::Zones(page), ProviderEvent::Http(response)) => {
                self.discovered(response.map_err(transport)?, page)
            }
            (Stage::VerifyZone, ProviderEvent::Http(response)) => {
                self.minimum_ttl = self
                    .api
                    .checked_zone(response.map_err(transport)?, &self.saved()?.zone)?;
                self.read()
            }
            (Stage::List(page), ProviderEvent::Http(response)) => {
                self.listed(response.map_err(transport)?, page)
            }
            (Stage::Reconcile, ProviderEvent::Timer) => self.read(),
            (Stage::Inspect, ProviderEvent::Http(response)) => {
                self.inspected(response.map_err(transport)?)
            }
            (Stage::Send(request), ProviderEvent::CheckpointSaved) => {
                let next = if matches!(self.action, ProviderAction::Present(_)) {
                    Stage::Created
                } else {
                    Stage::Deleted
                };
                Ok(self.http(request, next))
            }
            (Stage::Created, ProviderEvent::Http(response)) => {
                match response
                    .map_err(transport)
                    .and_then(|response| self.api.created(response))
                {
                    Ok(id) => self.save_created(id),
                    Err(failure) if failure.side_effect == SideEffect::None => {
                        self.checkpoint(Phase::Rejected, Stage::Finish(Err(failure)))
                    }
                    Err(failure) => Err(failure),
                }
            }
            (Stage::Deleted, ProviderEvent::Http(response)) => {
                let Phase::DeleteIntent { id } = &self.saved()?.phase else {
                    return Err(invalid_checkpoint());
                };
                let status = self.api.deleted(response.map_err(transport)?, id)?;
                Ok(ProviderEffect::Complete(ProviderOutcome::Cleaned(status)))
            }
            (Stage::Finish(result), ProviderEvent::CheckpointSaved) => {
                result.map(ProviderEffect::Complete)
            }
            _ => Err(configuration_error("invalid DNS record operation event")),
        }
    }
}

pub(super) fn valid_id(id: &str) -> bool {
    id.len() <= 24
        && id.bytes().all(|b| b.is_ascii_digit())
        && id.as_bytes().first().is_some_and(|b| *b != b'0')
}

fn invalid_checkpoint() -> ProviderError {
    configuration_error("invalid or incompatible DNS record checkpoint")
}

fn not_owned(uncertain: bool) -> ProviderError {
    error(
        ProviderErrorCode::RecordNotOwned,
        "cannot prove ownership of the exact TXT record; inspect remote DNS before retrying",
        if uncertain {
            SideEffect::Unknown
        } else {
            SideEffect::None
        },
    )
}
