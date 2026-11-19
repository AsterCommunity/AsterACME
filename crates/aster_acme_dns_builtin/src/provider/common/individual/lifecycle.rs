//! Durable individual-record state and event dispatch.
mod discovery;
mod factory;
mod publication;
use crate::provider::common::{
    individual::api::{IndividualApi, Record, Zone},
    retry::ReadRetry,
    rpc::{error, transport},
};
use aster_acme_dns::{
    CleanupStatus, DnsRecord, ProviderError, ProviderErrorCode, RecordOwnership, SideEffect,
    backend::configuration_error,
    operation::{
        HttpRequest, ProviderAction, ProviderEffect, ProviderEvent, ProviderOperation,
        ProviderOutcome, RecoveryState,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};
const MAX_PAGES: u32 = 100;
const MAX_SNAPSHOT: usize = 1000;

pub(in crate::provider) struct IndividualFactory<A>(pub Arc<A>);

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
    RemarkIntent { id: String },
    Marked { id: String },
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
    RemarkSend(HttpRequest),
    Remarked,
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
            Phase::Created { id }
            | Phase::RemarkIntent { id }
            | Phase::Marked { id }
            | Phase::DeleteIntent { id } => (self.api.inspect(&saved.zone, id)?, Stage::Inspect),
            _ => (
                self.api.list(&saved.zone, self.relative()?, 1)?,
                Stage::List(1),
            ),
        };
        Ok(self.http(request, next))
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
            (Stage::Remarked, ProviderEvent::Http(response)) => {
                self.remarked(response.map_err(transport)?)
            }
            (Stage::RemarkSend(request), ProviderEvent::CheckpointSaved) => {
                Ok(self.http(request, Stage::Remarked))
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
