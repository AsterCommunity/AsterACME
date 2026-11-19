//! Conditional `RRset` updates. A protocol must preserve all unknown metadata and
//! implement a genuine atomic, non-reusable revision precondition, including absence.
//! Protocols without this primitive cannot use this state machine safely.
use aster_acme_dns::{
    CleanupStatus, DnsRecord, ProviderError, ProviderErrorCode, PublicationReceipt,
    RecordOwnership, SideEffect,
    backend::configuration_error,
    operation::{
        HttpFailure, HttpRequest, HttpResponse, OperationFactory, ProviderAction, ProviderEffect,
        ProviderEvent, ProviderOperation, ProviderOutcome, RecoveryState,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};

/// Full logical `RRset` plus opaque, non-sensitive provider metadata preserved on updates.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RrsetSnapshot {
    /// All record values currently in the `RRset`, excluding preserved metadata.
    pub values: BTreeSet<String>,
    /// Opaque revision token; empty means the backend lacks a usable precondition.
    pub revision: String,
    /// Opaque provider metadata that write-back must preserve verbatim.
    pub metadata: serde_json::Value,
}

/// Outcome of one conditional `RRset` write interpreted by the protocol.
pub enum ConditionalWrite {
    /// The provider proved the new revision was applied.
    Applied,
    /// The provider proved the precondition failed and the write did not apply.
    Conflict,
}

/// Provider-specific request building, signing and response interpretation.
/// A conflict must prove the write did not apply. Transport failures remain unknown.
pub trait RrsetProtocol: Send + Sync {
    /// # Errors
    /// Reports provider request construction or signing errors.
    fn read(&self, record: &DnsRecord) -> Result<HttpRequest, ProviderError>;
    /// # Errors
    /// Rejects failed, malformed or lossy `RRset` observations.
    fn parse_read(&self, response: HttpResponse) -> Result<RrsetSnapshot, ProviderError>;
    /// # Errors
    /// Rejects unsupported conditional writes or invalid payloads.
    fn write(
        &self,
        record: &DnsRecord,
        snapshot: &RrsetSnapshot,
        values: &BTreeSet<String>,
    ) -> Result<HttpRequest, ProviderError>;
    /// # Errors
    /// Preserves provider failures and unknown mutation outcomes.
    fn parse_write(&self, response: HttpResponse) -> Result<ConditionalWrite, ProviderError>;
}

/// Reusable pure state machine; registering a concrete backend remains explicit.
pub struct ConditionalRrsetFactory {
    protocol: Arc<dyn RrsetProtocol>,
}
impl ConditionalRrsetFactory {
    /// Reuses one protocol implementation across every operation it starts.
    pub fn new(protocol: Arc<dyn RrsetProtocol>) -> Self {
        Self { protocol }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Checkpoint {
    PresentIntent,
    PresentRejected,
    Presented { created: bool },
    CleanupIntent,
    Cleaned(CleanedStatus),
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CleanedStatus {
    Removed,
    Retained,
    AlreadyAbsent,
}
impl From<CleanedStatus> for CleanupStatus {
    fn from(value: CleanedStatus) -> Self {
        match value {
            CleanedStatus::Removed => Self::Removed,
            CleanedStatus::Retained => Self::Retained,
            CleanedStatus::AlreadyAbsent => Self::AlreadyAbsent,
        }
    }
}
impl From<CleanupStatus> for CleanedStatus {
    fn from(value: CleanupStatus) -> Self {
        match value {
            CleanupStatus::Removed => Self::Removed,
            CleanupStatus::Retained => Self::Retained,
            CleanupStatus::AlreadyAbsent => Self::AlreadyAbsent,
        }
    }
}
#[derive(Clone, Copy)]
enum Stage {
    Start,
    Read,
    SaveIntent,
    Write,
    SaveOutcome,
    Done,
}
struct Operation {
    protocol: Arc<dyn RrsetProtocol>,
    action: ProviderAction,
    saved: Option<Checkpoint>,
    stage: Stage,
    snapshot: Option<RrsetSnapshot>,
    desired: BTreeSet<String>,
    conflicts: u8,
    outcome: Option<ProviderOutcome>,
    failure: Option<ProviderError>,
}

impl OperationFactory for ConditionalRrsetFactory {
    fn start(
        &self,
        action: ProviderAction,
        saved: Option<RecoveryState>,
    ) -> Result<Box<dyn ProviderOperation>, ProviderError> {
        let saved = saved
            .map(|saved| {
                if saved.version != 1 {
                    return Err(configuration_error("unsupported RRset checkpoint version"));
                }
                serde_json::from_value::<Checkpoint>(saved.data)
                    .map_err(|_| configuration_error("invalid RRset recovery checkpoint"))
            })
            .transpose()?;
        if let ProviderAction::Cleanup(request) = &action {
            if request.publication_id != request.record.publication_id
                || request.receipt.record_name != request.record.name
                || request.receipt.cname_chain != request.record.cname_chain
                || request.receipt.record_id != identity(&request.record)
            {
                return Err(configuration_error(
                    "RRset cleanup receipt does not match publication",
                ));
            }
            if request.receipt.ownership == RecordOwnership::Created
                && !matches!(
                    saved,
                    Some(
                        Checkpoint::Presented { created: true }
                            | Checkpoint::CleanupIntent
                            | Checkpoint::Cleaned(_)
                    )
                )
            {
                return Err(not_owned());
            }
        }
        Ok(Box::new(Operation {
            protocol: self.protocol.clone(),
            action,
            saved,
            stage: Stage::Start,
            snapshot: None,
            desired: BTreeSet::new(),
            conflicts: 0,
            outcome: None,
            failure: None,
        }))
    }
}

impl Operation {
    fn read_response(
        &mut self,
        response: Result<HttpResponse, HttpFailure>,
    ) -> Result<ProviderEffect, ProviderError> {
        let snapshot = self.protocol.parse_read(response.map_err(transport)?)?;
        if snapshot.revision.is_empty() {
            return Err(configuration_error(
                "RRset backend lacks an atomic revision precondition",
            ));
        }
        let exists = snapshot.values.contains(&self.record().value);
        match &self.action {
            ProviderAction::Present(_) if exists => {
                return match self.saved {
                    Some(Checkpoint::Presented { created }) => self.presented(created),
                    Some(
                        Checkpoint::PresentIntent
                        | Checkpoint::CleanupIntent
                        | Checkpoint::Cleaned(_),
                    ) => Err(not_owned()),
                    None | Some(Checkpoint::PresentRejected) => self.presented(false),
                };
            }
            ProviderAction::Cleanup(_) if !exists => {
                return self.cleaned(CleanupStatus::AlreadyAbsent);
            }
            _ => {}
        }
        if matches!(self.action, ProviderAction::Present(_))
            && matches!(
                self.saved,
                Some(
                    Checkpoint::PresentIntent | Checkpoint::CleanupIntent | Checkpoint::Cleaned(_),
                )
            )
        {
            return Err(not_owned());
        }
        self.desired.clone_from(&snapshot.values);
        let checkpoint = match &self.action {
            ProviderAction::Present(record) => {
                self.desired.insert(record.value.clone());
                Checkpoint::PresentIntent
            }
            ProviderAction::Cleanup(request) => {
                self.desired.remove(&request.record.value);
                Checkpoint::CleanupIntent
            }
        };
        self.snapshot = Some(snapshot);
        self.checkpoint(checkpoint, Stage::SaveIntent)
    }

    fn record(&self) -> &DnsRecord {
        match &self.action {
            ProviderAction::Present(record) => record,
            ProviderAction::Cleanup(request) => &request.record,
        }
    }
    fn read(&mut self) -> Result<ProviderEffect, ProviderError> {
        self.stage = Stage::Read;
        let mut request = self.protocol.read(self.record())?;
        request.mutation = false;
        Ok(ProviderEffect::Http(request))
    }
    fn checkpoint(
        &mut self,
        checkpoint: Checkpoint,
        stage: Stage,
    ) -> Result<ProviderEffect, ProviderError> {
        let data = serde_json::to_value(&checkpoint)
            .map_err(|_| configuration_error("cannot encode RRset checkpoint"))?;
        self.saved = Some(checkpoint);
        self.stage = stage;
        Ok(ProviderEffect::Checkpoint(RecoveryState {
            version: 1,
            data,
        }))
    }
    fn presented(&mut self, created: bool) -> Result<ProviderEffect, ProviderError> {
        let record = self.record();
        self.outcome = Some(ProviderOutcome::Presented(PublicationReceipt {
            effective_ttl_seconds: None,
            record_id: identity(record),
            ownership: if created {
                RecordOwnership::Created
            } else {
                RecordOwnership::Preexisting
            },
            record_name: record.name.clone(),
            cname_chain: record.cname_chain.clone(),
        }));
        self.checkpoint(Checkpoint::Presented { created }, Stage::SaveOutcome)
    }
    fn cleaned(&mut self, status: CleanupStatus) -> Result<ProviderEffect, ProviderError> {
        self.outcome = Some(ProviderOutcome::Cleaned(status));
        self.checkpoint(Checkpoint::Cleaned(status.into()), Stage::SaveOutcome)
    }
}

impl ProviderOperation for Operation {
    fn advance(&mut self, event: ProviderEvent) -> Result<ProviderEffect, ProviderError> {
        match (self.stage, event) {
            (Stage::Start, ProviderEvent::Start) => {
                if let Some(Checkpoint::Cleaned(status)) = self.saved {
                    return Ok(ProviderEffect::Complete(ProviderOutcome::Cleaned(
                        status.into(),
                    )));
                }
                if matches!(&self.action, ProviderAction::Cleanup(request) if request.receipt.ownership == RecordOwnership::Preexisting)
                {
                    return self.cleaned(CleanupStatus::Retained);
                }
                self.read()
            }
            (Stage::Read, ProviderEvent::Http(response)) => self.read_response(response),
            (Stage::SaveIntent, ProviderEvent::CheckpointSaved) => {
                let snapshot = self
                    .snapshot
                    .as_ref()
                    .ok_or_else(|| configuration_error("missing RRset read observation"))?;
                let mut request = self
                    .protocol
                    .write(self.record(), snapshot, &self.desired)?;
                request.mutation = true;
                self.stage = Stage::Write;
                Ok(ProviderEffect::Http(request))
            }
            (Stage::Write, ProviderEvent::Http(response)) => {
                let response = match response {
                    Ok(response) => response,
                    Err(failure)
                        if failure.side_effect == SideEffect::None
                            && matches!(self.action, ProviderAction::Present(_)) =>
                    {
                        self.outcome = None;
                        self.failure = Some(transport(failure));
                        return self.checkpoint(Checkpoint::PresentRejected, Stage::SaveOutcome);
                    }
                    Err(failure) => return Err(transport(failure)),
                };
                match self.protocol.parse_write(response)? {
                    ConditionalWrite::Applied => match &self.action {
                        ProviderAction::Present(_) => self.presented(true),
                        ProviderAction::Cleanup(_) => self.cleaned(CleanupStatus::Removed),
                    },
                    ConditionalWrite::Conflict => {
                        self.conflicts += 1;
                        if self.conflicts >= 4 {
                            let error = ProviderError {
                                code: ProviderErrorCode::RecordConflict,
                                message: "RRset changed repeatedly; conditional write was rejected"
                                    .into(),
                                side_effect: SideEffect::None,
                                retry_after_seconds: None,
                                provider_code: None,
                            };
                            if matches!(self.action, ProviderAction::Present(_)) {
                                self.failure = Some(error);
                                return self
                                    .checkpoint(Checkpoint::PresentRejected, Stage::SaveOutcome);
                            }
                            return Err(error);
                        }
                        // A proved conditional rejection is the only path that can
                        // discard pending ownership uncertainty before another read.
                        if matches!(self.action, ProviderAction::Present(_)) {
                            self.saved = None;
                        }
                        self.read()
                    }
                }
            }
            (Stage::SaveOutcome, ProviderEvent::CheckpointSaved) => {
                self.stage = Stage::Done;
                if let Some(error) = self.failure.take() {
                    return Err(error);
                }
                Ok(ProviderEffect::Complete(self.outcome.take().ok_or_else(
                    || configuration_error("missing RRset outcome"),
                )?))
            }
            _ => Err(configuration_error("invalid RRset state machine event")),
        }
    }
}

fn identity(record: &DnsRecord) -> String {
    format!("rrset:{}", record.publication_id)
}
fn not_owned() -> ProviderError {
    ProviderError {
        code: ProviderErrorCode::RecordNotOwned,
        message: "RRset value ownership is unproved; retain it for reconciliation".into(),
        side_effect: SideEffect::Unknown,
        retry_after_seconds: None,
        provider_code: None,
    }
}
fn transport(failure: HttpFailure) -> ProviderError {
    ProviderError {
        code: failure.code,
        message: "RRset HTTP execution failed".into(),
        side_effect: failure.side_effect,
        retry_after_seconds: None,
        provider_code: None,
    }
}

#[cfg(test)]
mod tests;
