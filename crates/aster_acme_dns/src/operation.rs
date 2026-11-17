//! Provider-owned state machines; the runner executes effects without vendor branches.
use crate::{
    CleanupRequest, CleanupResult, CleanupStatus, DnsProvider, DnsRecord, PresentResult,
    ProviderContext, ProviderError, ProviderErrorCode, ProviderExecution, ProviderFailure,
    PublicationReceipt, SideEffect,
    backend::{BackendImplementation, configuration_error},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Instant};

/// Host-side publication batch bound, independent of external wire versions.
pub const MAX_PUBLICATIONS: usize = 100;

/// Fully prepared request. Headers/body may contain credentials; deliberately no Debug.
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Explicit operation semantics: a POST may be a read on some DNS APIs.
    pub mutation: bool,
}

/// Bounded raw response, interpreted exclusively by the provider.
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// Transport evidence, without a URL, credential or raw provider response.
#[derive(Debug, Clone, Copy)]
pub struct HttpFailure {
    pub code: ProviderErrorCode,
    pub side_effect: SideEffect,
}

/// Versioned, provider-owned, non-sensitive durable observations and mutation intentions.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryState {
    pub version: u32,
    pub data: serde_json::Value,
}

impl std::fmt::Debug for RecoveryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryState")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Desired outcome, independent of the provider's record or `RRset` mutation API.
#[derive(Clone)]
pub enum ProviderAction {
    Present(DnsRecord),
    Cleanup(CleanupRequest),
}

/// Events include failures so the provider can reconcile rather than blindly replay.
pub enum ProviderEvent {
    Start,
    Http(Result<HttpResponse, HttpFailure>),
    CheckpointSaved,
    Secret(String),
    Timer,
}

pub enum ProviderOutcome {
    Presented(PublicationReceipt),
    Cleaned(CleanupStatus),
}

pub enum ProviderEffect {
    Http(HttpRequest),
    Checkpoint(RecoveryState),
    ReadSecret(std::path::PathBuf),
    WaitUntil(Instant),
    Complete(ProviderOutcome),
}

/// Invocation-local state, reconstructed from durable observations on restart.
pub trait ProviderOperation: Send {
    /// # Errors
    /// Rejects invalid events and reports provider failures with side-effect evidence.
    fn advance(&mut self, event: ProviderEvent) -> Result<ProviderEffect, ProviderError>;
}

pub trait OperationFactory: Send + Sync {
    /// # Errors
    /// Rejects unsupported recovery versions or conflicting publication identities.
    fn start(
        &self,
        action: ProviderAction,
        saved: Option<RecoveryState>,
    ) -> Result<Box<dyn ProviderOperation>, ProviderError>;
}

#[async_trait]
pub trait HttpExecutor: Send + Sync {
    async fn execute(
        &self,
        request: HttpRequest,
        execution: &ProviderExecution,
    ) -> Result<HttpResponse, HttpFailure>;
}

/// Host-owned private credential-file policy, independent of the HTTP transport.
#[async_trait]
pub trait CredentialReader: Send + Sync {
    /// Read an explicitly selected private credential file, bounded and without logging it.
    async fn read(
        &self,
        path: &std::path::Path,
        execution: &ProviderExecution,
    ) -> Result<String, ProviderError>;
}

/// Session holds the host's mutation lease through all effects and persistence workers.
#[async_trait]
pub trait PublicationSession: Send + Sync {
    fn state(&self) -> Option<RecoveryState>;
    /// Save a recovery checkpoint and return only after the update is durably committed.
    ///
    /// `Ok(())` is the confirmation boundary after which the runner may execute the next
    /// provider effect. Enqueuing a background write or updating memory is insufficient.
    /// Implementations should use the strongest persistence guarantee available on the
    /// host platform; this contract does not promise power-loss durability beyond the
    /// guarantees provided by that platform and its filesystem.
    async fn save(&mut self, state: RecoveryState) -> Result<(), ProviderError>;
}

#[async_trait]
pub trait PublicationStore: Send + Sync {
    /// Persist and validate backend/scope/record identity before returning the lease.
    async fn open(
        &self,
        backend: &str,
        binding: &str,
        record: &DnsRecord,
        execution: &ProviderExecution,
    ) -> Result<Box<dyn PublicationSession>, ProviderError>;
}

#[derive(Clone)]
pub struct ProviderHost {
    pub timeout: std::time::Duration,
    pub http: Arc<dyn HttpExecutor>,
    pub credentials: Option<Arc<dyn CredentialReader>>,
    pub publications: Arc<dyn PublicationStore>,
}

pub(crate) struct RegisteredProvider {
    backend: String,
    binding: String,
    implementation: BackendImplementation,
    host: ProviderHost,
}

impl RegisteredProvider {
    pub(crate) fn new(
        backend: String,
        binding: String,
        implementation: BackendImplementation,
        host: ProviderHost,
    ) -> Self {
        Self {
            backend,
            binding,
            implementation,
            host,
        }
    }

    async fn native(
        &self,
        factory: &dyn OperationFactory,
        action: ProviderAction,
        execution: &ProviderExecution,
    ) -> Result<ProviderOutcome, ProviderError> {
        check(execution, false)?;
        let record = match &action {
            ProviderAction::Present(record) => record,
            ProviderAction::Cleanup(request) => &request.record,
        };
        let mut session = self
            .host
            .publications
            .open(&self.backend, &self.binding, record, execution)
            .await?;
        let mut operation = factory.start(action, session.state())?;
        let mut event = ProviderEvent::Start;
        // Bounds even a buggy provider that emits effects without making progress.
        let mut mutated = session.state().is_some();
        let mut write_permitted = false;
        let mut draining = 0;
        for _ in 0..1024 {
            // Preserve an already observed response and its durable result on
            // cancellation, but never start more I/O. Bound even a buggy drain.
            if check(execution, mutated).is_err() {
                draining += 1;
                if draining > 8 {
                    return Err(interrupted(mutated));
                }
            }
            match operation.advance(event)? {
                ProviderEffect::Http(request) => {
                    if request.mutation && !write_permitted {
                        return Err(configuration_error(
                            "DNS mutation requires a durably acknowledged checkpoint",
                        ));
                    }
                    let mutation = request.mutation;
                    if mutation {
                        write_permitted = false;
                    }
                    if check(execution, mutated).is_err() {
                        event = ProviderEvent::Http(Err(HttpFailure {
                            code: ProviderErrorCode::ProviderTimeout,
                            side_effect: SideEffect::None,
                        }));
                        continue;
                    }
                    mutated |= mutation;
                    let failure = HttpFailure {
                        code: ProviderErrorCode::ProviderTimeout,
                        side_effect: if mutation {
                            SideEffect::Unknown
                        } else {
                            SideEffect::None
                        },
                    };
                    event = ProviderEvent::Http(tokio::select! {
                        biased;
                        () = execution.cancellation.cancelled() => Err(failure),
                        result = tokio::time::timeout_at(execution.deadline.into(), self.host.http.execute(request, execution)) => result.unwrap_or(Err(failure)),
                    });
                }
                ProviderEffect::Checkpoint(state) => {
                    if state.version == 0
                        || serde_json::to_vec(&state.data).map_or(true, |bytes| bytes.len() > 32768)
                    {
                        return Err(configuration_error("invalid DNS recovery checkpoint"));
                    }
                    session.save(state).await.map_err(|mut error| {
                        if mutated {
                            error.side_effect = SideEffect::Unknown;
                        }
                        error
                    })?;
                    write_permitted = true;
                    event = ProviderEvent::CheckpointSaved;
                }
                ProviderEffect::ReadSecret(path) => {
                    check(execution, mutated)?;
                    let reader = self
                        .host
                        .credentials
                        .as_ref()
                        .ok_or_else(missing_credentials)?;
                    event = ProviderEvent::Secret(reader.read(&path, execution).await?);
                }
                ProviderEffect::WaitUntil(until) => {
                    check(execution, mutated)?;
                    tokio::select! {
                        biased;
                        () = execution.cancellation.cancelled() => return Err(interrupted(mutated)),
                        () = tokio::time::sleep_until(execution.deadline.into()) => return Err(interrupted(mutated)),
                        () = tokio::time::sleep_until(until.into()) => event = ProviderEvent::Timer,
                    }
                }
                ProviderEffect::Complete(outcome) => return Ok(outcome),
            }
        }
        Err(interrupted(mutated))
    }

    async fn bind_external(
        &self,
        records: impl Iterator<Item = &DnsRecord>,
        execution: &ProviderExecution,
    ) -> Result<(), ProviderFailure> {
        for record in records {
            check(execution, false)?;
            // ADPP executables own their DNS-level concurrency; this session binds
            // durable identity only and is released before invoking the process.
            self.host
                .publications
                .open(&self.backend, &self.binding, record, execution)
                .await?;
        }
        Ok(())
    }
}

#[async_trait]
impl DnsProvider for RegisteredProvider {
    async fn present(
        &self,
        context: &ProviderContext,
        records: &[DnsRecord],
        execution: &ProviderExecution,
    ) -> Result<Vec<PresentResult>, ProviderFailure> {
        validate_batch(records.iter())?;
        let bounded = ProviderExecution {
            cancellation: execution.cancellation.clone(),
            deadline: execution.deadline.min(Instant::now() + self.host.timeout),
        };
        let execution = &bounded;
        match &self.implementation {
            BackendImplementation::External(provider) => {
                self.bind_external(records.iter(), execution).await?;
                provider.present(context, records, execution).await
            }
            BackendImplementation::Native(factory) => {
                let mut results = Vec::new();
                for record in records {
                    let result = match self
                        .native(
                            factory.as_ref(),
                            ProviderAction::Present(record.clone()),
                            execution,
                        )
                        .await
                    {
                        Ok(ProviderOutcome::Presented(receipt)) => Ok(receipt),
                        Ok(ProviderOutcome::Cleaned(_)) => Err(configuration_error(
                            "DNS provider returned wrong operation outcome",
                        )),
                        Err(error) => Err(error),
                    };
                    results.push(PresentResult {
                        publication_id: record.publication_id.clone(),
                        result,
                    });
                }
                Ok(results)
            }
        }
    }

    async fn cleanup(
        &self,
        context: &ProviderContext,
        records: &[CleanupRequest],
        execution: &ProviderExecution,
    ) -> Result<Vec<CleanupResult>, ProviderFailure> {
        validate_batch(records.iter().map(|request| &request.record))?;
        if records
            .iter()
            .any(|request| request.publication_id != request.record.publication_id)
        {
            return Err(configuration_error("DNS cleanup publication identity mismatch").into());
        }
        let bounded = ProviderExecution {
            cancellation: execution.cancellation.clone(),
            deadline: execution.deadline.min(Instant::now() + self.host.timeout),
        };
        let execution = &bounded;
        match &self.implementation {
            BackendImplementation::External(provider) => {
                self.bind_external(records.iter().map(|request| &request.record), execution)
                    .await?;
                provider.cleanup(context, records, execution).await
            }
            BackendImplementation::Native(factory) => {
                let mut results = Vec::new();
                for request in records {
                    let result = match self
                        .native(
                            factory.as_ref(),
                            ProviderAction::Cleanup(request.clone()),
                            execution,
                        )
                        .await
                    {
                        Ok(ProviderOutcome::Cleaned(status)) => Ok(status),
                        Ok(ProviderOutcome::Presented(_)) => Err(configuration_error(
                            "DNS provider returned wrong operation outcome",
                        )),
                        Err(error) => Err(error),
                    };
                    results.push(CleanupResult {
                        publication_id: request.publication_id.clone(),
                        result,
                    });
                }
                Ok(results)
            }
        }
    }
}

fn validate_batch<'a>(
    records: impl ExactSizeIterator<Item = &'a DnsRecord>,
) -> Result<(), ProviderError> {
    if records.len() == 0 || records.len() > MAX_PUBLICATIONS {
        return Err(configuration_error(
            "DNS batch must contain 1..=100 publications",
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    for record in records {
        if record.publication_id.is_empty()
            || record.publication_id.len() > 128
            || !record
                .publication_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !ids.insert(record.publication_id.as_str())
        {
            return Err(configuration_error(
                "invalid or duplicate DNS publication identity",
            ));
        }
    }
    Ok(())
}

fn missing_credentials() -> ProviderError {
    ProviderError {
        code: ProviderErrorCode::CredentialsUnavailable,
        message: "host does not provide private credential-file access".into(),
        side_effect: SideEffect::None,
        retry_after_seconds: None,
        provider_code: None,
    }
}

fn interrupted(mutated: bool) -> ProviderError {
    ProviderError {
        code: ProviderErrorCode::ProviderTimeout,
        message: "DNS provider execution interrupted".into(),
        side_effect: if mutated {
            SideEffect::Unknown
        } else {
            SideEffect::None
        },
        retry_after_seconds: None,
        provider_code: None,
    }
}

fn check(execution: &ProviderExecution, mutated: bool) -> Result<(), ProviderError> {
    if execution.cancellation.is_cancelled() || Instant::now() >= execution.deadline {
        Err(interrupted(mutated))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
