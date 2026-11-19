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

/// HTTP verbs supported by DNS provider effects, independent of vendor features.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// `GET` token.
    Get,
    /// `POST` token.
    Post,
    /// `PUT` token.
    Put,
    /// `DELETE` token.
    Delete,
}

impl HttpMethod {
    /// Exact HTTP token used by transports and request signers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

/// Fully prepared request. Headers/body may contain credentials; deliberately no Debug.
pub struct HttpRequest {
    /// Optional provider-owned API operation name; the host validates it before display.
    pub operation: Option<String>,
    /// Request verb as understood by the provider API.
    pub method: HttpMethod,
    /// Fully qualified request URL, potentially containing credential query parameters.
    pub url: String,
    /// Request headers; may carry auth credentials and are never logged by the host.
    pub headers: Vec<(String, String)>,
    /// Raw request body; may carry credentials and is never logged by the host.
    pub body: Vec<u8>,
    /// Explicit operation semantics: a POST may be a read on some DNS APIs.
    pub mutation: bool,
}

/// Bounded raw response, interpreted exclusively by the provider.
pub struct HttpResponse {
    /// HTTP status code as returned by the provider API.
    pub status: u16,
    /// Raw response headers; interpreted exclusively by the provider.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Raw response body; interpreted exclusively by the provider.
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
    /// Transport failure classification from the shared provider error taxonomy.
    pub code: ProviderErrorCode,
    /// Whether a mutation request may or may not have reached the provider API.
    pub side_effect: SideEffect,
}

/// Versioned, provider-owned, non-sensitive durable observations and mutation intentions.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryState {
    /// Provider-owned schema version; must be nonzero so empty checkpoints stay invalid.
    pub version: u32,
    /// Opaque provider JSON payload, bounded by the host and never interpreted by it.
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
    /// Publish the DNS validation records described by the request.
    Present(DnsRecord),
    /// Remove the records published under the referenced publication identity.
    Cleanup(CleanupRequest),
}

/// Events include failures so the provider can reconcile rather than blindly replay.
pub enum ProviderEvent {
    /// Begin a fresh operation or resume from the last durable checkpoint.
    Start,
    /// Outcome of an `Http` effect; failures carry side-effect evidence for reconciliation.
    Http(Result<HttpResponse, HttpFailure>),
    /// The host durably committed the requested `Checkpoint` state.
    CheckpointSaved,
    /// Contents of a `ReadSecret` credential file; never logged by the host.
    Secret(String),
    /// The instant requested by `WaitUntil` has been reached.
    Timer,
}

/// Terminal state of one provider operation.
pub enum ProviderOutcome {
    /// The publication finished; carries the provider-owned receipt.
    Presented(PublicationReceipt),
    /// The cleanup finished; carries the resulting record status.
    Cleaned(CleanupStatus),
}

/// Single effect the host must execute before the operation can advance again.
pub enum ProviderEffect {
    /// Perform one provider API request under the execution bounds.
    Http(HttpRequest),
    /// Persist a recovery checkpoint; the host confirms with `CheckpointSaved`.
    Checkpoint(RecoveryState),
    /// Read one private credential file through the host policy.
    ReadSecret(std::path::PathBuf),
    /// Suspend until the given instant or cancellation, whichever comes first.
    WaitUntil(Instant),
    /// Terminal outcome; the host stops driving the operation.
    Complete(ProviderOutcome),
}

/// Invocation-local state machine, reconstructed from durable observations on restart.
///
/// Implementations own the provider API protocol; the host drives effects and owns
/// persistence, cancellation, and timeout boundaries.
pub trait ProviderOperation: Send {
    /// # Errors
    /// Rejects invalid events and reports provider failures with side-effect evidence.
    fn advance(&mut self, event: ProviderEvent) -> Result<ProviderEffect, ProviderError>;
}

/// Creates provider operations for one native backend implementation.
pub trait OperationFactory: Send + Sync {
    /// # Errors
    /// Rejects unsupported recovery versions or conflicting publication identities.
    fn start(
        &self,
        action: ProviderAction,
        saved: Option<RecoveryState>,
    ) -> Result<Box<dyn ProviderOperation>, ProviderError>;
}

/// Transport boundary between the host and provider APIs; requests may carry credentials.
#[async_trait]
pub trait HttpExecutor: Send + Sync {
    /// Perform one provider API request within the execution deadline.
    ///
    /// Failures report side-effect evidence instead of raw responses so credential
    /// material never crosses back into provider-owned code.
    ///
    /// # Errors
    /// Returns transport failures classified from the shared provider error taxonomy.
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
    /// Last durably committed checkpoint, or `None` before the first save.
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

/// Opens durable mutation leases bound to backend, binding, and record identity.
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

/// Host-provided services and bounds for one registered provider.
#[derive(Clone)]
pub struct ProviderHost {
    /// Wall-clock cap applied on top of every caller-supplied execution deadline.
    pub timeout: std::time::Duration,
    /// HTTP transport used for all provider API requests.
    pub http: Arc<dyn HttpExecutor>,
    /// Private credential-file access; `None` rejects `ReadSecret` effects.
    pub credentials: Option<Arc<dyn CredentialReader>>,
    /// Durable publication lease store backing mutation checkpoints.
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
        let mut request_context = None;
        for _ in 0..1024 {
            // Preserve an already observed response and its durable result on
            // cancellation, but never start more I/O. Bound even a buggy drain.
            if check(execution, mutated).is_err() {
                draining += 1;
                if draining > 8 {
                    return Err(interrupted(mutated));
                }
            }
            let effect = advance_with_context(operation.as_mut(), event, &mut request_context)?;
            match effect {
                ProviderEffect::Http(request) => {
                    if request.mutation && !write_permitted {
                        return Err(configuration_error(
                            "DNS mutation requires a durably acknowledged checkpoint",
                        ));
                    }
                    let mutation = request.mutation;
                    request_context = Some(request_diagnostic(&request));
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

fn advance_with_context(
    operation: &mut dyn ProviderOperation,
    event: ProviderEvent,
    request_context: &mut Option<String>,
) -> Result<ProviderEffect, ProviderError> {
    let response_status = match &event {
        ProviderEvent::Http(Ok(response)) => Some(response.status),
        _ => None,
    };
    match operation.advance(event) {
        Ok(effect) => {
            if !matches!(effect, ProviderEffect::Checkpoint(_)) {
                *request_context = None;
            }
            Ok(effect)
        }
        Err(error) => Err(annotate_provider_error(
            error,
            request_context.take(),
            response_status,
        )),
    }
}

fn request_diagnostic(request: &HttpRequest) -> String {
    if let Some(action) = request
        .operation
        .as_ref()
        .filter(|action| safe_action(action))
    {
        return action.clone();
    }
    let path = request
        .url
        .split_once("://")
        .and_then(|(_, remainder)| remainder.find('/').map(|index| &remainder[index..]))
        .and_then(|path| path.split(['?', '#']).next())
        .filter(|path| {
            path.len() <= 128
                && path
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"/-_.{}".contains(&byte))
        })
        .map_or_else(|| "<path unavailable>".into(), str::to_owned);
    format!("{} {path}", request.method.as_str())
}

fn safe_action(action: &str) -> bool {
    (1..=64).contains(&action.len())
        && action
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn annotate_provider_error(
    mut error: ProviderError,
    request_context: Option<String>,
    response_status: Option<u16>,
) -> ProviderError {
    if let Some(context) = request_context {
        let status = if error.message.contains("HTTP ") {
            String::new()
        } else {
            response_status.map_or_else(String::new, |status| format!("; HTTP {status}"))
        };
        error.message = format!("{} (API request: {context}{status})", error.message);
    }
    error
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
