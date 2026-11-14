//! `AsterACME` DNS Provider Protocol (ADPP) v1 wire contract.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::unreachable,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo
    )
)]

use aster_acme_dns::{
    CleanupRequest, CleanupResult, CleanupStatus, DnsProvider, DnsRecord, HostErrorCode,
    PresentResult, ProviderContext, ProviderError, ProviderErrorCode, ProviderExecution,
    ProviderFailure, PublicationReceipt, SideEffect,
};
use async_trait::async_trait;
pub mod wire;
use crate::wire::{Action, RecordData, Request, RequestRecord, Response};
use std::{ffi::OsString, path::PathBuf, time::Duration};

/// ADPP v1 protocol identifier.
pub const PROTOCOL_ID: &str = "com.astercosm.acme.adpp";
/// Current ADPP major version.
pub const PROTOCOL_VERSION: u32 = 1;
/// Maximum serialized request or response size.
pub const MAX_JSON_BYTES: usize = 1024 * 1024;
/// Maximum records in one request.
pub const MAX_RECORDS: usize = 100;
/// Maximum provider record ID length in UTF-8 bytes.
pub const MAX_RECORD_ID_BYTES: usize = 1024;

/// Configured external ADPP executable.
#[derive(Debug, Clone)]
pub struct Executable {
    /// Absolute executable path.
    pub program: PathBuf,
    /// Exact argument vector.
    pub args: Vec<OsString>,
    /// Invocation deadline.
    pub timeout: Duration,
}

/// External process adapter for ADPP v1.
#[derive(Debug, Clone)]
pub struct AdppProvider {
    executable: Executable,
}

impl AdppProvider {
    /// Construct an external provider adapter.
    #[must_use]
    pub const fn new(executable: Executable) -> Self {
        Self { executable }
    }

    async fn invoke(
        &self,
        request: Request,
        execution: &ProviderExecution,
    ) -> Result<Response, ProviderFailure> {
        validate_request(&request)?;
        if !self.executable.program.is_absolute()
            || self.executable.timeout.is_zero()
            || self.executable.timeout > Duration::from_secs(300)
        {
            return Err(host(HostErrorCode::RequestInvalid, false));
        }
        let mut input =
            serde_json::to_vec(&request).map_err(|_| host(HostErrorCode::RequestInvalid, false))?;
        input.push(b'\n');
        if input.len() > MAX_JSON_BYTES {
            return Err(host(HostErrorCode::RequestInvalid, false));
        }
        let mut process = aster_acme_process::ProcessSpec::new(
            self.executable.program.clone(),
            self.executable.timeout,
        );
        process.args = self.executable.args.clone();
        process.stdin = Some(input);
        process.stdout_limit = MAX_JSON_BYTES;
        process.stderr_limit = 64 * 1024;
        process.clear_environment = true;
        process.timeout = process.timeout.min(
            execution
                .deadline
                .saturating_duration_since(std::time::Instant::now()),
        );
        let outcome = aster_acme_process::run(process, &execution.cancellation, |_, _| {}).await;
        let started = outcome.started;
        let status = outcome.status.map_err(|failure| {
            use aster_acme_process::ProcessFailure;
            let code = match failure {
                ProcessFailure::Spawn(_) => HostErrorCode::ProcessSpawnFailed,
                ProcessFailure::CancelledBeforeStart | ProcessFailure::Cancelled => {
                    HostErrorCode::ProcessCancelled
                }
                ProcessFailure::TimedOut => HostErrorCode::ProcessTimeout,
                ProcessFailure::Wait(_) => HostErrorCode::ProcessWaitFailed,
            };
            host(code, started)
        })?;
        if !status.success() {
            return Err(host(HostErrorCode::ProcessExitNonzero, started));
        }
        if outcome.stdin_error.is_some() {
            return Err(host(HostErrorCode::ProcessInputFailed, started));
        }
        if outcome.stdout.truncated {
            return Err(host(HostErrorCode::ResponseTooLarge, started));
        }
        if outcome.stdout.read_error.is_some() || !outcome.stdout.bytes.ends_with(b"\n") {
            return Err(host(HostErrorCode::ResponseInvalid, started));
        }
        let mut response: Response =
            serde_json::from_slice(&outcome.stdout.bytes).map_err(|error| {
                host(
                    if error.is_data() {
                        HostErrorCode::ResponseInvalid
                    } else {
                        HostErrorCode::ResponseInvalidJson
                    },
                    started,
                )
            })?;
        validate_response(&request, &response)
            .map_err(|_| host(HostErrorCode::ResponseInvalid, started))?;
        sanitize_response(&mut response, &request.context);
        if let Some(error) = response.error.take() {
            return Err(ProviderFailure::Provider(error.into()));
        }

        Ok(response)
    }
}

#[async_trait]
impl DnsProvider for AdppProvider {
    async fn present(
        &self,
        context: &ProviderContext,
        records: &[DnsRecord],
        execution: &ProviderExecution,
    ) -> Result<Vec<PresentResult>, ProviderFailure> {
        let request =
            request(Action::Present, context, records, &[]).map_err(ProviderFailure::from)?;
        let response = self.invoke(request, execution).await?;
        let routes = records
            .iter()
            .map(|record| {
                (
                    record.publication_id.as_str(),
                    (record.name.as_str(), record.cname_chain.as_slice()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        response
            .results
            .into_iter()
            .map(|result| {
                let value = match (result.status.as_str(), result.error) {
                    ("present", None) => {
                        let record_id = result.record_id.ok_or_else(|| {
                            provider_error(
                                ProviderErrorCode::InternalError,
                                "present result omitted record ID",
                                SideEffect::Unknown,
                            )
                        })?;
                        let ownership = result.ownership.ok_or_else(|| {
                            provider_error(
                                ProviderErrorCode::InternalError,
                                "present result omitted ownership",
                                SideEffect::Unknown,
                            )
                        })?;
                        Ok(PublicationReceipt {
                            record_id,
                            ownership,
                            record_name: routes
                                .get(result.publication_id.as_str())
                                .map(|route| route.0.to_owned())
                                .ok_or_else(|| {
                                    provider_error(
                                        ProviderErrorCode::InternalError,
                                        "present result has no saved route",
                                        SideEffect::Unknown,
                                    )
                                })?,
                            cname_chain: routes
                                .get(result.publication_id.as_str())
                                .map(|route| route.1.to_vec())
                                .ok_or_else(|| {
                                    provider_error(
                                        ProviderErrorCode::InternalError,
                                        "present result has no saved CNAME chain",
                                        SideEffect::Unknown,
                                    )
                                })?,
                        })
                    }
                    ("error", Some(error)) => Err(error.into()),
                    _ => Err(provider_error(
                        ProviderErrorCode::InternalError,
                        "present result is inconsistent",
                        SideEffect::Unknown,
                    )),
                };
                Ok(PresentResult {
                    publication_id: result.publication_id,
                    result: value,
                })
            })
            .collect::<Result<Vec<_>, ProviderError>>()
            .map_err(ProviderFailure::from)
    }

    async fn cleanup(
        &self,
        context: &ProviderContext,
        records: &[CleanupRequest],
        execution: &ProviderExecution,
    ) -> Result<Vec<CleanupResult>, ProviderFailure> {
        let request =
            request(Action::Cleanup, context, &[], records).map_err(ProviderFailure::from)?;
        let response = self.invoke(request, execution).await?;
        response
            .results
            .into_iter()
            .map(|result| {
                let value = match (result.status.as_str(), result.error) {
                    ("removed", None) => Ok(CleanupStatus::Removed),
                    ("retained", None) => Ok(CleanupStatus::Retained),
                    ("already_absent", None) => Ok(CleanupStatus::AlreadyAbsent),
                    ("error", Some(error)) => Err(error.into()),
                    _ => Err(provider_error(
                        ProviderErrorCode::InternalError,
                        "cleanup result is inconsistent",
                        SideEffect::Unknown,
                    )),
                };
                Ok(CleanupResult {
                    publication_id: result.publication_id,
                    result: value,
                })
            })
            .collect::<Result<Vec<_>, ProviderError>>()
            .map_err(ProviderFailure::from)
    }
}

fn request(
    action: Action,
    context: &ProviderContext,
    records: &[DnsRecord],
    cleanup: &[CleanupRequest],
) -> Result<Request, ProviderError> {
    let request_records = match action {
        Action::Present => records
            .iter()
            .map(|record| RequestRecord {
                publication_id: record.publication_id.clone(),
                challenge_name: Some(record.challenge_name.clone()),
                cname_chain: record.cname_chain.clone(),
                record: Some(RecordData {
                    record_type: "TXT".into(),
                    name: record.name.clone(),
                    value: record.value.clone(),
                    ttl_seconds: record.ttl_seconds,
                }),
                record_id: None,
                ownership: None,
            })
            .collect(),
        Action::Cleanup => cleanup
            .iter()
            .map(|entry| RequestRecord {
                publication_id: entry.publication_id.clone(),
                challenge_name: Some(entry.record.challenge_name.clone()),
                cname_chain: entry.receipt.cname_chain.clone(),
                record: Some(RecordData {
                    record_type: "TXT".into(),
                    name: entry.receipt.record_name.clone(),
                    value: entry.record.value.clone(),
                    ttl_seconds: entry.record.ttl_seconds,
                }),
                record_id: Some(entry.receipt.record_id.clone()),
                ownership: Some(entry.receipt.ownership),
            })
            .collect(),
    };
    let request = Request {
        protocol: PROTOCOL_ID.into(),
        version: PROTOCOL_VERSION,
        request_id: request_id()?,
        action,
        context: context.clone(),
        records: request_records,
    };
    if request.records.is_empty() || request.records.len() > MAX_RECORDS {
        return Err(provider_error(
            ProviderErrorCode::InvalidRequest,
            "ADPP request has an invalid record count",
            SideEffect::None,
        ));
    }
    Ok(request)
}

fn validate_response(request: &Request, response: &Response) -> Result<(), ProviderError> {
    if response.protocol != PROTOCOL_ID
        || response.version != PROTOCOL_VERSION
        || response.request_id != request.request_id
        || response.action != request.action
        || (response.error.is_some() && !response.results.is_empty())
    {
        return Err(provider_error(
            ProviderErrorCode::InternalError,
            "DNS provider response does not match its request",
            SideEffect::Unknown,
        ));
    }
    if let Some(error) = &response.error {
        if error.side_effect != SideEffect::None || !valid_error(error) {
            return Err(provider_error(
                ProviderErrorCode::InternalError,
                "invalid request-level error",
                SideEffect::Unknown,
            ));
        }
        return Ok(());
    }
    let expected = request
        .records
        .iter()
        .map(|record| record.publication_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let actual = response
        .results
        .iter()
        .map(|result| result.publication_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if actual.len() != response.results.len() || actual != expected {
        return Err(provider_error(
            ProviderErrorCode::InternalError,
            "DNS provider response has missing or duplicate publication IDs",
            SideEffect::Unknown,
        ));
    }
    for result in &response.results {
        if result
            .error
            .as_ref()
            .is_some_and(|error| !valid_error(error))
        {
            return Err(provider_error(
                ProviderErrorCode::InternalError,
                "invalid provider error fields",
                SideEffect::Unknown,
            ));
        }
        match (request.action, result.status.as_str(), &result.error) {
            (Action::Present, "present", None)
                if result.record_id.as_ref().is_some_and(|id| {
                    !id.is_empty()
                        && id.len() <= MAX_RECORD_ID_BYTES
                        && !id.chars().any(char::is_control)
                }) && result.ownership.is_some() => {}
            (Action::Present | Action::Cleanup, "error", Some(_))
            | (Action::Cleanup, "removed" | "retained" | "already_absent", None)
                if result.record_id.is_none() && result.ownership.is_none() => {}
            _ => {
                return Err(provider_error(
                    ProviderErrorCode::InternalError,
                    "DNS provider returned an invalid record result",
                    SideEffect::Unknown,
                ));
            }
        }
    }
    Ok(())
}

fn provider_error(
    code: ProviderErrorCode,
    message: &str,
    side_effect: SideEffect,
) -> ProviderError {
    ProviderError {
        code,
        message: message.into(),
        side_effect,
        retry_after_seconds: None,
        provider_code: None,
    }
}

fn request_id() -> Result<String, ProviderError> {
    let mut bytes = [0_u8; 16];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| {
        provider_error(
            ProviderErrorCode::InternalError,
            "cannot create ADPP request ID",
            SideEffect::None,
        )
    })?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        bytes,
    ))
}

fn host(code: HostErrorCode, started: bool) -> ProviderFailure {
    ProviderFailure::Host {
        code,
        side_effect: if started {
            SideEffect::Unknown
        } else {
            SideEffect::None
        },
    }
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn validate_request(request: &Request) -> Result<(), ProviderFailure> {
    let invalid = || host(HostErrorCode::RequestInvalid, false);
    if request.protocol != PROTOCOL_ID
        || request.version != PROTOCOL_VERSION
        || !valid_id(&request.request_id)
        || !valid_id(&request.context.provider_instance_id)
        || request.context.provider_profile_version != 1
        || request.records.is_empty()
        || request.records.len() > MAX_RECORDS
    {
        return Err(invalid());
    }
    let mut ids = std::collections::BTreeSet::new();
    for record in &request.records {
        if !valid_id(&record.publication_id) || !ids.insert(&record.publication_id) {
            return Err(invalid());
        }
        let data = record.record.as_ref().ok_or_else(invalid)?;
        let owner = record.challenge_name.as_ref().ok_or_else(invalid)?;
        if data.record_type != "TXT"
            || data.value.is_empty()
            || data.value.len() > 255
            || data
                .ttl_seconds
                .is_some_and(|ttl| ttl == 0 || ttl > 2_147_483_647)
        {
            return Err(invalid());
        }
        aster_acme_dns::routing::validate_chain(
            owner,
            &data.name,
            &record.cname_chain,
            std::slice::from_ref(&data.name),
        )
        .map_err(|_| invalid())?;
        match request.action {
            Action::Present if record.record_id.is_none() && record.ownership.is_none() => {}
            Action::Cleanup
                if record.record_id.as_ref().is_some_and(|id| {
                    !id.is_empty()
                        && id.len() <= MAX_RECORD_ID_BYTES
                        && !id.chars().any(char::is_control)
                }) && record.ownership.is_some() => {}
            _ => return Err(invalid()),
        }
    }
    Ok(())
}
fn valid_error(error: &wire::WireError) -> bool {
    error.message.len() <= 2048
        && error.retry_after_seconds.is_none_or(|delay| {
            error.code == ProviderErrorCode::RateLimited && (1..=86400).contains(&delay)
        })
        && error.provider_code.as_ref().is_none_or(|code| {
            !code.is_empty()
                && code.len() <= 128
                && code.bytes().all(|byte| byte.is_ascii_graphic())
        })
}
fn sanitize_response(response: &mut Response, context: &ProviderContext) {
    fn leaves(value: &serde_json::Value, values: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for value in map.values() {
                    leaves(value, values);
                }
            }
            serde_json::Value::Array(array) => {
                for value in array {
                    leaves(value, values);
                }
            }
            serde_json::Value::String(value) if !value.is_empty() => values.push(value.clone()),
            serde_json::Value::Number(_) | serde_json::Value::Bool(_) => {
                values.push(value.to_string());
            }
            _ => {}
        }
    }
    let mut secrets = Vec::new();
    for value in context.provider_custom.values() {
        leaves(value, &mut secrets);
    }
    secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    for error in response.error.iter_mut().chain(
        response
            .results
            .iter_mut()
            .filter_map(|item| item.error.as_mut()),
    ) {
        for secret in &secrets {
            error.message = error.message.replace(secret, "<redacted>");
        }
        // Provider-specific codes are diagnostic text, never used for decisions.
        if error
            .provider_code
            .as_ref()
            .is_some_and(|code| secrets.iter().any(|secret| code.contains(secret)))
        {
            error.provider_code = None;
        }
    }
}

#[cfg(test)]
mod tests;
