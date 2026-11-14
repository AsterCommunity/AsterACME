//! DNS publication records, provider contracts and policy-owned failures.

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

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Instant};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

pub mod propagation;
pub mod routing;

/// Named `AsterACME` provider profile and its provider-specific custom context.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderContext {
    /// Stable profile ID selected by the certificate definition.
    pub provider_instance_id: String,
    /// Provider profile schema version, independent of ADPP wire version.
    pub provider_profile_version: u32,
    /// Sensitive provider-owned values; callers must redact the whole map.
    #[serde(default)]
    pub provider_custom: BTreeMap<String, serde_json::Value>,
}

impl std::fmt::Debug for ProviderContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderContext")
            .field("provider_instance_id", &self.provider_instance_id)
            .field("provider_profile_version", &self.provider_profile_version)
            .field("provider_custom", &"<redacted>")
            .finish()
    }
}

/// Exact DNS-01 record requested by one ACME authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRecord {
    /// Stable idempotency identity persisted before provider invocation.
    pub publication_id: String,
    /// Original `_acme-challenge` owner.
    pub challenge_name: String,
    /// CNAME owner chain, including the original and final names.
    pub cname_chain: Vec<String>,
    /// Final TXT owner where the provider writes the value.
    pub name: String,
    /// Logical TXT value without presentation quotes.
    pub value: String,
    /// Requested TTL; provider may apply a documented minimum/default.
    pub ttl_seconds: Option<u32>,
}

/// Ownership classification for a published exact value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordOwnership {
    /// This publication created the exact DNS value.
    Created,
    /// The exact value existed before the publication.
    Preexisting,
}

/// Durable provider receipt for one publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    /// Stable provider-side exact-record identity.
    pub record_id: String,
    /// Whether cleanup may remove the record.
    pub ownership: RecordOwnership,
    /// Exact publication owner chosen when the DNS mutation occurred.
    pub record_name: String,
    /// CNAME chain resolved when the DNS mutation occurred.
    pub cname_chain: Vec<String>,
}

/// One completed cleanup result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupStatus {
    /// The owned record was removed.
    Removed,
    /// The existing value was not owned and was retained.
    Retained,
    /// The owned record was already absent.
    AlreadyAbsent,
}

/// One cleanup operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupRequest {
    /// Stable publication identity.
    pub publication_id: String,
    /// Saved exact-record receipt.
    pub receipt: PublicationReceipt,
    /// Original record tuple to verify exact ownership.
    pub record: DnsRecord,
}

/// One completed cleanup result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupResult {
    /// Publication ID from the request.
    pub publication_id: String,
    /// Exact cleanup outcome or one-record provider failure.
    pub result: Result<CleanupStatus, ProviderError>,
}

/// Cancellation and deadline shared by one provider invocation.
#[derive(Debug, Clone)]
pub struct ProviderExecution {
    /// Cooperative cancellation.
    pub cancellation: CancellationToken,
    /// Absolute monotonic deadline.
    pub deadline: Instant,
}

/// One publication result, including partial-batch errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentResult {
    /// Publication ID from the request.
    pub publication_id: String,
    /// Exact provider receipt or one-record provider failure.
    pub result: Result<PublicationReceipt, ProviderError>,
}

/// Whether a provider error may have changed remote DNS state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    /// The provider proves no DNS mutation occurred.
    None,
    /// The caller cannot prove whether DNS changed.
    Unknown,
}

/// Stable provider failure code from ADPP v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorCode {
    /// Request schema or field value is invalid.
    InvalidRequest,
    /// Provider does not support the requested protocol version.
    UnsupportedVersion,
    /// Provider does not support the requested action.
    UnsupportedAction,
    /// Requested profile is not configured by the external provider.
    ProviderNotConfigured,
    /// Provider could not load required credentials.
    CredentialsUnavailable,
    /// DNS service rejected the credential.
    AuthenticationFailed,
    /// Credential lacks permission for the DNS mutation.
    AuthorizationDenied,
    /// No authoritative DNS zone matched the record.
    ZoneNotFound,
    /// More than one DNS zone matched ambiguously.
    ZoneAmbiguous,
    /// Existing DNS data conflicts with the requested value.
    RecordConflict,
    /// DNS service throttled the operation.
    RateLimited,
    /// Provider dependency is unavailable.
    ProviderUnavailable,
    /// Provider operation timed out.
    ProviderTimeout,
    /// Cleanup ownership could not be proved.
    RecordNotOwned,
    /// Provider failure without a more specific stable code.
    InternalError,
}

impl std::fmt::Display for ProviderErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnsupportedAction => "unsupported_action",
            Self::ProviderNotConfigured => "provider_not_configured",
            Self::CredentialsUnavailable => "credentials_unavailable",
            Self::AuthenticationFailed => "authentication_failed",
            Self::AuthorizationDenied => "authorization_denied",
            Self::ZoneNotFound => "zone_not_found",
            Self::ZoneAmbiguous => "zone_ambiguous",
            Self::RecordConflict => "record_conflict",
            Self::RateLimited => "rate_limited",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::ProviderTimeout => "provider_timeout",
            Self::RecordNotOwned => "record_not_owned",
            Self::InternalError => "internal_error",
        })
    }
}

/// Structured provider failure. Messages are diagnostic and must be sanitized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{code}: {message}")]
#[serde(deny_unknown_fields)]
pub struct ProviderError {
    /// Stable protocol code.
    pub code: ProviderErrorCode,
    /// Short diagnostic without credentials or raw provider bodies.
    pub message: String,
    /// Side-effect classification for this exact operation.
    pub side_effect: SideEffect,
    /// Retry delay, valid only for rate limits and within 1..=86400.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
    /// Optional stable provider-specific diagnostic code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_code: Option<String>,
}

/// DNS provider operation surface shared by external and built-in adapters.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Publish or reconcile exact TXT values idempotently.
    async fn present(
        &self,
        context: &ProviderContext,
        records: &[DnsRecord],
        execution: &ProviderExecution,
    ) -> Result<Vec<PresentResult>, ProviderFailure>;

    /// Remove only exact records represented by saved receipts.
    async fn cleanup(
        &self,
        context: &ProviderContext,
        records: &[CleanupRequest],
        execution: &ProviderExecution,
    ) -> Result<Vec<CleanupResult>, ProviderFailure>;
}

/// Local process/ADPP failures are distinct from a DNS provider's wire error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HostErrorCode {
    /// Executable could not be started.
    #[error("process_spawn_failed")]
    ProcessSpawnFailed,
    /// Owned process invocation was cancelled.
    #[error("process_cancelled")]
    ProcessCancelled,
    /// Owned process deadline elapsed.
    #[error("process_timeout")]
    ProcessTimeout,
    /// Immediate child could not be observed.
    #[error("process_wait_failed")]
    ProcessWaitFailed,
    /// Child input pipe could not accept the full request.
    #[error("process_input_failed")]
    ProcessInputFailed,
    /// Child exited unsuccessfully.
    #[error("process_exit_nonzero")]
    ProcessExitNonzero,
    /// Output did not form one JSON response.
    #[error("response_invalid_json")]
    ResponseInvalidJson,
    /// Output did not match the correlated ADPP contract.
    #[error("response_invalid")]
    ResponseInvalid,
    /// Output exceeded the allowed bound.
    #[error("response_too_large")]
    ResponseTooLarge,
    /// Locally supplied request was invalid.
    #[error("request_invalid")]
    RequestInvalid,
}

/// A whole invocation failed before per-record results could be trusted.
#[derive(Debug, Error)]
pub enum ProviderFailure {
    /// Provider rejected the request before starting record operations.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Host process or ADPP validation failure; no provider code is invented.
    #[error("{code} (DNS side effect: {side_effect:?})")]
    Host {
        /// Stable local diagnostic.
        code: HostErrorCode,
        /// No side effect is claimed only when the child was not started.
        side_effect: SideEffect,
    },
}

#[cfg(test)]
mod tests;
