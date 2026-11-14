//! Versioned ADPP JSON types; custom context is always redacted in Debug.
use aster_acme_dns::{
    ProviderContext, ProviderError, ProviderErrorCode, RecordOwnership, SideEffect,
};
use serde::{Deserialize, Serialize};

/// Selected operation for one child invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Publish or reconcile requested records.
    Present,
    /// Remove records represented by saved receipts.
    Cleanup,
}

/// ADPP request document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Protocol identifier.
    pub protocol: String,
    /// Wire protocol version.
    pub version: u32,
    /// Per-invocation correlation ID.
    pub request_id: String,
    /// Requested action.
    pub action: Action,
    /// Provider profile and custom values.
    pub context: ProviderContext,
    /// Batched DNS record operations.
    pub records: Vec<RequestRecord>,
}

/// Request record form for both present and cleanup actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRecord {
    /// Stable idempotency identity.
    pub publication_id: String,
    /// Original challenge owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_name: Option<String>,
    /// Resolved CNAME chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cname_chain: Vec<String>,
    /// Exact DNS record data for present, and ownership verification for cleanup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<RecordData>,
    /// Saved provider record ID for cleanup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    /// Saved ownership result for cleanup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<RecordOwnership>,
}

/// Exact TXT record passed over the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordData {
    /// DNS type; ADPP v1 currently permits TXT only.
    #[serde(rename = "type")]
    pub record_type: String,
    /// Absolute publication owner with trailing dot.
    pub name: String,
    /// Logical TXT value without presentation quotes.
    pub value: String,
    /// Optional requested TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
}

/// ADPP response document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Optional provider name for diagnostics, never interpreted as protocol identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    /// Optional provider implementation version, independent of wire version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_version: Option<String>,
    /// Protocol identifier.
    pub protocol: String,
    /// Wire protocol version.
    pub version: u32,
    /// Request correlation ID, copied exactly.
    pub request_id: String,
    /// Completed action, copied exactly.
    pub action: Action,
    /// One result per processed publication ID.
    pub results: Vec<RecordResult>,
    /// Request-level error; must be absent when record results are present.
    #[serde(deserialize_with = "required_error")]
    pub error: Option<WireError>,
}

/// One record result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordResult {
    /// Stable publication ID from the request.
    pub publication_id: String,
    /// Action result state.
    pub status: String,
    /// Provider record identity for a successful present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    /// Ownership for a successful present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<RecordOwnership>,
    /// Per-record provider failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<WireError>,
}

/// Wire error document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireError {
    /// Stable ADPP v1 provider error code.
    pub code: ProviderErrorCode,
    /// Short sanitized message.
    pub message: String,
    /// Whether the remote mutation may have happened.
    pub side_effect: SideEffect,
    /// Bounded retry hint for rate limits only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
    /// Optional provider-specific diagnostic code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_code: Option<String>,
}

impl From<WireError> for ProviderError {
    fn from(error: WireError) -> Self {
        Self {
            code: error.code,
            message: error.message,
            side_effect: error.side_effect,
            retry_after_seconds: error.retry_after_seconds,
            provider_code: error.provider_code,
        }
    }
}

fn required_error<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<WireError>, D::Error> {
    Option::<WireError>::deserialize(deserializer)
}
