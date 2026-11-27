//! Google DNS v1 wire types and redacted error classification.
//!
//! The [v1 discovery document](https://dns.googleapis.com/$discovery/rest?version=v1)
//! declares `RRset` TTL as `int32`, change IDs server-generated/read-only, and `done` as
//! the authoritative-update request being sent. The [changes API](https://cloud.google.com/dns/docs/reference/v1/changes/create)
//! requires each deletion to match existing data exactly.
use crate::provider::common::{
    rpc::{ApiErrorDetails, api_error, invalid},
    txt::txt_decode,
};
use crate::provider::vendors::google_cloud_dns::safe_id;
use aster_acme_dns::{
    ProviderError, ProviderErrorCode, operation::HttpResponse, routing::absolute_name,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Zone {
    pub id: String,
    #[serde(rename = "dnsName")]
    pub dns_name: String,
    pub visibility: String,
}

#[derive(Deserialize)]
pub(super) struct Zones {
    #[serde(default, rename = "managedZones")]
    pub zones: Vec<Zone>,
    #[serde(default, rename = "nextPageToken")]
    pub next: String,
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub(super) struct Rrset {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// Google DNS v1 discovery defines this field as `int32`.
    pub ttl: u32,
    #[serde(deserialize_with = "unique_values")]
    pub rrdatas: BTreeSet<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn unique_values<'de, D: serde::Deserializer<'de>>(input: D) -> Result<BTreeSet<String>, D::Error> {
    let values = Vec::<String>::deserialize(input)?;
    let count = values.len();
    let unique = values.into_iter().collect::<BTreeSet<_>>();
    if unique.len() != count {
        return Err(serde::de::Error::custom("duplicate RRset values"));
    }
    Ok(unique)
}

impl Rrset {
    pub fn validate(&self, owner: &str) -> Result<(), ProviderError> {
        // The discovery schema defines TTL as signed int32 (0..=2^31-1).
        if absolute_name(&self.name).ok().as_deref() != Some(owner)
            || self.kind != "TXT"
            || self.ttl > 2_147_483_647
            || self.rrdatas.is_empty()
            || self.rrdatas.len() > 100
            || self.extra.contains_key("routingPolicy")
            || self.extra.contains_key("signatureRrdatas")
            || self
                .rrdatas
                .iter()
                .any(|v| v.len() > 4096 || google_txt_decode(v).is_none())
        {
            return Err(invalid(false));
        }
        Ok(())
    }

    pub fn matches(&self, value: &str) -> Result<Option<String>, ProviderError> {
        let matches: Vec<_> = self
            .rrdatas
            .iter()
            .filter(|wire| google_txt_decode(wire).as_deref() == Some(value.as_bytes()))
            .collect();
        if matches.len() > 1 {
            return Err(invalid(false));
        }
        Ok(matches.first().map(|v| (*v).clone()))
    }
}

// Cloud DNS accepts both quoted and unquoted character strings. Normalize one
// chunk at a time while retaining the shared decoder's escape and size checks.
fn google_txt_decode(value: &str) -> Option<Vec<u8>> {
    let mut input = value.char_indices().peekable();
    let mut decoded = Vec::new();
    let mut chunks = 0;
    while input.peek().is_some() {
        while input.peek().is_some_and(|(_, ch)| ch.is_ascii_whitespace()) {
            input.next();
        }
        let Some((start, first)) = input.next() else {
            break;
        };
        let quoted = first == '"';
        let mut end = start + first.len_utf8();
        let mut escaped = first == '\\';
        let mut closed = false;
        while let Some(&(index, ch)) = input.peek() {
            if !quoted && !escaped && ch.is_ascii_whitespace() {
                break;
            }
            input.next();
            end = index + ch.len_utf8();
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                if !quoted {
                    return None;
                }
                closed = true;
                break;
            }
        }
        if quoted && !closed {
            return None;
        }
        if quoted
            && input
                .peek()
                .is_some_and(|(_, ch)| !ch.is_ascii_whitespace())
        {
            return None;
        }
        let wire = &value[start..end];
        let chunk = if quoted {
            txt_decode(wire)?
        } else {
            txt_decode(&format!("\"{wire}\""))?
        };
        decoded.extend(chunk);
        chunks += 1;
    }
    (chunks > 0).then_some(decoded)
}

#[derive(Deserialize)]
pub(super) struct Rrsets {
    #[serde(default)]
    pub rrsets: Vec<Rrset>,
    #[serde(default, rename = "nextPageToken")]
    pub next: String,
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub additions: Vec<Rrset>,
    /// Google `changes.create` requires each deletion to exactly match existing data.
    pub deletions: Vec<Rrset>,
}

#[derive(Deserialize)]
pub(super) struct Change {
    /// Server-generated, read-only ID according to the v1 discovery schema.
    pub id: String,
    /// `done` means the authoritative update request was sent, not globally propagated.
    pub status: String,
    #[serde(default)]
    pub additions: Vec<Rrset>,
    #[serde(default)]
    pub deletions: Vec<Rrset>,
}

impl Change {
    pub fn verifies(&self, plan: &Plan) -> bool {
        // `id` and `status` semantics are server-owned in the v1 discovery schema;
        // `done` does not mean the change has propagated to public resolvers.
        safe_id(&self.id)
            && matches!(self.status.as_str(), "pending" | "done")
            && equivalent(&self.additions, &plan.additions)
            && equivalent(&self.deletions, &plan.deletions)
    }
}

fn equivalent(left: &[Rrset], right: &[Rrset]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).all(|(a, b)| {
        a.name == b.name
            && a.kind == b.kind
            && a.ttl == b.ttl
            && a.rrdatas == b.rrdatas
            && a.extra
                .iter()
                .filter(|(k, _)| k.as_str() != "kind")
                .eq(b.extra.iter().filter(|(k, _)| k.as_str() != "kind"))
    })
}

#[derive(Deserialize)]
struct Envelope {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    errors: Vec<Reason>,
}

#[derive(Deserialize)]
struct Reason {
    reason: String,
}

pub(super) fn failure(response: &HttpResponse, mutation: bool) -> ProviderError {
    let reason = serde_json::from_slice::<Envelope>(&response.body)
        .ok()
        .and_then(|e| e.error.errors.first().map(|r| r.reason.clone()));
    let classification = match (response.status, reason.as_deref()) {
        (400 | 409 | 412, Some("preconditionFailed" | "alreadyExists")) => {
            Some((ProviderErrorCode::RecordConflict, "preconditionFailed"))
        }
        (
            400,
            Some("invalid" | "invalidParameter" | "invalidValue" | "badRequest" | "required"),
        ) => Some((ProviderErrorCode::InvalidRequest, "invalidRequest")),
        (401, Some("authError" | "unauthorized" | "invalidCredentials")) => {
            Some((ProviderErrorCode::AuthenticationFailed, "unauthenticated"))
        }
        (403 | 429, Some("rateLimitExceeded" | "userRateLimitExceeded" | "quotaExceeded")) => {
            Some((ProviderErrorCode::RateLimited, "rateLimitExceeded"))
        }
        (403, Some("forbidden" | "insufficientPermissions" | "accessNotConfigured")) => {
            Some((ProviderErrorCode::AuthorizationDenied, "forbidden"))
        }
        (404, Some("notFound")) => Some((ProviderErrorCode::InvalidRequest, "notFound")),
        _ => None,
    };
    let mut failure = api_error(
        response,
        mutation,
        ApiErrorDetails {
            classification,
            provider_code: classification.map(|(_, s)| s.into()),
            request_id: None,
        },
    );
    if response.status == 400 && classification.is_none() {
        failure.code = ProviderErrorCode::InvalidRequest;
    }
    failure
}

pub(super) fn decode<T: DeserializeOwned>(
    response: &HttpResponse,
    mutation: bool,
) -> Result<T, ProviderError> {
    if response.status != 200 {
        return Err(failure(response, mutation));
    }
    serde_json::from_slice(&response.body).map_err(|_| invalid(mutation))
}
