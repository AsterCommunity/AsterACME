//! RFC 8555 sections 7.1.3–7.1.5, 7.4 and 7.5 wire resources and requests.
use crate::{problem::Problem, url::AcmeUrl};
use aster_acme_core::protocol::{AuthorizationStatus, ChallengeStatus, OrderStatus};
use aster_forge_macros::wire_enum;
use serde::{Deserialize, Serialize};

wire_enum! {
    /// Challenge methods advertised by a CA; unknown extensions remain lossless.
    pub enum WireChallengeKind {
        /// HTTP token publication.
        Http01 => "http-01",
        /// DNS TXT publication.
        Dns01 => "dns-01",
        /// Dedicated TLS ALPN response.
        TlsAlpn01 => "tls-alpn-01",
    }
}

/// Identifier as transmitted by the CA; execution validation belongs to the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireIdentifier {
    /// Registry identifier type.
    #[serde(rename = "type")]
    pub kind: String,
    /// Exact identifier value.
    pub value: String,
}

/// Complete newOrder payload. Requested certificate dates are omitted by this client.
#[derive(Serialize)]
pub struct NewOrderRequest<'a> {
    /// Requested DNS identifiers, preserving primary-domain order.
    pub identifiers: &'a [WireIdentifier],
}

/// CSR encoded as unpadded base64url DER (RFC 8555 section 7.4).
#[derive(Serialize)]
pub struct FinalizeRequest<'a> {
    /// Stable, already persisted CSR.
    pub csr: &'a str,
}

/// Challenge acknowledgement is an empty object, unlike POST-as-GET's empty payload.
#[derive(Serialize)]
pub struct AcknowledgeRequest {}

/// CA order resource. Optional dates are parsed strictly as RFC 3339.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderObject {
    /// Authoritative CA lifecycle state.
    pub status: OrderStatus,
    /// Required by RFC 8555 for pending and valid orders; checked by the client.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires: Option<time::OffsetDateTime>,
    /// Identifiers authorized by this order.
    pub identifiers: Vec<WireIdentifier>,
    /// Authorization resource URLs, not constructed paths.
    pub authorizations: Vec<AcmeUrl>,
    /// CSR submission endpoint.
    pub finalize: AcmeUrl,
    /// Issued certificate URL when available.
    pub certificate: Option<AcmeUrl>,
    /// Optional CA explanation for an invalid order.
    pub error: Option<Problem>,
}

/// CA authorization resource; wildcard values omit the `*.` prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationObject {
    /// Exact wire identifier.
    pub identifier: WireIdentifier,
    /// CA authorization lifecycle state.
    pub status: AuthorizationStatus,
    /// A valid authorization must include its expiry.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires: Option<time::OffsetDateTime>,
    /// Wildcard authorization flag, absent means false.
    #[serde(default)]
    pub wildcard: bool,
    /// Offered challenges; unsupported methods are retained.
    pub challenges: Vec<ChallengeObject>,
}

/// CA challenge resource, including optional validation failure details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeObject {
    /// Advertised challenge type.
    #[serde(rename = "type")]
    pub kind: WireChallengeKind,
    /// Challenge resource URL.
    pub url: AcmeUrl,
    /// Authoritative challenge lifecycle state.
    pub status: ChallengeStatus,
    /// Optional validation failure.
    pub error: Option<Problem>,
    /// Method-specific fields. RFC 8555 section 7.1.5 does not require every method
    /// to have a token; unsupported methods retain their complete extension data.
    #[serde(flatten)]
    pub parameters: std::collections::BTreeMap<String, serde_json::Value>,
}
