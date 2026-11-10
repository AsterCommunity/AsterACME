//! RFC 8555 §7.3 account request and response contracts.
use crate::jws::FlattenedJws;
use aster_acme_core::protocol::AccountStatus;
use serde::{Deserialize, Serialize};

/// Only-return-existing lookup is structurally separate from account creation.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindAccountRequest {
    /// The CA must not create an account when true.
    pub only_return_existing: bool,
}

/// New account payload; absent optional fields are omitted, not serialized as null.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountRequest<'a> {
    /// Contact URIs explicitly supplied by the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<&'a [String]>,
    /// Explicit agreement to the currently advertised terms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,
    /// Out-of-band account binding signed by external credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<&'a FlattenedJws>,
}

/// Account status update used for irreversible deactivation.
#[derive(Serialize)]
pub struct AccountStatusRequest {
    /// Requested status; clients use Deactivated for §7.3.6.
    pub status: AccountStatus,
}

/// Account object returned by the CA. Optional contact omission differs from an empty list.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountObject {
    /// Authoritative server state.
    pub status: AccountStatus,
    /// Optional contact URLs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
    /// EAB echoed when confirmed by a new-account response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<FlattenedJws>,
}
