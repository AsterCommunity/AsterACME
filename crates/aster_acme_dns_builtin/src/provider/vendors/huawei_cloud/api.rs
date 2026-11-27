//! HWS request signing and bounded API response interpretation.
//!
//! Signing behavior is cross-checked against the official SDK's test vectors
//! at the same pinned revision as the module-level API evidence in
//! `vendors/huawei_cloud.rs`:
//! <https://github.com/huaweicloud/huaweicloud-sdk-go-v3/blob/3da3be180a23bcbf8f6e668606c6ef26e76e95af/core/auth/signer/signer_test.go>
use crate::provider::common::rpc::{ApiErrorDetails, api_error, hex, hmac256, invalid};
use aster_acme_dns::{
    ProviderError, ProviderErrorCode,
    backend::configuration_error,
    operation::{HttpMethod, HttpRequest, HttpResponse},
};
use serde::Deserialize;
use serde_json::Value;
use url::Url;
pub(super) struct SignedRequest<'a> {
    pub(super) endpoint: &'a str,
    pub(super) method: HttpMethod,
    pub(super) path: &'a str,
    pub(super) query: &'a [(&'a str, &'a str)],
    pub(super) body: &'a [u8],
    pub(super) mutation: bool,
    pub(super) project_id: Option<&'a str>,
}

impl SignedRequest<'_> {
    pub(super) fn sign(
        &self,
        access_key: &str,
        secret: &str,
        date: &str,
    ) -> Result<HttpRequest, ProviderError> {
        if date.len() != 16 || !date.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(configuration_error("invalid HWS signature date"));
        }
        let canonical_query = canonical_query(self.query);
        let content_hash = crate::provider::common::rpc::sha256(self.body);
        let (signed_headers, canonical_headers) = self.project_id.map_or_else(
            || ("x-sdk-date", format!("x-sdk-date:{date}\n")),
            |id| {
                (
                    "x-project-id;x-sdk-date",
                    format!("x-project-id:{id}\nx-sdk-date:{date}\n"),
                )
            },
        );
        let canonical_uri = canonical_uri(self.path);
        let canonical = format!(
            "{}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{content_hash}",
            self.method.as_str()
        );
        let string_to_sign = format!(
            "SDK-HMAC-SHA256\n{date}\n{}",
            crate::provider::common::rpc::sha256(canonical.as_bytes())
        );
        let signature = hex(hmac256(secret.as_bytes(), string_to_sign.as_bytes()).as_ref());
        let mut url = format!("{}{}", self.endpoint, self.path);
        if !canonical_query.is_empty() {
            url.push('?');
            url.push_str(&canonical_query);
        }
        let mut headers = vec![
            ("content-type".into(), "application/json".into()),
            ("x-sdk-date".into(), date.to_owned()),
            (
                "authorization".into(),
                format!(
                    "SDK-HMAC-SHA256 Access={access_key}, SignedHeaders={signed_headers}, Signature={signature}"
                ),
            ),
        ];
        if let Some(id) = self.project_id {
            headers.push(("x-project-id".into(), id.into()));
        }
        Ok(HttpRequest {
            operation: None,
            method: self.method,
            url,
            headers,
            body: self.body.to_vec(),
            mutation: self.mutation,
        })
    }
}

pub(super) fn canonical_uri(path: &str) -> String {
    let encoded = path.split('/').map(percent).collect::<Vec<_>>().join("/");
    if encoded.ends_with('/') {
        encoded
    } else {
        format!("{encoded}/")
    }
}

pub(super) fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut values = query
        .iter()
        .map(|(key, value)| (percent(key), percent(value)))
        .collect::<Vec<_>>();
    values.sort();
    values
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent(value: &str) -> String {
    use std::fmt::Write;
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'~' | b'.') {
            output.push(char::from(byte));
        } else {
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

pub(super) fn marker_from_next(next: &str, endpoint: &str) -> Result<String, ProviderError> {
    let next = Url::parse(next).map_err(|_| invalid(false))?;
    let base = Url::parse(endpoint).map_err(|_| invalid(false))?;
    if next.scheme() != base.scheme() || next.host_str() != base.host_str() {
        return Err(invalid(false));
    }
    next.query_pairs()
        .find(|(key, _)| key == "marker")
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(false))
}

pub(super) fn payload(response: &HttpResponse, mutation: bool) -> Result<Value, ProviderError> {
    let body = serde_json::from_slice::<Value>(&response.body);
    let error_body = serde_json::from_slice::<ErrorBody>(&response.body).ok();
    let raw_code = error_body
        .as_ref()
        .and_then(|error| error.code.as_deref().or(error.error_code.as_deref()));
    let provider_code = raw_code.and_then(safe_huawei_error_code);
    let request_id = error_body
        .as_ref()
        .and_then(|error| error.request_id.as_deref())
        .and_then(safe_request_id);
    let structured = raw_code.is_some_and(|code| {
        code.starts_with("DNS.")
            || code.starts_with("APIG.")
            || code.starts_with("APIGW.")
            || code.starts_with("APIC.")
    });
    let recognized = if structured {
        match response.status {
            400 if matches!(raw_code, Some("DNS.0312" | "DNS.0016")) => {
                Some((ProviderErrorCode::RecordConflict, "HuaweiRecordConflict"))
            }
            400 => Some((ProviderErrorCode::InvalidRequest, "HuaweiInvalidRequest")),
            401 => Some((
                ProviderErrorCode::AuthenticationFailed,
                "HuaweiAuthenticationFailed",
            )),
            403 => Some((
                ProviderErrorCode::AuthorizationDenied,
                "HuaweiAuthorizationDenied",
            )),
            409 => Some((ProviderErrorCode::RecordConflict, "HuaweiRecordConflict")),
            429 => Some((ProviderErrorCode::RateLimited, "HuaweiRateLimited")),
            _ => None,
        }
    } else {
        None
    };
    if response.status / 100 != 2 || structured {
        return Err(api_error(
            response,
            mutation,
            ApiErrorDetails {
                classification: recognized,
                provider_code,
                request_id,
            },
        ));
    }
    if body.as_ref().is_ok_and(Value::is_object) {
        let body = body.map_err(|_| invalid(mutation))?;
        if body.get("code").is_some() || body.get("error_code").is_some() {
            return Err(invalid(mutation));
        }
        Ok(body)
    } else {
        Err(invalid(mutation))
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    code: Option<String>,
    error_code: Option<String>,
    #[serde(alias = "requestId")]
    request_id: Option<String>,
}

pub(super) fn safe_huawei_error_code(code: &str) -> Option<String> {
    let recognized_namespace = ["DNS.", "APIG.", "APIGW.", "APIC."].iter().any(|prefix| {
        code.strip_prefix(prefix).is_some_and(|suffix| {
            suffix.len() == 4 && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
    });
    (recognized_namespace
        || ((16..=128).contains(&code.len())
            && code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))))
    .then(|| code.to_owned())
}

pub(super) fn safe_request_id(id: &str) -> Option<String> {
    ((16..=128).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    .then(|| id.to_owned())
}

pub(super) fn decode_body<T: for<'de> Deserialize<'de>>(
    value: Value,
    mutation: bool,
) -> Result<T, ProviderError> {
    serde_json::from_value(value).map_err(|_| invalid(mutation))
}
