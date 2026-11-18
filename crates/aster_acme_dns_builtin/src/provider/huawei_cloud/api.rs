//! HWS request signing and bounded API response interpretation.
use crate::provider::rpc::{api_error, hex, hmac256, invalid};
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
        let content_hash = crate::provider::rpc::sha256(self.body);
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
            crate::provider::rpc::sha256(canonical.as_bytes())
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
    let structured = body
        .as_ref()
        .ok()
        .and_then(|body| body.get("code").or_else(|| body.get("error_code")))
        .and_then(Value::as_str)
        .is_some_and(|code| {
            code.starts_with("DNS.") || code.starts_with("APIG.") || code.starts_with("APIC.")
        });
    let recognized = if structured {
        Some(match response.status {
            400 => (ProviderErrorCode::InvalidRequest, "HuaweiInvalidRequest"),
            401 => (
                ProviderErrorCode::AuthenticationFailed,
                "HuaweiAuthenticationFailed",
            ),
            403 => (
                ProviderErrorCode::AuthorizationDenied,
                "HuaweiAuthorizationDenied",
            ),
            409 => (ProviderErrorCode::RecordConflict, "HuaweiRecordConflict"),
            429 => (ProviderErrorCode::RateLimited, "HuaweiRateLimited"),
            _ => return Err(api_error(response, mutation, None)),
        })
    } else {
        None
    };
    if response.status / 100 == 2 && body.as_ref().is_ok_and(Value::is_object) {
        let body = body.map_err(|_| invalid(mutation))?;
        if body.get("code").is_some() || body.get("error_code").is_some() {
            return Err(invalid(mutation));
        }
        Ok(body)
    } else {
        Err(api_error(response, mutation, recognized))
    }
}

pub(super) fn decode_body<T: for<'de> Deserialize<'de>>(
    value: Value,
    mutation: bool,
) -> Result<T, ProviderError> {
    serde_json::from_value(value).map_err(|_| invalid(mutation))
}
