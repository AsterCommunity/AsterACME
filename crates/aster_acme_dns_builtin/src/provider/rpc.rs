//! Common wire helpers for native signed RPC APIs. No raw vendor messages escape.
#[cfg(feature = "_individual-records")]
use aster_acme_dns::operation::HttpFailure;
use aster_acme_dns::{
    ProviderError, ProviderErrorCode, SideEffect, backend::configuration_error,
    operation::HttpResponse,
};
use aws_lc_rs::{digest, hmac};
use serde::de::DeserializeOwned;
use std::fmt::Write;

pub(super) fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

pub(super) fn hmac256(key: &[u8], bytes: &[u8]) -> hmac::Tag {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), bytes)
}

#[cfg(feature = "aliyun")]
pub(super) fn query(parameters: &[(&str, &str)]) -> String {
    fn encode(input: &str) -> String {
        let mut result = String::new();
        for byte in input.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                result.push(char::from(byte));
            } else {
                let _ = write!(result, "%{byte:02X}");
            }
        }
        result
    }
    let mut encoded: Vec<_> = parameters
        .iter()
        .map(|(name, value)| (encode(name), encode(value)))
        .collect();
    encoded.sort_unstable();
    encoded
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub(super) fn validate_keys(id: &str, secret: &str) -> Result<(), ProviderError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        || secret.is_empty()
        || secret.len() > 256
        || !secret.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(configuration_error("invalid DNS API key pair"));
    }
    Ok(())
}

pub(super) fn settings<T: DeserializeOwned>(
    config: &aster_acme_dns::backend::BackendConfig,
) -> Result<T, ProviderError> {
    if config.version != 1 || !config.executable.as_os_str().is_empty() || !config.args.is_empty() {
        return Err(configuration_error(
            "unsupported native DNS backend configuration",
        ));
    }
    serde_json::from_value(serde_json::Value::Object(config.custom.clone()))
        .map_err(|_| configuration_error("invalid native DNS backend settings"))
}

pub(super) const fn key_field(
    name: &'static str,
    label: &'static str,
) -> aster_acme_dns::backend::ConfigField {
    aster_acme_dns::backend::ConfigField {
        name,
        label,
        required: true,
        sensitive: true,
        kind: aster_acme_dns::backend::ConfigFieldKind::Text,
    }
}

pub(super) fn error(
    code: ProviderErrorCode,
    message: &'static str,
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

pub(super) fn invalid(mutation: bool) -> ProviderError {
    error(
        ProviderErrorCode::InternalError,
        "invalid or inconsistent DNS API response",
        possible_effect(mutation),
    )
}

pub(super) const fn possible_effect(mutation: bool) -> SideEffect {
    if mutation {
        SideEffect::Unknown
    } else {
        SideEffect::None
    }
}

#[cfg(feature = "_individual-records")]
pub(super) fn transport(failure: HttpFailure) -> ProviderError {
    error(
        failure.code,
        "DNS API HTTP exchange failed",
        failure.side_effect,
    )
}

pub(super) fn api_error(
    response: &HttpResponse,
    mutation: bool,
    recognized: Option<(ProviderErrorCode, &'static str)>,
) -> ProviderError {
    let body = serde_json::from_slice::<serde_json::Value>(&response.body).ok();
    let response_code = body.as_ref().and_then(safe_provider_code);
    let request_id = body.as_ref().and_then(safe_request_id);
    // A vendor error from a server failure or timeout does not prove rejection.
    let trusted_rejection = matches!(response.status, 200 | 400..=499) && response.status != 408;
    let provider_code = response_code.or_else(|| {
        trusted_rejection
            .then_some(recognized)
            .flatten()
            .map(|(_, name)| name.into())
    });
    let code = if trusted_rejection {
        recognized.map_or_else(|| status_code(response.status), |(code, _)| code)
    } else {
        status_code(response.status)
    };
    let side_effect = possible_effect(mutation && !(trusted_rejection && recognized.is_some()));
    let mut failure = ProviderError {
        code,
        message: api_message(
            response.status,
            provider_code.as_deref(),
            request_id.as_deref(),
        ),
        side_effect,
        retry_after_seconds: None,
        provider_code,
    };
    if code == ProviderErrorCode::RateLimited {
        failure.retry_after_seconds = Some(
            response
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                .filter_map(|(_, value)| {
                    let value = std::str::from_utf8(value).ok()?.trim();
                    value.parse::<u64>().ok().or_else(|| {
                        let date = httpdate::parse_http_date(value).ok()?;
                        let delta = date.duration_since(std::time::SystemTime::now()).ok()?;
                        Some(
                            delta
                                .as_secs()
                                .saturating_add(u64::from(delta.subsec_nanos() != 0)),
                        )
                    })
                })
                .max()
                .unwrap_or(60)
                .clamp(1, 86400),
        );
    }
    failure
}

fn api_message(status: u16, provider_code: Option<&str>, request_id: Option<&str>) -> String {
    let mut message = match provider_code {
        Some(provider_code) => format!(
            "DNS API rejected or did not confirm the request (HTTP {status}, provider code {provider_code})"
        ),
        None => format!(
            "DNS API rejected or did not confirm the request (HTTP {status}; provider code unavailable)"
        ),
    };
    if let Some(request_id) = request_id {
        use std::fmt::Write as _;
        let _ = write!(message, ", request ID {request_id}");
    }
    message
}

fn safe_provider_code(body: &serde_json::Value) -> Option<String> {
    let candidate = body
        .get("Code")
        .or_else(|| body.get("code"))
        .or_else(|| body.get("error_code"))
        .or_else(|| body.get("Error").and_then(|error| error.get("Code")))
        .or_else(|| {
            body.get("Response")
                .and_then(|response| response.get("Error"))
                .and_then(|error| error.get("Code"))
        })
        .and_then(serde_json::Value::as_str)?;
    if (16..=128).contains(&candidate.len())
        && (candidate.contains('.')
            || matches!(
                candidate,
                "MissingParameter"
                    | "InvalidParameter"
                    | "RequestLimitExceeded"
                    | "UnauthorizedOperation"
                    | "InternalError"
                    | "AuthFailure"
            ))
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Some(candidate.to_owned())
    } else {
        None
    }
}

fn safe_request_id(body: &serde_json::Value) -> Option<String> {
    let candidate = body
        .get("RequestId")
        .or_else(|| body.get("request_id"))
        .or_else(|| body.get("requestId"))
        .or_else(|| {
            body.get("Response")
                .and_then(|response| response.get("RequestId"))
        })
        .and_then(serde_json::Value::as_str)?;
    if (16..=128).contains(&candidate.len())
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Some(candidate.to_owned())
    } else {
        None
    }
}

fn status_code(status: u16) -> ProviderErrorCode {
    match status {
        401 => ProviderErrorCode::AuthenticationFailed,
        403 => ProviderErrorCode::AuthorizationDenied,
        408 => ProviderErrorCode::ProviderTimeout,
        429 => ProviderErrorCode::RateLimited,
        500..=599 => ProviderErrorCode::ProviderUnavailable,
        _ => ProviderErrorCode::InternalError,
    }
}

#[cfg(feature = "_individual-records")]
pub(super) fn decode<T: DeserializeOwned>(
    value: serde_json::Value,
    mutation: bool,
) -> Result<T, ProviderError> {
    serde_json::from_value(value).map_err(|_| invalid(mutation))
}

#[cfg(test)]
mod tests {
    use super::{api_error, safe_provider_code, safe_request_id};
    use aster_acme_dns::{ProviderErrorCode, SideEffect, operation::HttpResponse};
    use serde_json::json;

    #[test]
    fn provider_api_errors_keep_safe_vendor_codes_without_echoing_messages() {
        let response = HttpResponse {
            status: 400,
            headers: Vec::new(),
            body: serde_json::to_vec(&json!({
                "Response": {
                    "Error": {
                        "Code": "InvalidParameterValue.DomainId",
                        "Message": "secret-key-must-never-appear"
                    }
                }
            }))
            .unwrap(),
        };
        let error = api_error(&response, false, None);
        assert_eq!(error.code, ProviderErrorCode::InternalError);
        assert_eq!(
            error.provider_code.as_deref(),
            Some("InvalidParameterValue.DomainId")
        );
        assert_eq!(error.side_effect, SideEffect::None);
        assert!(error.message.contains("HTTP 400"));
        assert!(error.message.contains("InvalidParameterValue.DomainId"));
        assert!(!error.message.contains("secret-key"));
    }

    #[test]
    fn unsafe_vendor_codes_are_not_exposed() {
        let body = json!({"code": "bad code\nwith secret"});
        assert_eq!(safe_provider_code(&body), None);
        assert_eq!(safe_provider_code(&json!({"code": "dummysecret"})), None);
    }

    #[test]
    fn provider_errors_include_safe_request_ids_but_reject_arbitrary_values() {
        assert_eq!(
            safe_request_id(&json!({"Response":{"RequestId":"req-123_abcdefghijk"}})).as_deref(),
            Some("req-123_abcdefghijk")
        );
        assert_eq!(safe_request_id(&json!({"RequestId":"secret value"})), None);
    }
}
