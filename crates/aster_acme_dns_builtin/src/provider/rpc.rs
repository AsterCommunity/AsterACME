//! Common wire helpers for native signed RPC APIs. No raw vendor messages escape.
#[cfg(any(feature = "aliyun", feature = "tencent_cloud"))]
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

#[cfg(any(feature = "aliyun", feature = "tencent_cloud"))]
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
    // A vendor error from a server failure or timeout does not prove rejection.
    let trusted_rejection = matches!(response.status, 200 | 400..=499) && response.status != 408;
    let (code, provider_code) = if trusted_rejection {
        recognized.map_or_else(
            || (status_code(response.status), None),
            |(code, name)| (code, Some(name.into())),
        )
    } else {
        (status_code(response.status), None)
    };
    let side_effect = possible_effect(mutation && !(trusted_rejection && provider_code.is_some()));
    let mut failure = error(
        code,
        "DNS API rejected or did not confirm the request",
        side_effect,
    );
    failure.provider_code = provider_code;
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

#[cfg(any(feature = "aliyun", feature = "tencent_cloud"))]
pub(super) fn decode<T: DeserializeOwned>(
    value: serde_json::Value,
    mutation: bool,
) -> Result<T, ProviderError> {
    serde_json::from_value(value).map_err(|_| invalid(mutation))
}
