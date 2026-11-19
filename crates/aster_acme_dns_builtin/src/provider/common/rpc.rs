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

pub(in crate::provider) fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

pub(in crate::provider) fn sha256(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

pub(in crate::provider) fn hmac256(key: &[u8], bytes: &[u8]) -> hmac::Tag {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), bytes)
}

pub(in crate::provider) fn validate_keys(id: &str, secret: &str) -> Result<(), ProviderError> {
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

pub(in crate::provider) fn settings<T: DeserializeOwned>(
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

pub(in crate::provider) const fn key_field(
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

pub(in crate::provider) fn error(
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

pub(in crate::provider) fn invalid(mutation: bool) -> ProviderError {
    error(
        ProviderErrorCode::InternalError,
        "invalid or inconsistent DNS API response",
        possible_effect(mutation),
    )
}

pub(in crate::provider) const fn possible_effect(mutation: bool) -> SideEffect {
    if mutation {
        SideEffect::Unknown
    } else {
        SideEffect::None
    }
}

#[cfg(feature = "_individual-records")]
pub(in crate::provider) fn transport(failure: HttpFailure) -> ProviderError {
    error(
        failure.code,
        "DNS API HTTP exchange failed",
        failure.side_effect,
    )
}

pub(in crate::provider) struct ApiErrorDetails {
    pub classification: Option<(ProviderErrorCode, &'static str)>,
    pub provider_code: Option<String>,
    pub request_id: Option<String>,
}

pub(in crate::provider) fn api_error(
    response: &HttpResponse,
    mutation: bool,
    details: ApiErrorDetails,
) -> ProviderError {
    // A vendor error from a server failure or timeout does not prove rejection.
    let trusted_rejection = matches!(response.status, 200 | 400..=499) && response.status != 408;
    let provider_code = details.provider_code.or_else(|| {
        trusted_rejection
            .then_some(details.classification)
            .flatten()
            .map(|(_, name)| name.into())
    });
    let code = if trusted_rejection {
        details
            .classification
            .map_or_else(|| status_code(response.status), |(code, _)| code)
    } else {
        status_code(response.status)
    };
    let side_effect =
        possible_effect(mutation && !(trusted_rejection && details.classification.is_some()));
    let mut failure = ProviderError {
        code,
        message: api_message(
            response.status,
            provider_code.as_deref(),
            details.request_id.as_deref(),
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
pub(in crate::provider) fn decode<T: DeserializeOwned>(
    value: serde_json::Value,
    mutation: bool,
) -> Result<T, ProviderError> {
    serde_json::from_value(value).map_err(|_| invalid(mutation))
}

#[cfg(test)]
mod tests {
    use crate::provider::common::rpc::{
        ApiErrorDetails, api_error, key_field, settings, validate_keys,
    };
    use aster_acme_dns::{
        ProviderErrorCode, SideEffect, backend::BackendConfig, operation::HttpResponse,
    };
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn provider_api_errors_format_only_prevalidated_details() {
        let response = HttpResponse {
            status: 400,
            headers: Vec::new(),
            body: b"provider-specific raw message".to_vec(),
        };
        let error = api_error(
            &response,
            false,
            ApiErrorDetails {
                classification: Some((ProviderErrorCode::InvalidRequest, "InvalidRequest")),
                provider_code: Some("ExampleProvider.ValidationError".into()),
                request_id: Some("req-1234567890123456".into()),
            },
        );
        assert_eq!(error.code, ProviderErrorCode::InvalidRequest);
        assert_eq!(
            error.provider_code.as_deref(),
            Some("ExampleProvider.ValidationError")
        );
        assert_eq!(error.side_effect, SideEffect::None);
        assert!(error.message.contains("HTTP 400"));
        assert!(error.message.contains("ExampleProvider.ValidationError"));
        assert!(error.message.contains("req-1234567890123456"));
        assert!(!error.message.contains("provider-specific raw message"));
    }

    #[test]
    fn key_and_native_settings_boundaries_fail_closed() {
        assert!(validate_keys("", "secret").is_err());
        assert!(validate_keys(&"a".repeat(129), "secret").is_err());
        assert!(validate_keys("bad key", "secret").is_err());
        assert!(validate_keys("valid", "").is_err());
        assert!(validate_keys("valid", "bad\nsecret").is_err());
        assert!(validate_keys("valid", "secret").is_ok());

        let mut config = BackendConfig::default();
        assert!(settings::<serde_json::Value>(&config).is_ok());
        config.version = 2;
        assert!(settings::<serde_json::Value>(&config).is_err());
        config.version = 1;
        config.executable = PathBuf::from("/tmp/provider");
        assert!(settings::<serde_json::Value>(&config).is_err());
        config.executable.clear();
        config.args.push("--flag".into());
        assert!(settings::<serde_json::Value>(&config).is_err());
    }

    #[test]
    fn api_error_status_and_retry_header_boundaries_are_typed() {
        for (status, code) in [
            (401, ProviderErrorCode::AuthenticationFailed),
            (403, ProviderErrorCode::AuthorizationDenied),
            (408, ProviderErrorCode::ProviderTimeout),
            (429, ProviderErrorCode::RateLimited),
            (503, ProviderErrorCode::ProviderUnavailable),
            (301, ProviderErrorCode::InternalError),
        ] {
            let mut response = HttpResponse {
                status,
                headers: vec![],
                body: b"{}".to_vec(),
            };
            if status == 429 {
                response.headers = vec![("Retry-After".into(), b"0".to_vec())];
            }
            let error = api_error(
                &response,
                true,
                ApiErrorDetails {
                    classification: None,
                    provider_code: None,
                    request_id: None,
                },
            );
            assert_eq!(error.code, code);
            assert_eq!(error.side_effect, SideEffect::Unknown);
            if status == 429 {
                assert_eq!(error.retry_after_seconds, Some(1));
            }
        }
        let mut response = HttpResponse {
            status: 429,
            headers: vec![(
                "Retry-After".into(),
                b"Wed, 21 Oct 2037 07:28:00 GMT".to_vec(),
            )],
            body: json!({"RequestId":"req-1234567890123456"})
                .to_string()
                .into_bytes(),
        };
        let error = api_error(
            &response,
            true,
            ApiErrorDetails {
                classification: None,
                provider_code: None,
                request_id: Some("req-1234567890123456".into()),
            },
        );
        assert!(error.message.contains("request ID"));
        response.headers = vec![("Retry-After".into(), b"not-a-date".to_vec())];
        assert_eq!(
            api_error(
                &response,
                true,
                ApiErrorDetails {
                    classification: None,
                    provider_code: None,
                    request_id: None,
                },
            )
            .retry_after_seconds,
            Some(60)
        );
        assert!(key_field("id", "label").sensitive);
        let response = HttpResponse {
            status: 500,
            headers: vec![],
            body: b"private raw message".to_vec(),
        };
        let error = api_error(
            &response,
            false,
            ApiErrorDetails {
                classification: None,
                provider_code: Some("ProviderFailure.Code".into()),
                request_id: None,
            },
        );
        assert_eq!(error.provider_code.as_deref(), Some("ProviderFailure.Code"));
        assert!(error.message.contains("ProviderFailure.Code"));
        assert!(!error.message.contains("private raw message"));
    }
}
