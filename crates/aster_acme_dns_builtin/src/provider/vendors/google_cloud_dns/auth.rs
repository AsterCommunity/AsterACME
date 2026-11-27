//! OAuth service-account JWT exchange. Tokens live only in factory memory.
//!
//! Follows [Google's service-account OAuth profile](https://developers.google.com/identity/protocols/oauth2/service-account)
//! and [RFC 6749 §5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1) token responses.
use crate::provider::vendors::google_cloud_dns::ServiceAccount;
use aster_acme_dns::{
    ProviderError,
    backend::configuration_error,
    operation::{HttpMethod, HttpRequest},
};
use aws_lc_rs::{rand::SystemRandom, rsa::KeyPair, signature::RSA_PKCS1_SHA256};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub(super) const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

pub(super) struct Token {
    pub value: Zeroizing<String>,
    pub expires: Instant,
}

pub(super) fn key(account: &ServiceAccount) -> Result<KeyPair, ProviderError> {
    if account.private_key.len() > 16384 {
        return Err(configuration_error(
            "Google private key exceeds the supported size",
        ));
    }
    let pem = account.private_key.trim();
    let inner = pem
        .strip_prefix("-----BEGIN PRIVATE KEY-----")
        .and_then(|s| s.strip_suffix("-----END PRIVATE KEY-----"))
        .ok_or_else(|| {
            configuration_error("Google service account requires a PKCS8 RSA private key")
        })?;
    let text = Zeroizing::new(
        inner
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    );
    let bytes = Zeroizing::new(
        STANDARD
            .decode(text.as_bytes())
            .map_err(|_| configuration_error("invalid Google private key encoding"))?,
    );
    let key = KeyPair::from_pkcs8(&bytes)
        .map_err(|_| configuration_error("invalid Google RSA private key"))?;
    if !(256..=512).contains(&key.public_modulus_len()) {
        return Err(configuration_error(
            "Google RSA key must be 2048 to 4096 bits",
        ));
    }
    Ok(key)
}

#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    typ: &'static str,
    kid: &'a str,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    scope: &'static str,
    aud: &'static str,
    iat: i64,
    exp: i64,
}

pub(super) fn request(account: &ServiceAccount, now: i64) -> Result<HttpRequest, ProviderError> {
    let header = serde_json::to_vec(&Header {
        alg: "RS256",
        typ: "JWT",
        kid: &account.private_key_id,
    })
    .map_err(|_| configuration_error("cannot encode Google JWT header"))?;
    let claims = serde_json::to_vec(&Claims {
        iss: &account.client_email,
        scope: "https://www.googleapis.com/auth/ndev.clouddns.readwrite",
        aud: TOKEN_URL,
        iat: now,
        exp: now + 3600,
    })
    .map_err(|_| configuration_error("cannot encode Google JWT claims"))?;
    let key = key(account)?;
    let mut input = Zeroizing::new(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    ));
    let mut signature = vec![0; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .map_err(|_| configuration_error("cannot sign Google JWT"))?;
    input.push('.');
    input.push_str(&URL_SAFE_NO_PAD.encode(signature));
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
        .append_pair("assertion", &input)
        .finish()
        .into_bytes();
    Ok(HttpRequest {
        operation: Some("ExchangeToken".into()),
        method: HttpMethod::Post,
        url: TOKEN_URL.into(),
        headers: vec![(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        )],
        body,
        mutation: false,
    })
}

#[derive(Deserialize)]
struct Response {
    access_token: String,
    /// RFC 6749 §5.1 requires case-insensitive comparison of this token type.
    token_type: String,
    /// RFC 6749 §5.1 lifetime; requests refresh sixty seconds before this expires.
    expires_in: u64,
}

pub(super) fn token(body: &[u8]) -> Result<Token, ProviderError> {
    let response: Response = serde_json::from_slice(body)
        .map_err(|_| configuration_error("invalid Google token response"))?;
    let value = Zeroizing::new(response.access_token);
    if !response.token_type.eq_ignore_ascii_case("Bearer")
        || !(61..=3600).contains(&response.expires_in)
        || value.is_empty()
        || value.len() > 16384
        || !value.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(configuration_error(
            "invalid Google access token or expiration",
        ));
    }
    // Refresh 60 seconds before expires_in, leaving time for the next request.
    Ok(Token {
        value,
        expires: Instant::now() + Duration::from_secs(response.expires_in - 60),
    })
}
