//! RFC 8555 HTTPS discovery, bounded responses, nonce consumption and signed POSTs.

use std::{
    collections::VecDeque,
    time::{Duration, SystemTime},
};

use reqwest::{
    Method, StatusCode,
    header::{HeaderMap, LOCATION, RETRY_AFTER},
};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::crypto::{AccountSigner, CryptoError, sign_request};

use aster_acme_protocol::{
    directory::Directory,
    jws::RequestIdentity,
    problem::{BAD_NONCE, Problem},
    url::AcmeUrl,
};

const MAX_BODY_BYTES: usize = 1024 * 1024;
const NONCE_POOL_CAPACITY: usize = 64;

/// Retry information returned to callers, never an instruction for unbounded retries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryAfter {
    /// Delay in seconds from the response.
    Delay(Duration),
    /// Absolute HTTP-date.
    At(SystemTime),
}

/// Transport or protocol failure. Raw bodies and signed requests are not included.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Resource URL is not safe for ACME transport.
    #[error("invalid ACME URL: require HTTPS without credentials or fragments")]
    InvalidUrl(#[from] aster_acme_protocol::url::InvalidAcmeUrl),
    /// Plaintext loopback requests need explicit test configuration.
    #[error("loopback HTTP requires explicit test-only opt-in")]
    InsecureTransport,
    /// Invalid request policy.
    #[error("timeout must be nonzero and badNonce retries must not exceed 5")]
    InvalidOptions,
    /// Invalid custom HTTP User-Agent.
    #[error("invalid User-Agent; use 1 to 512 printable characters")]
    InvalidUserAgent,
    /// Underlying network failure; mutations may already have happened remotely.
    #[error("ACME network request failed: {0}")]
    Network(#[from] reqwest::Error),
    /// Bounded response exceeded its allowed size.
    #[error("ACME response exceeds the 1 MiB limit")]
    BodyTooLarge,
    /// Response was not the expected JSON shape.
    #[error("invalid ACME JSON response: {0}")]
    Json(#[from] serde_json::Error),
    /// No valid replay nonce was available.
    #[error("ACME response did not provide a valid Replay-Nonce")]
    MissingNonce,
    /// Account resource location is required for durable identity.
    #[error("ACME account response is missing a valid Location URL")]
    MissingLocation,
    /// An ACME error response, preserving problem and rate-limit metadata.
    #[error("ACME HTTP {status}: {problem:?}; retry-after: {retry_after:?}")]
    Problem {
        /// HTTP status independent of any problem JSON status field.
        status: u16,
        /// Structured problem including unknown extensions.
        problem: Box<Problem>,
        /// Parsed retry information.
        retry_after: Option<RetryAfter>,
    },
    /// Non-problem HTTP response or unexpected success status.
    #[error("unexpected ACME HTTP status {status}; retry-after: {retry_after:?}")]
    HttpStatus {
        /// HTTP status.
        status: u16,
        /// Parsed retry information.
        retry_after: Option<RetryAfter>,
    },
    /// Cryptographic request construction failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl TransportError {
    /// Match a complete ACME problem URI; unknown errors do not trigger known behavior.
    #[must_use]
    pub fn is_problem(&self, kind: &str) -> bool {
        match self {
            Self::Problem { problem, .. } => problem.kind == kind,
            _ => false,
        }
    }
}

/// Explicit request budget and local-testing policy.
#[derive(Debug, Clone)]
pub struct TransportOptions {
    /// Entire request timeout, including response body reading.
    pub request_timeout: Duration,
    /// Retries only for protocol badNonce responses, with fresh signatures.
    pub bad_nonce_retries: u8,
    /// Permit numeric loopback HTTP (mock/Pebble testing only).
    pub allow_loopback_http: bool,
    /// Optional RFC 9110 product token/comment string. Defaults to this crate's name/version.
    pub user_agent: Option<String>,
}
impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            bad_nonce_retries: 2,
            allow_loopback_http: false,
            user_agent: None,
        }
    }
}

/// Account-oriented ACME transport with a concurrency-safe bounded nonce pool.
pub struct AcmeClient {
    http: reqwest::Client,
    directory_url: AcmeUrl,
    pub(crate) directory: Directory,
    options: TransportOptions,
    nonces: Mutex<VecDeque<String>>,
}

pub(crate) struct AcmeResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl AcmeClient {
    /// Discover a CA using verified TLS, without redirects or automatic mutation retries.
    ///
    /// # Errors
    /// Reports unsafe endpoints, HTTP/JSON failures or an oversized directory.
    pub async fn discover(
        directory_url: AcmeUrl,
        options: TransportOptions,
    ) -> Result<Self, TransportError> {
        if options.request_timeout.is_zero() || options.bad_nonce_retries > 5 {
            return Err(TransportError::InvalidOptions);
        }
        check_transport(&directory_url, &options)?;
        let http = crate::http_client::build(&options)?;
        let response = read_response(http.get(directory_url.as_str()).send().await?).await?;
        if response.status != StatusCode::OK {
            return Err(response_error(&response));
        }
        let directory: Directory = serde_json::from_slice(&response.body)?;
        check_transport(&directory.new_nonce, &options)?;
        check_transport(&directory.new_account, &options)?;
        let client = Self {
            http,
            directory_url,
            directory,
            options,
            nonces: Mutex::new(VecDeque::new()),
        };
        client.remember_nonce(nonce(&response.headers)).await;
        Ok(client)
    }

    /// Discovered directory and its current metadata.
    #[must_use]
    pub fn directory(&self) -> &Directory {
        &self.directory
    }
    /// Exact configured directory URL, also used to scope local account storage.
    #[must_use]
    pub fn directory_url(&self) -> &AcmeUrl {
        &self.directory_url
    }

    async fn remember_nonce(&self, nonce: Option<String>) {
        if let Some(nonce) = nonce {
            let mut pool = self.nonces.lock().await;
            if pool.len() < NONCE_POOL_CAPACITY && !pool.contains(&nonce) {
                pool.push_back(nonce);
            }
        }
    }

    async fn take_nonce(&self) -> Result<String, TransportError> {
        if let Some(nonce) = self.nonces.lock().await.pop_front() {
            return Ok(nonce);
        }
        let response = self
            .http
            .request(Method::HEAD, self.directory.new_nonce.as_str())
            .send()
            .await?;
        let status = response.status();
        if status != StatusCode::OK && status != StatusCode::NO_CONTENT {
            return Err(response_error(&read_response(response).await?));
        }
        nonce(response.headers()).ok_or(TransportError::MissingNonce)
    }

    pub(crate) async fn signed(
        &self,
        url: &AcmeUrl,
        signer: &dyn AccountSigner,
        kid: Option<&AcmeUrl>,
        payload: &[u8],
    ) -> Result<AcmeResponse, TransportError> {
        check_transport(url, &self.options)?;
        let jwk = signer.jwk()?;
        let mut current_nonce = self.take_nonce().await?;
        for attempt in 0..=self.options.bad_nonce_retries {
            let identity = match kid {
                Some(kid) => RequestIdentity::Kid { kid: kid.as_str() },
                None => RequestIdentity::Jwk { jwk: &jwk },
            };
            let jws = sign_request(signer, identity, &current_nonce, url.as_str(), payload)?;
            let response = read_response(
                self.http
                    .post(url.as_str())
                    .header("Content-Type", "application/jose+json")
                    .json(&jws)
                    .send()
                    .await?,
            )
            .await?;
            let fresh = nonce(&response.headers);
            if response.status.is_success() {
                if fresh.is_none() {
                    return Err(TransportError::MissingNonce);
                }
                self.remember_nonce(fresh).await;
                return Ok(response);
            }
            let error = response_error(&response);
            if error.is_problem(BAD_NONCE) && attempt < self.options.bad_nonce_retries {
                // RFC 8555 §6.5: retry MUST consume this response's nonce, not a pooled nonce.
                current_nonce = fresh.ok_or(TransportError::MissingNonce)?;
            } else {
                self.remember_nonce(fresh).await;
                return Err(error);
            }
        }
        // The inclusive retry loop always returns on its final attempt.
        Err(TransportError::MissingNonce)
    }
}

pub(crate) fn response_location(
    response: &AcmeResponse,
    options: &TransportOptions,
) -> Result<AcmeUrl, TransportError> {
    let value = response
        .headers
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(TransportError::MissingLocation)?;
    let url = AcmeUrl::new(value).map_err(|_| TransportError::MissingLocation)?;
    check_transport(&url, options)?;
    Ok(url)
}

impl AcmeClient {
    pub(crate) fn account_location(
        &self,
        response: &AcmeResponse,
    ) -> Result<AcmeUrl, TransportError> {
        response_location(response, &self.options)
    }
}

fn check_transport(url: &AcmeUrl, options: &TransportOptions) -> Result<(), TransportError> {
    if url
        .as_str()
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http:"))
        && !options.allow_loopback_http
    {
        return Err(TransportError::InsecureTransport);
    }
    Ok(())
}

fn nonce(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all("Replay-Nonce").iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some()
        || value.is_empty()
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return None;
    }
    Some(value.to_owned())
}

async fn read_response(mut response: reqwest::Response) -> Result<AcmeResponse, TransportError> {
    if response.content_length().is_some_and(|length| {
        aster_forge_utils::numbers::u64_to_usize(length, "ACME response length")
            .map_or(true, |length| length > MAX_BODY_BYTES)
    }) {
        return Err(TransportError::BodyTooLarge);
    }
    let status = response.status();
    let headers = response.headers().clone();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX_BODY_BYTES - body.len() {
            return Err(TransportError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(AcmeResponse {
        status,
        headers,
        body,
    })
}

fn response_error(response: &AcmeResponse) -> TransportError {
    let retry_after = response
        .headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|value| {
            value
                .parse::<u64>()
                .map(|seconds| RetryAfter::Delay(Duration::from_secs(seconds)))
                .ok()
                .or_else(|| httpdate::parse_http_date(value).ok().map(RetryAfter::At))
        });
    match serde_json::from_slice::<Problem>(&response.body) {
        Ok(problem) if response.status.is_client_error() || response.status.is_server_error() => {
            TransportError::Problem {
                status: response.status.as_u16(),
                problem: Box::new(problem),
                retry_after,
            }
        }
        _ => TransportError::HttpStatus {
            status: response.status.as_u16(),
            retry_after,
        },
    }
}

/// Encode public payloads for account requests.
pub(crate) fn json_payload(value: &impl Serialize) -> Result<Vec<u8>, TransportError> {
    Ok(serde_json::to_vec(value)?)
}

#[cfg(test)]
pub(crate) mod tests;
