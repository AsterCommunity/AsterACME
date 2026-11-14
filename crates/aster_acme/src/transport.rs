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

use crate::crypto::{CryptoError, JwsSigner, sign_request};

use aster_acme_protocol::{
    directory::Directory,
    jws::RequestIdentity,
    problem::{Problem, ProblemKind},
    url::AcmeUrl,
};

#[cfg(feature = "precheck-http")]
mod http_precheck;

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
    /// Durable ACME submission intent failed before the request was sent.
    #[error("could not persist ACME submission intent: {0}")]
    SubmissionIntent(String),
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
        // Keep nested account/issuance errors small without discarding problem details.
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
    pub fn is_problem(&self, kind: &ProblemKind) -> bool {
        match self {
            Self::Problem { problem, .. } => &problem.kind == kind,
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

impl TransportOptions {
    /// Validate explicit transport settings before storing intent or performing I/O.
    ///
    /// # Errors
    /// Rejects zero deadlines, excessive nonce retries and invalid User-Agent headers.
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.request_timeout.is_zero() || self.bad_nonce_retries > 5 {
            return Err(TransportError::InvalidOptions);
        }
        if let Some(user_agent) = &self.user_agent {
            crate::http_client::validate_user_agent(user_agent)?;
        }
        Ok(())
    }
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

/// Reusable verified-TLS connection pool, injectable by CLI commands or embedded
/// applications. Cloning this handle shares the lazily constructed Forge/reqwest
/// pool; it does not construct another HTTP client. Account identity, nonce state
/// and request policy remain per ACME client.
#[derive(Clone, Default)]
pub struct HttpPool(std::sync::Arc<tokio::sync::OnceCell<aster_forge_http::HttpClient>>);

impl HttpPool {
    async fn client(&self) -> Result<&aster_forge_http::HttpClient, TransportError> {
        self.0
            .get_or_try_init(|| async { crate::http_client::build() })
            .await
    }

    /// Discover a CA using verified TLS, without redirects or automatic mutation retries.
    ///
    /// # Errors
    /// Reports unsafe endpoints, HTTP/JSON failures or an oversized directory.
    pub async fn discover(
        &self,
        directory_url: AcmeUrl,
        options: TransportOptions,
    ) -> Result<AcmeClient, TransportError> {
        options.validate()?;
        check_transport(&directory_url, &options)?;
        let http = self.client().await?;
        let started = std::time::Instant::now();
        tracing::debug!(request_kind = "directory", "ACME request started");
        let sent = request(http, Method::GET, &directory_url, &options)
            .send()
            .await;
        if let Err(error) = &sent {
            tracing::debug!(
                request_kind = "directory",
                timeout = error.is_timeout(),
                connect_error = error.is_connect(),
                elapsed_ms = started.elapsed().as_millis(),
                "ACME transport failed"
            );
        }
        let response = read_response(sent?).await?;
        tracing::debug!(
            request_kind = "directory",
            status = response.status.as_u16(),
            elapsed_ms = started.elapsed().as_millis(),
            "ACME response received"
        );
        if response.status != StatusCode::OK {
            return Err(response_error(&response));
        }
        let directory: Directory = serde_json::from_slice(&response.body)?;
        check_transport(&directory.new_nonce, &options)?;
        check_transport(&directory.new_account, &options)?;
        for endpoint in [
            directory.new_order.as_ref(),
            directory.key_change.as_ref(),
            directory.renewal_info.as_ref(),
            directory.revoke_cert.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            check_transport(endpoint, &options)?;
        }
        let client = AcmeClient {
            http_pool: self.clone(),
            directory_url,
            directory,
            options,
            nonces: Mutex::new(VecDeque::new()),
        };
        client.remember_nonce(nonce(&response.headers)).await;
        Ok(client)
    }
}

/// Account-oriented ACME transport with a concurrency-safe bounded nonce pool.
pub struct AcmeClient {
    http_pool: HttpPool,
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

    /// Unauthenticated bounded GET for RFC 9773; no JWS or replay nonce is required.
    pub(crate) async fn get(&self, url: &AcmeUrl) -> Result<AcmeResponse, TransportError> {
        check_transport(url, &self.options)?;
        let response = read_response(
            request(
                self.http_pool.client().await?,
                Method::GET,
                url,
                &self.options,
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?,
        )
        .await?;
        if response.status != StatusCode::OK {
            return Err(response_error(&response));
        }
        Ok(response)
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
        let response = request(
            self.http_pool.client().await?,
            Method::HEAD,
            &self.directory.new_nonce,
            &self.options,
        )
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
        signer: &dyn JwsSigner,
        kid: Option<&AcmeUrl>,
        payload: &[u8],
    ) -> Result<AcmeResponse, TransportError> {
        self.signed_observed(
            url,
            signer,
            kid,
            payload,
            &std::sync::atomic::AtomicBool::new(false),
            || std::future::ready(Ok(())),
        )
        .await
    }

    pub(crate) async fn signed_observed<F, Fut>(
        &self,
        url: &AcmeUrl,
        signer: &dyn JwsSigner,
        kid: Option<&AcmeUrl>,
        payload: &[u8],
        submitted: &std::sync::atomic::AtomicBool,
        before_submit: F,
    ) -> Result<AcmeResponse, TransportError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), String>> + Send,
    {
        check_transport(url, &self.options)?;
        let jwk = signer.jwk()?;
        let mut current_nonce = self.take_nonce().await?;
        let mut before_submit = Some(before_submit);
        for attempt in 0..=self.options.bad_nonce_retries {
            let identity = match kid {
                Some(kid) => RequestIdentity::Kid { kid: kid.as_str() },
                None => RequestIdentity::Jwk { jwk: &jwk },
            };
            let jws = sign_request(signer, identity, &current_nonce, url.as_str(), payload)?;
            let started = std::time::Instant::now();
            tracing::debug!(
                request_kind = "signed_post",
                nonce_retry = attempt,
                "ACME request started"
            );
            let http = self.http_pool.client().await?;
            let prepared = request(http, Method::POST, url, &self.options)
                .header("Content-Type", "application/jose+json")
                .json(&jws);
            if let Some(before_submit) = before_submit.take() {
                before_submit()
                    .await
                    .map_err(TransportError::SubmissionIntent)?;
            }
            submitted.store(true, std::sync::atomic::Ordering::SeqCst);
            let sent = prepared.send().await;
            if let Err(error) = &sent {
                tracing::debug!(
                    request_kind = "signed_post",
                    nonce_retry = attempt,
                    timeout = error.is_timeout(),
                    connect_error = error.is_connect(),
                    elapsed_ms = started.elapsed().as_millis(),
                    "ACME transport failed"
                );
            }
            let response = read_response(sent?).await?;
            tracing::debug!(
                request_kind = "signed_post",
                nonce_retry = attempt,
                status = response.status.as_u16(),
                has_location = response.headers.contains_key(LOCATION), retry_after = ?retry_after(&response.headers),
                elapsed_ms = started.elapsed().as_millis(),
                "ACME response received"
            );
            let fresh = nonce(&response.headers);
            if response.status.is_success() {
                // RFC 8555 section 6.5.1: ignore invalid Replay-Nonce values.
                // Preserve a successful mutation response (especially its Location);
                // the next signed request can acquire a fresh nonce with HEAD.
                self.remember_nonce(fresh).await;
                return Ok(response);
            }
            let error = response_error(&response);
            if error.is_problem(&ProblemKind::BadNonce) && attempt < self.options.bad_nonce_retries
            {
                // RFC 8555 §6.5: retry MUST consume this response's nonce, not a pooled nonce.
                submitted.store(false, std::sync::atomic::Ordering::SeqCst);
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

// User-Agent and total request budget are per invocation/account. Applying them
// on the request prevents a shared pool from inheriting the previous account's policy.
fn request(
    http: &aster_forge_http::HttpClient,
    method: Method,
    url: &AcmeUrl,
    options: &TransportOptions,
) -> aster_forge_http::HttpRequestBuilder {
    http.request(method, url.as_str())
        .header(
            reqwest::header::USER_AGENT,
            options
                .user_agent
                .as_deref()
                .unwrap_or(concat!("AsterACME/", env!("CARGO_PKG_VERSION"))),
        )
        .timeout(options.request_timeout)
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
    let retry_after = retry_after(&response.headers);
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

/// Parse the CA scheduling hint once for both errors and successful resource responses.
pub(crate) fn retry_after(headers: &HeaderMap) -> Option<RetryAfter> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .parse::<u64>()
                .map(|seconds| RetryAfter::Delay(Duration::from_secs(seconds)))
                .ok()
                .or_else(|| httpdate::parse_http_date(value).ok().map(RetryAfter::At))
        })
}

#[cfg(test)]
pub(crate) mod tests;
