//! RFC 9773 renewal planning. No background task or certificate issuance is started here.

use crate::storage::issuance::IssueSession;
use crate::{
    issuance::{IssueError, IssueRecord},
    solver::ExecutionContext,
    transport::{AcmeClient, RetryAfter, TransportError, retry_after},
};
use aster_acme_core::renewal::{RenewalAction, renewal_action};
use aster_acme_protocol::renewal::{RenewalInfo, SuggestedWindow, information_url};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use time::OffsetDateTime;
use x509_parser::{extensions::ParsedExtension, pem::parse_x509_pem, prelude::FromDer as _};

use crate::renewal_calculation::fallback_renew_at;

/// Provenance of a saved renewal time, independent of last-query success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalSource {
    /// Uniformly sampled inside the CA's suggested window.
    Ari,
    /// Local randomized fallback derived from the certificate's validity interval.
    Fallback,
}

/// Durable per-certificate schedule; timestamps preserve RFC 3339 precision on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalPlan {
    /// RFC 9773 AKI/serial identifier, absent when the leaf has no AKI keyIdentifier.
    pub certificate_id: Option<String>,
    /// Leaf validity begins here, not at local download time.
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    /// Leaf validity ends here, independently of order expiry.
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    /// Chosen time; once reached the caller should attempt renewal.
    #[serde(with = "time::serde::rfc3339")]
    pub renew_at: OffsetDateTime,
    /// Explains the chosen time even when a later query fails.
    pub source: RenewalSource,
    /// Latest valid CA window; identical windows retain the selected time.
    pub suggested_window: Option<SuggestedWindow>,
    /// Optional operator information; never fetched or executed.
    pub explanation_url: Option<String>,
    /// Time of the last query attempt, successful or not.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_checked_at: Option<OffsetDateTime>,
    /// Earliest next query, independently of `renew_at`.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub next_check_at: Option<OffsetDateTime>,
    /// A query failure leaves the previous valid renewal schedule intact.
    pub last_query_failed: bool,
}

impl RenewalPlan {
    /// Derive fallback and ARI identity from an already validated leaf certificate.
    ///
    /// # Errors
    /// Rejects malformed certificates, duplicate extensions or empty validity intervals.
    pub fn from_certificate(chain: &[u8]) -> Result<Self, IssueError> {
        let (_, pem) = parse_x509_pem(chain)
            .map_err(|_| IssueError::InvalidInput("invalid renewal certificate PEM"))?;
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
            .map_err(|_| IssueError::InvalidInput("invalid renewal certificate DER"))?;
        let invalid = || IssueError::InvalidInput("invalid certificate renewal metadata");
        cert.extensions_map().map_err(|_| invalid())?;
        let certificate_id = certificate_identifier(&cert);
        let not_before =
            OffsetDateTime::from_unix_timestamp(cert.validity().not_before.timestamp())
                .map_err(|_| invalid())?;
        let not_after = OffsetDateTime::from_unix_timestamp(cert.validity().not_after.timestamp())
            .map_err(|_| invalid())?;
        Self::fallback(
            not_before,
            not_after,
            OffsetDateTime::now_utc(),
            certificate_id,
        )
    }

    fn fallback(
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        issued_at: OffsetDateTime,
        certificate_id: Option<String>,
    ) -> Result<Self, IssueError> {
        if not_after <= not_before {
            return Err(IssueError::InvalidInput(
                "invalid certificate renewal validity",
            ));
        }
        Ok(Self {
            certificate_id,
            not_before,
            not_after,
            renew_at: fallback_renew_at(not_before, not_after, issued_at)?,
            source: RenewalSource::Fallback,
            suggested_window: None,
            explanation_url: None,
            last_checked_at: None,
            next_check_at: None,
            last_query_failed: false,
        })
    }

    fn apply(&mut self, info: RenewalInfo) -> Result<(), IssueError> {
        let window = &info.suggested_window;
        if window.end <= window.start
            || window.start >= self.not_after
            || window.end > self.not_after
        {
            return Err(IssueError::InvalidInput(
                "invalid ARI suggested renewal window",
            ));
        }
        if self.suggested_window.as_ref() != Some(window) {
            self.renew_at = sample(window)?;
        }
        self.source = RenewalSource::Ari;
        self.suggested_window = Some(info.suggested_window);
        self.explanation_url = info.explanation_url;
        Ok(())
    }
}

// RFC 9773 requires raw DER INTEGER bytes, including a positive serial's leading zero.
fn certificate_identifier(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<String> {
    cert.extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|key| {
                    format!(
                        "{}.{}",
                        URL_SAFE_NO_PAD.encode(key.0),
                        URL_SAFE_NO_PAD.encode(cert.raw_serial())
                    )
                })
            }
            _ => None,
        })
}

// Rejection sampling avoids modulo bias, including for subsecond windows. RNG failure
// keeps the durable fallback rather than choosing the same window start for every client.
fn sample(window: &SuggestedWindow) -> Result<OffsetDateTime, IssueError> {
    let width = u128::try_from((window.end - window.start).whole_nanoseconds())
        .map_err(|_| IssueError::InvalidInput("invalid ARI interval"))?;
    if width == 0 {
        return Err(IssueError::InvalidInput("empty ARI interval"));
    }
    let threshold = width.wrapping_neg() % width;
    loop {
        let mut bytes = [0; 16];
        aws_lc_rs::rand::fill(&mut bytes)
            .map_err(|_| IssueError::InvalidInput("renewal randomness unavailable"))?;
        let value = u128::from_be_bytes(bytes);
        if value >= threshold {
            let offset = i128::try_from(value % width)
                .map_err(|_| IssueError::InvalidInput("invalid ARI interval width"))?;
            return OffsetDateTime::from_unix_timestamp_nanos(
                window.start.unix_timestamp_nanos() + offset,
            )
            .map_err(|_| IssueError::InvalidInput("ARI time out of range"));
        }
    }
}

/// Embeddable ARI reader. Uses unauthenticated GET and never registers an account.
pub struct RenewalService {
    client: Arc<AcmeClient>,
}

impl RenewalService {
    /// Reuse the CA-discovered HTTP pool and its request policy.
    #[must_use]
    pub fn new(client: Arc<AcmeClient>) -> Self {
        Self { client }
    }

    /// Refresh a due plan and save it under the caller's existing certificate lease.
    /// Network/invalid-response failures retain the plan and schedule another check in six hours.
    ///
    /// # Errors
    /// Returns identity, cancellation/deadline or persistence failures; never issues a certificate.
    pub async fn refresh(
        &self,
        session: &mut dyn IssueSession,
        execution: &ExecutionContext,
    ) -> Result<IssueRecord, IssueError> {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        let mut record = session.record().await?;
        if record.directory != *self.client.directory_url() {
            return Err(IssueError::InvalidInput("renewal directory mismatch"));
        }
        if !record.is_in_use
            || record.unfinished()
            || !matches!(
                record.revocation.state,
                aster_acme_core::revocation::RevocationState::NotRequested
            )
        {
            return Ok(record);
        }
        let Some(plan) = &mut record.renewal else {
            return Ok(record);
        };
        let now = OffsetDateTime::now_utc();
        let endpoint = self.client.directory().renewal_info.as_ref();
        match renewal_action(
            endpoint.is_some() && plan.certificate_id.is_some(),
            plan.next_check_at.map(OffsetDateTime::unix_timestamp),
            now.unix_timestamp(),
        ) {
            RenewalAction::Unavailable | RenewalAction::Wait => return Ok(record),
            RenewalAction::Query => {}
        }
        let endpoint = endpoint.ok_or(IssueError::InvalidInput("missing ARI endpoint"))?;
        let id = plan
            .certificate_id
            .as_deref()
            .ok_or(IssueError::InvalidInput(
                "missing ARI certificate identifier",
            ))?;
        let url = information_url(endpoint, id).map_err(TransportError::from)?;
        // Persist the retry deadline before I/O so cancellation/restart cannot create
        // a request storm. A successful query replaces it with the server's hint.
        plan.last_checked_at = Some(now);
        plan.next_check_at = Some(now + time::Duration::hours(6));
        plan.last_query_failed = true;
        session.save(&record).await?;
        let response = self.query(&url, execution).await;
        let plan = record
            .renewal
            .as_mut()
            .ok_or(IssueError::InvalidInput("missing renewal plan"))?;
        match response {
            Ok(response) => {
                let info = serde_json::from_slice::<RenewalInfo>(&response.body);
                if let Ok(info) = info
                    && plan.apply(info).is_ok()
                {
                    // Missing/invalid Retry-After does not erase a valid CA window.
                    // Keep the six-hour long-term-error query schedule in that case.
                    if let Some(retry) = retry_after(&response.headers) {
                        plan.next_check_at = Some(next_check(&retry, OffsetDateTime::now_utc()));
                        plan.last_query_failed = false;
                    }
                }
            }
            Err(IssueError::Interrupted) => return Err(IssueError::Interrupted),
            Err(_) => {}
        }
        session.save(&record).await?;
        Ok(record)
    }

    async fn query(
        &self,
        url: &aster_acme_protocol::url::AcmeUrl,
        execution: &ExecutionContext,
    ) -> Result<crate::transport::AcmeResponse, IssueError> {
        for attempt in 0..3u32 {
            let response = tokio::select! {
                () = execution.cancellation.cancelled() => return Err(IssueError::Interrupted),
                result = tokio::time::timeout_at(execution.deadline.into(), self.client.get(url)) => result.map_err(|_| IssueError::Interrupted)?,
            };
            match response {
                Ok(response) => return Ok(response),
                Err(error) if attempt < 2 && temporary(&error) => {
                    tokio::select! {
                        () = execution.cancellation.cancelled() => return Err(IssueError::Interrupted),
                        () = tokio::time::sleep_until(execution.deadline.into()) => return Err(IssueError::Interrupted),
                        () = tokio::time::sleep(Duration::from_secs(1 << attempt)) => {}
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(IssueError::InvalidInput("ARI retry budget exhausted"))
    }
}

fn temporary(error: &TransportError) -> bool {
    match error {
        TransportError::Network(error) => error.is_timeout(),
        TransportError::Problem { status, .. } | TransportError::HttpStatus { status, .. } => {
            (500..600).contains(status)
        }
        _ => false,
    }
}

// RFC 9773 section 4.3.2 permits reasonable limits; clamp to one minute .. one day.
fn next_check(retry: &RetryAfter, now: OffsetDateTime) -> OffsetDateTime {
    let seconds = match retry {
        RetryAfter::Delay(delay) => delay.as_secs().clamp(60, 86400),
        RetryAfter::At(at) => at
            .duration_since(std::time::SystemTime::from(now))
            .map_or(60, |delay| delay.as_secs().clamp(60, 86400)),
    };
    now + time::Duration::seconds(i64::try_from(seconds).unwrap_or(86400))
}

#[cfg(test)]
mod tests;
