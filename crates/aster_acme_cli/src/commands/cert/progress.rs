//! Timestamped human progress on stderr; JSON mode never emits human progress.
use crate::common::log::Level;
use aster_acme::issuance::progress::{IssueEvent, IssueObserver};
use aster_acme_core::protocol::{AuthorizationStatus, OrderStatus};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
struct Observed {
    authorizations: HashMap<String, AuthorizationStatus>,
    last_wait: Option<Instant>,
}

pub(super) struct Progress {
    pub(super) log: crate::common::log::Log,
    observed: Mutex<Observed>,
}
impl Progress {
    pub(super) fn new(json: bool) -> Self {
        Self {
            log: crate::common::log::Log::new(json),
            observed: Mutex::new(Observed::default()),
        }
    }

    fn should_display(&self, event: &IssueEvent) -> bool {
        if !self.log.enabled {
            return false;
        }
        let Ok(mut observed) = self.observed.lock() else {
            return false;
        };
        match event {
            IssueEvent::AuthorizationObserved { identifier, status } => {
                observed
                    .authorizations
                    .insert(identifier.clone(), status.clone())
                    .as_ref()
                    != Some(status)
            }
            IssueEvent::Waiting { .. } => {
                if observed
                    .last_wait
                    .is_some_and(|at| at.elapsed() < Duration::from_secs(5))
                {
                    return false;
                }
                observed.last_wait = Some(Instant::now());
                true
            }
            _ => true,
        }
    }
}

impl IssueObserver for Progress {
    fn observe(&self, event: &IssueEvent) {
        if !self.should_display(event) {
            return;
        }
        let (level, message) = match event {
            IssueEvent::CreatingOrder => (Level::Info, "Creating ACME order".into()),
            IssueEvent::OrderCreated { url } => {
                (Level::Success, format!("Order created: {}", url.as_str()))
            }
            IssueEvent::OrderObserved { status } => match status {
                OrderStatus::Pending => {
                    (Level::Wait, "CA order is pending domain validation".into())
                }
                OrderStatus::Ready => (
                    Level::Success,
                    "Domain validation finished; order is ready for signing".into(),
                ),
                OrderStatus::Processing => {
                    (Level::Wait, "CA is processing certificate issuance".into())
                }
                OrderStatus::Valid => (Level::Success, "CA has issued the certificate".into()),
                OrderStatus::Invalid => (Level::Warning, "CA marked this order invalid".into()),
                OrderStatus::Unknown(value) => (
                    Level::Warning,
                    format!("CA returned unsupported order status: {value}"),
                ),
            },
            IssueEvent::AuthorizationObserved { identifier, status } => (
                if matches!(status, AuthorizationStatus::Valid) {
                    Level::Success
                } else {
                    Level::Info
                },
                format!(
                    "Authorization {identifier}: {}",
                    String::from(status.clone())
                ),
            ),
            IssueEvent::PublicationRequired { count } => (
                Level::Info,
                format!("Prepared {count} DNS TXT requirement(s); publish every required value"),
            ),
            IssueEvent::DnsReady { forced: true } => (
                Level::Warning,
                "Local DNS check skipped (--force); CA validation is still required".into(),
            ),
            IssueEvent::DnsReady { forced: false } => (
                Level::Success,
                "All required TXT values are visible through the local DNS resolver".into(),
            ),
            IssueEvent::ValidationSubmitted { identifier } => (
                Level::Info,
                format!("CA validation requested for {identifier}"),
            ),
            IssueEvent::Waiting { delay } => (
                Level::Wait,
                format!(
                    "Waiting {:.1}s before the next CA query",
                    delay.as_secs_f64()
                ),
            ),
            IssueEvent::Finalizing => (
                Level::Info,
                "Submitting the saved CSR to finalize the order".into(),
            ),
            IssueEvent::Downloading => (
                Level::Info,
                "Downloading and checking the issued certificate chain".into(),
            ),
            IssueEvent::CertificateSaved => {
                (Level::Success, "Certificate verified and saved".into())
            }
        };
        self.log.line(level, &message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn json_suppresses_progress_and_repeated_waits_and_authorizations_are_throttled() {
        let json = Progress::new(true);
        assert!(!json.should_display(&IssueEvent::CreatingOrder));
        let progress = Progress::new(false);
        let wait = IssueEvent::Waiting {
            delay: Duration::from_secs(2),
        };
        assert!(progress.should_display(&wait));
        assert!(!progress.should_display(&wait));
        let authorization = IssueEvent::AuthorizationObserved {
            identifier: "example.com".into(),
            status: AuthorizationStatus::Pending,
        };
        assert!(progress.should_display(&authorization));
        assert!(!progress.should_display(&authorization));
        assert!(progress.should_display(&IssueEvent::AuthorizationObserved {
            identifier: "example.com".into(),
            status: AuthorizationStatus::Valid
        }));
    }
}
