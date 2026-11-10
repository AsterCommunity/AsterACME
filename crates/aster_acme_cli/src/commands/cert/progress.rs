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

    pub(super) fn protocol(
        &self,
        directory: &aster_acme_protocol::directory::Directory,
        record: &aster_acme::issuance::IssueRecord,
    ) {
        for message in protocol_messages(directory, record) {
            self.log.line(Level::Info, &message);
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
                "Local DNS check skipped (--skip-dns-check); CA validation is still required"
                    .into(),
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

fn protocol_messages(
    directory: &aster_acme_protocol::directory::Directory,
    record: &aster_acme::issuance::IssueRecord,
) -> Vec<String> {
    let mut capabilities = vec!["RFC 8555 account/nonce"];
    for (available, name) in [
        (directory.new_order.is_some(), "RFC 8555 orders"),
        (directory.key_change.is_some(), "RFC 8555 keyChange"),
        (directory.revoke_cert.is_some(), "RFC 8555 revokeCert"),
        (directory.renewal_info.is_some(), "RFC 9773 ARI"),
    ] {
        if available {
            capabilities.push(name);
        }
    }
    let strategy = match (
        &record.renewal_of,
        record.creation_submitted,
        record.submitted_replaces.as_ref(),
        directory.renewal_info.as_ref(),
    ) {
        (None, _, _, _) => "Issuance strategy: RFC 8555 newOrder/finalize",
        (Some(_), true, Some(_), _) => {
            "Renewal strategy: resume RFC 8555 order with saved RFC 9773 replaces"
        }
        (Some(_), true, None, _) => {
            "Renewal strategy: resume saved RFC 8555 order without replaces"
        }
        (Some(previous), false, _, Some(_)) if previous.certificate_id.is_some() => {
            "Renewal strategy: RFC 8555 issuance with RFC 9773 replaces"
        }
        (Some(_), false, _, Some(_)) => {
            "Renewal strategy: RFC 8555 issuance; no usable certificate identifier for RFC 9773 replaces"
        }
        (Some(_), false, _, None) => {
            "Renewal strategy: RFC 8555 issuance; CA does not advertise RFC 9773 ARI/replaces"
        }
    };
    let timing = match directory.renewal_info {
        Some(_) => {
            "Renewal timing: RFC 9773 ARI when available; failed queries retain the saved plan, otherwise fallback to 2/3 of certificate validity"
        }
        None => {
            "Renewal timing: local fallback at 2/3 of certificate validity (no advertised RFC 9773 ARI)"
        }
    };
    vec![
        format!("CA capabilities (advertised): {}", capabilities.join(", ")),
        strategy.into(),
        timing.into(),
    ]
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
    #[test]
    fn advertised_capabilities_are_distinct_from_the_selected_renewal_strategy() {
        let mut directory:aster_acme_protocol::directory::Directory=serde_json::from_value(serde_json::json!({"newNonce":"https://ca.example/nonce","newAccount":"https://ca.example/account","newOrder":"https://ca.example/order"})).unwrap();
        let mut record:aster_acme::issuance::IssueRecord=serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p256","solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"web","created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"id","account_thumbprint":"key","directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],"phase":"creating_order","creation_submitted":false,"authorizations":[],"finalize_submitted":"not_submitted"
        })).unwrap();
        assert!(protocol_messages(&directory, &record)[1].contains("Issuance strategy: RFC 8555"));
        record.renewal_of = Some(aster_acme::issuance::RenewalPredecessor {
            operation_id: "old".into(),
            certificate_id: Some("a.b".into()),
        });
        let messages = protocol_messages(&directory, &record);
        assert!(messages[1].contains("does not advertise"));
        assert!(messages[2].contains("2/3"));
        directory.renewal_info =
            Some(aster_acme_protocol::url::AcmeUrl::new("https://ca.example/ari").unwrap());
        let messages = protocol_messages(&directory, &record);
        assert!(messages[0].contains("RFC 9773 ARI"));
        assert!(messages[1].contains("RFC 9773 replaces"));
        record.renewal_of.as_mut().unwrap().certificate_id = None;
        assert!(
            protocol_messages(&directory, &record)[1].contains("no usable certificate identifier")
        );
    }
}
