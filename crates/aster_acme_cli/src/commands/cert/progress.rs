//! Timestamped human progress on stderr; JSON mode never emits human progress.
use crate::common::output::MessageKind;
use aster_acme::issuance::progress::{IssueEvent, IssueObserver};
use aster_acme_core::protocol::{AuthorizationStatus, OrderStatus};
use std::{collections::HashMap, sync::Mutex};

#[derive(Default)]
struct Observed {
    authorizations: HashMap<String, AuthorizationStatus>,
}

pub(super) struct Progress {
    pub(super) output: crate::common::session::OutputSession,
    observed: Mutex<Observed>,
}
impl Progress {
    pub(super) fn new(output: crate::common::session::OutputSession) -> Self {
        Self {
            output,
            observed: Mutex::new(Observed::default()),
        }
    }

    fn should_display(&self, event: &IssueEvent) -> bool {
        if self.output.is_json() {
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
            _ => true,
        }
    }
}

impl aster_acme::issuance::workflow::WorkflowObserver for Progress {
    fn discovering(&self) {
        self.output.progress(
            MessageKind::Info,
            "Discovering ACME endpoints over verified TLS",
        );
    }
    fn discovered(
        &self,
        directory: &aster_acme_protocol::directory::Directory,
        record: &aster_acme::issuance::IssueRecord,
    ) {
        for message in protocol_messages(directory, record) {
            self.output.progress(MessageKind::Info, &message);
        }
    }
}

impl IssueObserver for Progress {
    fn observe(&self, event: &IssueEvent) {
        if !self.should_display(event) {
            return;
        }
        let (level, message) = match event {
            IssueEvent::CreatingOrder { method, solver_id } => (MessageKind::Info, format!("Creating ACME order using {solver_id} ({})", method.name())),
            IssueEvent::OrderCreated { url } => (
                MessageKind::Success,
                format!("Order created: {}", url.as_str()),
            ),
            IssueEvent::OrderObserved { status } => match status {
                OrderStatus::Pending => (
                    MessageKind::Wait,
                    "CA order is pending domain validation".into(),
                ),
                OrderStatus::Ready => (
                    MessageKind::Success,
                    "Domain validation finished; order is ready for signing".into(),
                ),
                OrderStatus::Processing => (
                    MessageKind::Wait,
                    "CA is processing certificate issuance".into(),
                ),
                OrderStatus::Valid => {
                    (MessageKind::Success, "CA has issued the certificate".into())
                }
                OrderStatus::Invalid => {
                    (MessageKind::Warning, "CA marked this order invalid".into())
                }
                OrderStatus::Unknown(value) => (
                    MessageKind::Warning,
                    format!("CA returned unsupported order status: {value}"),
                ),
            },
            IssueEvent::AuthorizationObserved { identifier, status } => (
                if matches!(status, AuthorizationStatus::Valid) {
                    MessageKind::Success
                } else {
                    MessageKind::Info
                },
                format!(
                    "Authorization {identifier}: {}",
                    String::from(status.clone())
                ),
            ),
            IssueEvent::PublicationRequired { count, method } => (
                MessageKind::Info,
                format!("Prepared {count} {} requirement(s)", match method { aster_acme::challenge::ChallengeKind::Dns01 => "DNS TXT", aster_acme::challenge::ChallengeKind::DnsPersist01 => "persistent DNS TXT", aster_acme::challenge::ChallengeKind::Http01 => "HTTP file", aster_acme::challenge::ChallengeKind::TlsAlpn01 => "TLS-ALPN" }),
            ),
            IssueEvent::PublicationReady { method } => (
                MessageKind::Info,
                format!("{} publication ready; the CA will verify domain control", method.name()),
            ),
            IssueEvent::CleanupPending => (MessageKind::Warning, "Validation cleanup remains pending. The saved CA outcome is retained; inspect the publication files.".into()),
            IssueEvent::ValidationSubmitted { identifier } => (
                MessageKind::Info,
                format!("CA validation requested for {identifier}"),
            ),
            IssueEvent::Polling { attempt, limit } => (MessageKind::Wait, format!("Querying CA order ({attempt}/{limit})")),
            IssueEvent::Waiting { delay, attempt, limit, source } => (
                MessageKind::Wait,
                format!(
                    "Waiting {:.1}s before CA poll ({attempt}/{limit}; {})",
                    delay.as_secs_f64(), match source { aster_acme::issuance::PollWaitSource::RetryAfter => "Retry-After", aster_acme::issuance::PollWaitSource::LocalInterval => "local polling interval" }
                ),
            ),
            IssueEvent::Finalizing => (
                MessageKind::Info,
                "Submitting the saved CSR to finalize the order".into(),
            ),
            IssueEvent::Downloading => (
                MessageKind::Info,
                "Downloading and checking the issued certificate chain".into(),
            ),
            IssueEvent::ChainCandidatesObserved { .. } => return,
            IssueEvent::ChainSelectionUnavailable { requested, using } => (
                MessageKind::Warning,
                format!(
                    "Preferred certificate chain unavailable: {requested}; using CA default {using}"
                ),
            ),
            IssueEvent::ChainSelected { chain } => (
                MessageKind::Success,
                format!("Certificate chain: {chain}"),
            ),
            IssueEvent::CertificateSaved { name } => (
                MessageKind::Success,
                format!("Certificate {name} verified and saved"),
            ),
        };
        self.output.progress(level, &message);
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
        record.new_order_intent_saved,
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
            "Renewal timing: RFC 9773 ARI when available; fallback randomizes the day before the validity threshold and uses half for certificates shorter than 10 days"
        }
        None => {
            "Renewal timing: randomized local fallback before 2/3 validity (half for certificates shorter than 10 days; no advertised RFC 9773 ARI)"
        }
    };
    let mut lines = vec![format!(
        "CA capabilities (advertised): {}",
        capabilities.join(", ")
    )];
    // Draft-ietf-acme-profiles §3 (https://datatracker.ietf.org/doc/html/draft-ietf-acme-profiles):
    // surface advertised profiles so operators
    // can pass the exact name to --profile without a separate lookup.
    if let Some(profiles) = &directory.meta.profiles {
        lines.push(format!(
            "CA certificate profiles (advertised): {}",
            profiles.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if let Some(profile) = &record.profile {
        lines.push(format!("Certificate profile: {profile}"));
    }
    // RFC 8555 §7.4.2 (https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2):
    // surface the saved chain preference and the actually published chain so
    // operators can pass the exact name to --preferred-chain.
    if let Some(selection) = &record.chain_selection {
        let description = match selection {
            aster_acme::issuance::ChainSelection::Default => "CA default".to_owned(),
            aster_acme::issuance::ChainSelection::Named { chain, remember } => {
                if *remember {
                    format!("soft preferred {}", chain.as_str())
                } else {
                    format!("one-time {}", chain.as_str())
                }
            }
        };
        lines.push(format!("Preferred certificate chain: {description}"));
    }
    if let Some(chain) = &record.selected_chain {
        lines.push(format!(
            "Certificate chain: {} (sha256:{})",
            chain.dn, chain.fingerprint_sha256
        ));
    }
    lines.push(strategy.into());
    lines.push(timing.into());
    lines
}

#[cfg(test)]
mod tests {
    use crate::commands::cert::progress::*;
    use std::time::Duration;

    #[test]
    fn progress_displays_only_the_published_chain() {
        let (output, _, stderr) = crate::common::session::tests::session(false);
        let progress = Progress::new(output);
        progress.observe(&IssueEvent::ChainCandidatesObserved {
            available: vec!["CN=Other".into()],
        });
        progress.observe(&IssueEvent::ChainSelected {
            chain: "CN=Published".into(),
        });
        assert_eq!(stderr.text().lines().count(), 1);
        assert!(stderr.text().contains("Certificate chain: CN=Published"));
    }

    #[test]
    fn saved_events_identify_each_certificate_and_keep_json_silent() {
        for json in [false, true] {
            let (output, stdout, stderr) = crate::common::session::tests::session(json);
            let progress = Progress::new(output);
            for name in ["cdn.example.com-first", "cdn.example.com-second"] {
                progress.observe(&IssueEvent::CertificateSaved {
                    name: aster_acme::issuance::CertificateName::new(name).unwrap(),
                });
            }
            assert_eq!(stdout.text(), "");
            let text = stderr.text();
            if json {
                assert_eq!(text, "");
            } else {
                assert_eq!(text.lines().count(), 2);
                for name in ["cdn.example.com-first", "cdn.example.com-second"] {
                    assert!(
                        text.contains(&format!("[OK]    Certificate {name} verified and saved"))
                    );
                }
            }
        }
    }
    #[test]
    fn json_suppresses_progress_but_every_wait_source_is_visible() {
        let json = Progress::new(crate::common::session::OutputSession::new(true));
        assert!(!json.should_display(&IssueEvent::CreatingOrder {
            method: aster_acme::challenge::ChallengeKind::Dns01,
            solver_id: "manual_dns".into()
        }));
        let progress = Progress::new(crate::common::session::OutputSession::new(false));
        let wait = IssueEvent::Waiting {
            attempt: 1,
            limit: 30,
            source: aster_acme::issuance::PollWaitSource::RetryAfter,
            delay: Duration::from_secs(2),
        };
        assert!(progress.should_display(&wait));
        assert!(progress.should_display(&wait));
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
        let mut directory:aster_acme_protocol::directory::Directory=serde_json::from_value(serde_json::json!({"newNonce":"https://ca.example/nonce","newAccount":"https://ca.example/account","newOrder":"https://ca.example/order","keyChange":"https://ca.example/key-change"})).unwrap();
        let mut record:aster_acme::issuance::IssueRecord=serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p256","challenge":"dns-01","solver_config":{},"solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"web","created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"id","account_thumbprint":"key","directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],"phase":"creating_order","new_order_intent_saved":false,"authorizations":[],"finalize_submitted":"not_submitted"
        })).unwrap();
        assert!(protocol_messages(&directory, &record)[1].contains("Issuance strategy: RFC 8555"));
        record.renewal_of = Some(aster_acme::issuance::RenewalPredecessor {
            retained_validation: Vec::new(),
            operation_id: "old".into(),
            certificate_id: Some("a.b".into()),
        });
        let messages = protocol_messages(&directory, &record);
        assert!(messages[1].contains("does not advertise"));
        assert!(messages[2].contains("half") || messages[2].contains("2/3"));
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

    #[test]
    fn advertised_profiles_and_selected_profile_are_surfaced_to_the_operator() {
        let with_profiles: aster_acme_protocol::directory::Directory = serde_json::from_value(
            serde_json::json!({
                "newNonce": "https://ca.example/nonce", "newAccount": "https://ca.example/account",
                "newOrder": "https://ca.example/order", "keyChange": "https://ca.example/key-change",
                "renewalInfo": "https://ca.example/ari",
                "meta": {"profiles": {"classic": "https://ca.example/classic", "shortlived": "https://ca.example/shortlived"}}
            }),
        )
        .unwrap();
        let record_with_profile: aster_acme::issuance::IssueRecord =
            serde_json::from_value(serde_json::json!({
                "challenge": "http-01",
                "solver_config": {},
                "solver_id": "standalone",
                "operation_id": "a".repeat(43),
                "name": "web",
                "created_at": "2026-01-01T00:00:00Z",
                "account_name": "default",
                "account_id": "stable",
                "account_thumbprint": "key",
                "directory": "https://ca.example/directory",
                "account_url": "https://ca.example/account",
                "key_algorithm": "ecdsa-p256",
                "identifiers": ["example.com"],
                "profile": "shortlived",
                "phase": "authorizing",
                "new_order_intent_saved": true,
                "finalize_submitted": "not_submitted",
                "authorizations": []
            }))
            .unwrap();
        let lines = protocol_messages(&with_profiles, &record_with_profile);
        assert!(
            lines
                .iter()
                .any(|line| line
                    .contains("CA certificate profiles (advertised): classic, shortlived")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Certificate profile: shortlived")),
            "{lines:?}"
        );

        // No advertisement and no explicit selection: neither line appears.
        let plain: aster_acme_protocol::directory::Directory = serde_json::from_value(
            serde_json::json!({
                "newNonce": "https://ca.example/nonce", "newAccount": "https://ca.example/account",
                "newOrder": "https://ca.example/order", "keyChange": "https://ca.example/key-change",
                "renewalInfo": "https://ca.example/ari"
            }),
        )
        .unwrap();
        let record_plain: aster_acme::issuance::IssueRecord =
            serde_json::from_value(serde_json::json!({
                "challenge": "http-01",
                "solver_config": {},
                "solver_id": "standalone",
                "operation_id": "a".repeat(43),
                "name": "web",
                "created_at": "2026-01-01T00:00:00Z",
                "account_name": "default",
                "account_id": "stable",
                "account_thumbprint": "key",
                "directory": "https://ca.example/directory",
                "account_url": "https://ca.example/account",
                "key_algorithm": "ecdsa-p256",
                "identifiers": ["example.com"],
                "phase": "authorizing",
                "new_order_intent_saved": true,
                "finalize_submitted": "not_submitted",
                "authorizations": []
            }))
            .unwrap();
        let lines = protocol_messages(&plain, &record_plain);
        assert!(!lines.iter().any(|line| line.contains("profile")));
        let lines = protocol_messages(&plain, &record_plain);
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("Certificate profile:"))
        );
    }
    #[test]
    fn chain_preference_and_selected_chain_are_surfaced_to_the_operator() {
        let directory: aster_acme_protocol::directory::Directory = serde_json::from_value(
            serde_json::json!({
                "newNonce": "https://ca.example/nonce", "newAccount": "https://ca.example/account",
                "newOrder": "https://ca.example/order", "keyChange": "https://ca.example/key-change",
                "renewalInfo": "https://ca.example/ari"
            }),
        )
        .unwrap();
        let record: aster_acme::issuance::IssueRecord = serde_json::from_value(serde_json::json!({
            "challenge": "http-01",
            "solver_config": {},
            "solver_id": "standalone",
            "operation_id": "a".repeat(43),
            "name": "web",
            "created_at": "2026-01-01T00:00:00Z",
            "account_name": "default",
            "account_id": "stable",
            "account_thumbprint": "key",
            "directory": "https://ca.example/directory",
            "account_url": "https://ca.example/account",
            "key_algorithm": "ecdsa-p256",
            "identifiers": ["example.com"],
            "chain_selection": {"named": {"chain": "CN=Mock Default CA", "remember": true}},
            "selected_chain": {
                "dn": "CN=Mock Default CA",
                "common_name": "Mock Default CA",
                "fingerprint_sha256": "00"
            },
            "phase": "authorizing",
            "new_order_intent_saved": true,
            "finalize_submitted": "not_submitted",
            "authorizations": []
        }))
        .unwrap();
        let lines = protocol_messages(&directory, &record);
        assert!(
            lines.iter().any(|line| {
                line.contains("Preferred certificate chain: soft preferred CN=Mock Default CA")
            }),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Certificate chain: CN=Mock Default CA (sha256:00")),
            "{lines:?}"
        );

        // A CA-default preference reads differently from a named one.
        let default_only: aster_acme::issuance::IssueRecord =
            serde_json::from_value(serde_json::json!({
                "challenge": "http-01", "solver_config": {}, "solver_id": "standalone",
                "operation_id": "a".repeat(43), "name": "web",
                "created_at": "2026-01-01T00:00:00Z", "account_name": "default",
                "account_id": "stable", "account_thumbprint": "key",
                "directory": "https://ca.example/directory",
                "account_url": "https://ca.example/account", "key_algorithm": "ecdsa-p256",
                "identifiers": ["example.com"],
            "chain_selection": "default",
                "phase": "authorizing", "new_order_intent_saved": true,
                "finalize_submitted": "not_submitted", "authorizations": []
            }))
            .unwrap();
        let lines = protocol_messages(&directory, &default_only);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Preferred certificate chain: CA default")),
            "{lines:?}"
        );
        assert!(
            !lines.iter().any(|line| line.contains("Certificate chain:")),
            "{lines:?}"
        );
    }
}
