//! Google changes + durable files/leases + the real ACME issuance service.
use crate::commands::cert::validation::{
    ValidationMethod,
    dns_provider::ProviderDns,
    tests::{
        flow::{
            Fixture,
            dns_provider::{controls, run},
        },
        progress,
    },
};
use aster_acme::{
    crypto::{key::SoftwareSigningKey, key_algorithm::KeyAlgorithm},
    issuance::IssueOutcome,
};
use aster_acme_cli_storage::provider_publication::ProviderPublicationStore;
use aster_acme_dns::{
    DnsRecord, ProviderContext, ProviderErrorCode, ProviderExecution, SideEffect,
    backend::BackendConfig,
    operation::{
        HttpExecutor, HttpFailure, HttpMethod, HttpRequest, HttpResponse, ProviderHost,
        PublicationStore,
    },
    propagation::PropagationPolicy,
    routing::{DnsLookup, LookupError},
};
use aster_acme_dns_builtin::provider::vendors::google_cloud_dns::BACKEND_ID;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const OWNER: &str = "delegated.validation.net.";

struct Cloud {
    root: PathBuf,
    rrset: Mutex<Option<Value>>,
    changes: Mutex<BTreeMap<String, Value>>,
    writes: AtomicUsize,
    tokens: AtomicUsize,
    lose_submit: AtomicBool,
    lose_poll: AtomicBool,
    cancel_submit: AtomicBool,
    throttle: AtomicBool,
    lease_checked: AtomicBool,
}

impl Cloud {
    fn new(root: &Path) -> Self {
        Self {
            root: root.into(),
            rrset: Mutex::new(None),
            changes: Mutex::new(BTreeMap::new()),
            writes: AtomicUsize::new(0),
            tokens: AtomicUsize::new(0),
            lose_submit: AtomicBool::new(false),
            lose_poll: AtomicBool::new(false),
            cancel_submit: AtomicBool::new(false),
            throttle: AtomicBool::new(false),
            lease_checked: AtomicBool::new(false),
        }
    }

    fn checkpoint(&self) -> Value {
        let path = std::fs::read_dir(self.root.join("providers/.publications"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let bytes = std::fs::read(path).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("PRIVATE KEY") && !text.contains("access-token-sentinel"));
        serde_json::from_slice(&bytes).unwrap()
    }

    fn solver(self: &Arc<Self>) -> ProviderDns {
        let provider = crate::commands::provider::runtime::registry()
            .unwrap()
            .provider(
                BACKEND_ID,
                &config(),
                ProviderHost {
                    http: self.clone(),
                    credentials: None,
                    publications: Arc::new(ProviderPublicationStore::new(self.root.clone())),
                    timeout: Duration::from_secs(5),
                },
            )
            .unwrap();
        ProviderDns {
            ttl_seconds: 120,
            context: ProviderContext {
                provider_instance_id: "google".into(),
                provider_profile_version: 1,
                provider_custom: BTreeMap::new(),
            },
            provider,
            lookup: self.clone(),
            allowed_zones: vec!["validation.net".into()],
            dns_targets: BTreeMap::new(),
            propagation: PropagationPolicy {
                initial_delay: Duration::from_millis(1),
                fallback_delay: Duration::from_millis(1),
                timeout: Duration::from_secs(1),
            },
            progress: progress(),
        }
    }
}

fn config() -> BackendConfig {
    static PEM: OnceLock<String> = OnceLock::new();
    let pem = PEM.get_or_init(|| {
        let key = SoftwareSigningKey::generate(KeyAlgorithm::Rsa2048).unwrap();
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            STANDARD.encode(key.to_pkcs8().unwrap().as_slice())
        )
    });
    BackendConfig { custom: serde_json::from_value(json!({"service_account":{"type":"service_account","project_id":"test-project","client_email":"test@test-project.iam.gserviceaccount.com","private_key_id":"key-id","private_key":pem,"token_uri":"https://oauth2.googleapis.com/token"}})).unwrap(), ..BackendConfig::default() }
}

fn reply(status: u16, body: &Value) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("Retry-After".into(), b"120".to_vec())],
        body: serde_json::to_vec(body).unwrap(),
    }
}

fn lost() -> HttpFailure {
    HttpFailure {
        code: ProviderErrorCode::ProviderTimeout,
        side_effect: SideEffect::Unknown,
    }
}

#[async_trait]
impl HttpExecutor for Cloud {
    async fn execute(
        &self,
        request: HttpRequest,
        execution: &ProviderExecution,
    ) -> Result<HttpResponse, HttpFailure> {
        if request.url == "https://oauth2.googleapis.com/token" {
            assert!(!request.mutation);
            self.tokens.fetch_add(1, Ordering::SeqCst);
            return Ok(reply(
                200,
                &json!({"access_token":"access-token-sentinel","token_type":"Bearer","expires_in":3600}),
            ));
        }
        assert!(request.headers.contains(&(
            "Authorization".into(),
            "Bearer access-token-sentinel".into()
        )));
        if request.url.contains("/rrsets?") {
            assert!(request.url.contains("name=delegated.validation.net."));
            return Ok(reply(
                200,
                &json!({"rrsets":self.rrset.lock().unwrap().iter().cloned().collect::<Vec<_>>()}),
            ));
        }
        if request.url.contains("/changes/") {
            if self.lose_poll.swap(false, Ordering::SeqCst) {
                return Err(lost());
            }
            let id = request.url.rsplit('/').next().unwrap();
            return Ok(reply(200, &self.changes.lock().unwrap()[id]));
        }
        if request.method == HttpMethod::Post {
            assert!(request.mutation);
            let plan: Value = serde_json::from_slice(&request.body).unwrap();
            let cp = self.checkpoint();
            assert_eq!(cp["state"]["data"]["plan"], plan);
            assert_eq!(cp["record"]["name"], OWNER);
            if !self.lease_checked.swap(true, Ordering::SeqCst) {
                let output=std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--ignored","--exact","commands::cert::validation::tests::flow::dns_provider::google_cloud_dns::cross_process_contender"])
                    .env("ASTER_GOOGLE_DNS_TEST_ROOT",&self.root).output().unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stdout)
                );
            }
            if self.throttle.swap(false, Ordering::SeqCst) {
                return Ok(reply(
                    429,
                    &json!({"error":{"errors":[{"reason":"rateLimitExceeded"}],"message":"private-key-sentinel"}}),
                ));
            }
            let mut rrset = self.rrset.lock().unwrap();
            assert_eq!(
                plan["deletions"],
                json!(rrset.iter().cloned().collect::<Vec<_>>())
            );
            *rrset = plan["additions"].as_array().unwrap().first().cloned();
            let id = (self.writes.fetch_add(1, Ordering::SeqCst) + 1).to_string();
            let mut change = plan;
            change["id"] = json!(id);
            change["status"] = json!("done");
            self.changes.lock().unwrap().insert(id, change.clone());
            if self.lose_submit.swap(false, Ordering::SeqCst) {
                return Err(lost());
            }
            if self.cancel_submit.swap(false, Ordering::SeqCst) {
                execution.cancellation.cancel();
            }
            return Ok(reply(200, &change));
        }
        assert!(request.url.contains("/managedZones?"));
        Ok(reply(
            200,
            &json!({"managedZones":[{"id":"zone-1","dnsName":"validation.net.","visibility":"public"}]}),
        ))
    }
}

#[async_trait]
impl DnsLookup for Cloud {
    async fn cname(&self, name: &str) -> Result<Option<String>, LookupError> {
        Ok((name == "_acme-challenge.example.com.").then(|| OWNER.into()))
    }

    async fn txt(&self, _: &str) -> Result<Vec<Vec<u8>>, LookupError> {
        Ok(self
            .rrset
            .lock()
            .unwrap()
            .iter()
            .flat_map(|s| s["rrdatas"].as_array().unwrap())
            .map(|v| v.as_str().unwrap().trim_matches('"').as_bytes().to_vec())
            .collect())
    }
}

#[tokio::test]
#[ignore = "child process fixture"]
async fn cross_process_contender() {
    let Ok(root) = std::env::var("ASTER_GOOGLE_DNS_TEST_ROOT") else {
        return;
    };
    let record = DnsRecord {
        publication_id: "competing".into(),
        challenge_name: OWNER.into(),
        name: OWNER.into(),
        cname_chain: vec![],
        value: "other".into(),
        ttl_seconds: None,
    };
    let deadline = Instant::now() + Duration::from_millis(100);
    let result = ProviderPublicationStore::new(root.into())
        .open(
            BACKEND_ID,
            "other-scope",
            &record,
            &ProviderExecution {
                cancellation: tokio_util::sync::CancellationToken::new(),
                deadline,
            },
        )
        .await;
    assert!(result.is_err());
    assert!(Instant::now() >= deadline);
}

#[tokio::test]
async fn google_change_recovery_uses_files_leases_and_loopback_ca_then_cleans() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::new(fixture.temp.path()));
    cloud.lose_poll.store(true, Ordering::SeqCst);
    assert!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .is_err()
    );
    assert_eq!(fixture.count("/dns-challenge").await, 0);
    assert_eq!(cloud.checkpoint()["state"]["data"]["change_id"], "1");
    fixture.reopen().await;
    assert!(matches!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 2);
    assert!(cloud.rrset.lock().unwrap().is_none());
    assert_eq!(cloud.checkpoint()["state"]["data"]["phase"], "cleaned");
}

#[tokio::test]
async fn google_unknown_submission_is_preserved_without_replay_or_ca_ack() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::new(fixture.temp.path()));
    cloud.lose_submit.store(true, Ordering::SeqCst);
    assert!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .is_err()
    );
    fixture.reopen().await;
    assert!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .is_err()
    );
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    assert!(cloud.rrset.lock().unwrap().is_some());
    assert_eq!(fixture.count("/dns-challenge").await, 0);
}

#[tokio::test]
async fn google_cancel_after_response_keeps_change_id_for_restart() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::new(fixture.temp.path()));
    cloud.cancel_submit.store(true, Ordering::SeqCst);
    assert!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .is_err()
    );
    assert_eq!(cloud.checkpoint()["state"]["data"]["change_id"], "1");
    fixture.reopen().await;
    assert!(matches!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn google_rate_limit_floor_survives_restart() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::new(fixture.temp.path()));
    cloud.throttle.store(true, Ordering::SeqCst);
    assert!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .is_err()
    );
    assert!(
        cloud.checkpoint()["state"]["data"]["retry_at"]
            .as_i64()
            .is_some()
    );
    fixture.reopen().await;
    assert!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .is_err()
    );
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.count("/dns-challenge").await, 0);
}
