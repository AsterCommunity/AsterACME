//! Native Cloudflare -> durable host runner -> DNS solver -> real ACME service.
use crate::commands::cert::validation::{
    ValidationMethod,
    dns_provider::ProviderDns,
    tests::flow::Fixture,
    tests::flow::dns_provider::{controls, run},
    tests::progress,
};
use aster_acme::issuance::IssueOutcome;
use aster_acme_dns::{
    ProviderContext, ProviderExecution,
    backend::BackendConfig,
    operation::{HttpExecutor, HttpFailure, HttpRequest, HttpResponse, ProviderHost},
    propagation::PropagationPolicy,
    routing::{DnsLookup, LookupError},
};
use aster_acme_dns_builtin::provider::cloudflare::BACKEND_ID;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
const ZONE: &str = "0123456789abcdef0123456789abcdef";
#[derive(Default)]
struct Cloud {
    remote: Mutex<BTreeMap<String, Value>>,
    writes: AtomicUsize,
    deletes: AtomicUsize,
    lose_response: AtomicBool,
    cancel_after_write: AtomicBool,
    changed_cname: AtomicBool,
    discovered: AtomicUsize,
}
#[async_trait]
impl HttpExecutor for Cloud {
    async fn execute(
        &self,
        request: HttpRequest,
        execution: &ProviderExecution,
    ) -> Result<HttpResponse, HttpFailure> {
        assert!(
            request
                .url
                .starts_with("https://api.cloudflare.com/client/v4/zones")
        );
        let mut remote = self.remote.lock().unwrap();
        let result = if request.url.contains("/zones?name=") {
            self.discovered.fetch_add(1, Ordering::SeqCst);
            if request.url.contains("name=validation.net&") {
                json!([{"id":ZONE,"name":"validation.net"}])
            } else {
                json!([])
            }
        } else if request.url.ends_with(ZONE) {
            json!({"id":ZONE,"name":"validation.net"})
        } else if request.method == aster_acme_dns::operation::HttpMethod::Post {
            let mut record: Value = serde_json::from_slice(&request.body).unwrap();
            record["id"] = json!("11111111111111111111111111111111");
            remote.insert("11111111111111111111111111111111".into(), record.clone());
            self.writes.fetch_add(1, Ordering::SeqCst);
            if self.lose_response.swap(false, Ordering::SeqCst) {
                return Err(HttpFailure {
                    code: aster_acme_dns::ProviderErrorCode::ProviderTimeout,
                    side_effect: aster_acme_dns::SideEffect::Unknown,
                });
            }
            if self.cancel_after_write.load(Ordering::SeqCst) {
                execution.cancellation.cancel();
            }
            record
        } else if request.method == aster_acme_dns::operation::HttpMethod::Delete {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            remote.remove("11111111111111111111111111111111");
            json!({"id":"11111111111111111111111111111111"})
        } else if request.url.contains('?') {
            json!(remote.values().cloned().collect::<Vec<_>>())
        } else {
            remote
                .get("11111111111111111111111111111111")
                .cloned()
                .unwrap()
        };
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(
                &json!({"success":true,"result":result,"result_info":{"page":1,"total_pages":1}}),
            )
            .unwrap(),
        })
    }
}
#[async_trait]
impl DnsLookup for Cloud {
    async fn cname(&self, name: &str) -> Result<Option<String>, LookupError> {
        Ok((name == "_acme-challenge.example.com.").then(|| {
            if self.changed_cname.load(Ordering::SeqCst) {
                "elsewhere.example.net.".into()
            } else {
                "delegated.validation.net.".into()
            }
        }))
    }
    async fn txt(&self, _: &str) -> Result<Vec<Vec<u8>>, LookupError> {
        Ok(self
            .remote
            .lock()
            .unwrap()
            .values()
            .map(|value| value["content"].as_str().unwrap().as_bytes().to_vec())
            .collect())
    }
}
fn config() -> BackendConfig {
    BackendConfig {
        custom: serde_json::from_value(json!({"zone_id":ZONE,"api_token":"credential-sentinel"}))
            .unwrap(),
        ..BackendConfig::default()
    }
}
fn solver(cloud: Arc<Cloud>, root: &std::path::Path, config: &BackendConfig) -> ProviderDns {
    let provider = crate::commands::provider::runtime::registry()
        .unwrap()
        .provider(
            BACKEND_ID,
            config,
            ProviderHost {
                timeout: Duration::from_secs(5),
                credentials: None,
                http: cloud.clone(),
                publications: Arc::new(
                    aster_acme_cli_storage::provider_publication::ProviderPublicationStore::new(
                        root.into(),
                    ),
                ),
            },
        )
        .unwrap();
    ProviderDns {
        ttl_seconds: 120,
        context: ProviderContext {
            provider_instance_id: "native".into(),
            provider_profile_version: 1,
            provider_custom: BTreeMap::new(),
        },
        provider,
        lookup: cloud,
        allowed_zones: vec!["validation.net".into()],
        dns_targets: std::collections::BTreeMap::new(),
        propagation: PropagationPolicy {
            initial_delay: Duration::from_millis(1),
            fallback_delay: Duration::from_millis(1),
            timeout: Duration::from_secs(1),
        },
        progress: progress(),
    }
}
#[tokio::test]
async fn explicit_target_is_used_by_cloudflare_through_restart_and_cleanup() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::default());
    cloud.lose_response.store(true, Ordering::SeqCst);
    let mut auto = config();
    auto.custom.remove("zone_id");
    let mut first = solver(cloud.clone(), fixture.temp.path(), &auto);
    first
        .dns_targets
        .insert("example.com".into(), "manual.validation.net.".into());
    assert!(run(&mut fixture, &first, &controls()).await.is_err());
    assert_eq!(
        cloud.remote.lock().unwrap().values().next().unwrap()["name"],
        "manual.validation.net"
    );
    cloud.changed_cname.store(true, Ordering::SeqCst);
    fixture.reopen().await;
    let mut restored = solver(cloud.clone(), fixture.temp.path(), &auto);
    restored.dns_targets = first.dns_targets;
    assert!(matches!(
        run(&mut fixture, &restored, &controls()).await.unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.deletes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn automatic_zone_survives_delegation_change_after_lost_create_response() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::default());
    cloud.lose_response.store(true, Ordering::SeqCst);
    let mut auto = config();
    auto.custom.remove("zone_id");
    let first = solver(cloud.clone(), fixture.temp.path(), &auto);
    assert!(run(&mut fixture, &first, &controls()).await.is_err());
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    let queries = cloud.discovered.load(Ordering::SeqCst);
    assert!(queries > 0);
    assert_eq!(
        cloud.remote.lock().unwrap().values().next().unwrap()["name"],
        "delegated.validation.net"
    );
    cloud.changed_cname.store(true, Ordering::SeqCst);
    fixture.reopen().await;
    let restored = solver(cloud.clone(), fixture.temp.path(), &auto);
    assert!(matches!(
        run(&mut fixture, &restored, &controls()).await.unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(cloud.discovered.load(Ordering::SeqCst), queries);
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.deletes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn native_provider_survives_lost_response_and_restart_then_validates_and_cleans_once() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::default());
    cloud.lose_response.store(true, Ordering::SeqCst);
    let first = solver(cloud.clone(), fixture.temp.path(), &config());
    assert!(run(&mut fixture, &first, &controls()).await.is_err());
    assert_eq!(fixture.count("/dns-challenge").await, 0);
    let before = fixture.session.as_ref().unwrap().record().await.unwrap();
    assert!(before.authorizations[0].publication_plan.is_some());
    assert!(before.authorizations[0].publication_receipt.is_none());
    fixture.reopen().await;
    let restored = solver(cloud.clone(), fixture.temp.path(), &config());
    let IssueOutcome::Completed { record, .. } =
        run(&mut fixture, &restored, &controls()).await.unwrap()
    else {
        panic!("native issuance did not finish")
    };
    assert_eq!(
        record.authorizations[0].publication_id,
        before.authorizations[0].publication_id
    );
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.deletes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.count("/orders/create").await, 1);
    assert_eq!(fixture.count("/dns-challenge").await, 1);
    for entry in std::fs::read_dir(fixture.temp.path().join("providers/.publications")).unwrap() {
        assert!(
            !String::from_utf8(std::fs::read(entry.unwrap().path()).unwrap())
                .unwrap()
                .contains("credential-sentinel")
        );
    }
}
#[tokio::test]
async fn saved_definition_allows_token_rotation_but_rejects_backend_or_zone_changes() {
    let fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        fixture.temp.path().into(),
        Duration::from_secs(1),
    );
    let profile = aster_acme_cli_storage::provider::ProviderProfile::builtin(
        BACKEND_ID.into(),
        config().custom,
        vec![],
    )
    .unwrap();
    store.add("native".into(), profile.clone()).await.unwrap();
    let mut record = fixture.session.as_ref().unwrap().record().await.unwrap();
    record.solver_config =
        crate::commands::cert::validation::provider::bound_provider_configuration(
            Some("native"),
            fixture.temp.path(),
        )
        .await
        .unwrap();
    assert!(
        !record
            .solver_config
            .to_string()
            .contains("credential-sentinel")
    );
    for mapping in [
        json!({"invalid name": "target.example."}),
        json!({"_acme-challenge.example.com.": "TARGET.example."}),
    ] {
        let mut tampered = record.clone();
        tampered.solver_config["dns_targets"] = mapping;
        assert!(
            crate::commands::cert::validation::provider::provider_adapter(
                &tampered,
                fixture.temp.path(),
                progress(),
                aster_acme_dns_http::ForgeDnsHttp::default()
            )
            .await
            .is_err()
        );
    }
    store
        .edit("native".into(), |profile| {
            profile
                .provider_custom
                .insert("api_token".into(), json!("rotated-token"));
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        crate::commands::cert::validation::provider::provider_adapter(
            &record,
            fixture.temp.path(),
            progress(),
            aster_acme_dns_http::ForgeDnsHttp::default()
        )
        .await
        .is_ok()
    );
    store
        .edit("native".into(), |profile| {
            profile
                .provider_custom
                .insert("zone_id".into(), json!("abcdef0123456789abcdef0123456789"));
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        crate::commands::cert::validation::provider::provider_adapter(
            &record,
            fixture.temp.path(),
            progress(),
            aster_acme_dns_http::ForgeDnsHttp::default()
        )
        .await
        .is_err()
    );
    let executable = std::env::current_exe().unwrap();
    store
        .edit("native".into(), move |profile| {
            profile.backend_id = aster_acme_dns::backend::ADPP_BACKEND_ID.into();
            profile.executable = executable;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        crate::commands::cert::validation::provider::provider_adapter(
            &record,
            fixture.temp.path(),
            progress(),
            aster_acme_dns_http::ForgeDnsHttp::default()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn provider_binding_validation_preserves_domain_targets_and_rejects_identity_drift() {
    let fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        fixture.temp.path().into(),
        Duration::from_secs(1),
    );
    store
        .add(
            "native".into(),
            aster_acme_cli_storage::provider::ProviderProfile::builtin(
                BACKEND_ID.into(),
                config().custom,
                vec![],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let mut saved = crate::commands::cert::validation::provider::bound_provider_configuration(
        Some("native"),
        fixture.temp.path(),
    )
    .await
    .unwrap();
    saved["dns_targets"] = json!({"example.com":"verify.validation.net."});
    crate::commands::cert::validation::provider::validate_provider_binding(
        &saved,
        fixture.temp.path(),
    )
    .await
    .unwrap();

    let mut bad_binding = saved.clone();
    bad_binding["backend_binding"] = json!("different-account");
    assert!(
        crate::commands::cert::validation::provider::validate_provider_binding(
            &bad_binding,
            fixture.temp.path()
        )
        .await
        .is_err()
    );
    let mut bad_backend = saved.clone();
    bad_backend["backend_id"] = json!("com.astercosm.acme.adpp");
    assert!(
        crate::commands::cert::validation::provider::validate_provider_binding(
            &bad_backend,
            fixture.temp.path()
        )
        .await
        .is_err()
    );
    let mut bad_version = saved.clone();
    bad_version["backend_config_version"] = json!(99);
    assert!(
        crate::commands::cert::validation::provider::validate_provider_binding(
            &bad_version,
            fixture.temp.path()
        )
        .await
        .is_err()
    );
    let mut changed_targets = saved.clone();
    changed_targets["dns_targets"] = json!({"example.com":"verify.other.net."});
    crate::commands::cert::validation::provider::validate_provider_binding(
        &changed_targets,
        fixture.temp.path(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn provider_binding_validation_rejects_malformed_and_missing_profiles() {
    let fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        fixture.temp.path().into(),
        Duration::from_secs(1),
    );
    store
        .add(
            "native".into(),
            aster_acme_cli_storage::provider::ProviderProfile::builtin(
                BACKEND_ID.into(),
                config().custom,
                vec![],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let saved = crate::commands::cert::validation::provider::bound_provider_configuration(
        Some("native"),
        fixture.temp.path(),
    )
    .await
    .unwrap();
    for invalid in [json!({}), json!({"unexpected":true})] {
        assert!(
            crate::commands::cert::validation::provider::validate_provider_binding(
                &invalid,
                fixture.temp.path()
            )
            .await
            .is_err()
        );
    }
    let missing = fixture.temp.path().join("missing-profile-data");
    assert!(
        crate::commands::cert::validation::provider::validate_provider_binding(&saved, &missing)
            .await
            .is_err()
    );
    assert!(
        crate::commands::cert::validation::provider::bound_provider_configuration(
            Some("../bad"),
            fixture.temp.path()
        )
        .await
        .is_err()
    );
    assert!(
        crate::commands::cert::validation::provider::bound_provider_configuration(
            Some("missing"),
            fixture.temp.path()
        )
        .await
        .is_err()
    );
    assert!(crate::commands::cert::validation::provider::provider_configuration(None).is_err());
}

#[tokio::test]
async fn provider_adapter_rejects_mapping_profile_and_saved_backend_boundaries() {
    let fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        fixture.temp.path().into(),
        Duration::from_secs(1),
    );
    store
        .add(
            "native".into(),
            aster_acme_cli_storage::provider::ProviderProfile::builtin(
                BACKEND_ID.into(),
                config().custom,
                vec![],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let mut record = fixture.session.as_ref().unwrap().record().await.unwrap();
    record.solver_config =
        crate::commands::cert::validation::provider::bound_provider_configuration(
            Some("native"),
            fixture.temp.path(),
        )
        .await
        .unwrap();
    for mapping in [
        json!({"bad..name":"target.example."}),
        json!({"other.example":"target.example."}),
    ] {
        let mut changed = record.clone();
        changed.solver_config["dns_targets"] = mapping;
        assert!(
            crate::commands::cert::validation::provider::provider_adapter(
                &changed,
                fixture.temp.path(),
                progress(),
                aster_acme_dns_http::ForgeDnsHttp::default()
            )
            .await
            .is_err()
        );
    }
    for key in [
        "backend_id",
        "backend_config_version",
        "backend_binding",
        "provider_profile_version",
    ] {
        let mut changed = record.clone();
        changed.solver_config[key] =
            if key == "backend_config_version" || key == "provider_profile_version" {
                json!(99)
            } else {
                json!("different")
            };
        assert!(
            crate::commands::cert::validation::provider::provider_adapter(
                &changed,
                fixture.temp.path(),
                progress(),
                aster_acme_dns_http::ForgeDnsHttp::default()
            )
            .await
            .is_err(),
            "{key}"
        );
    }
    let profile_path = store.path("native").unwrap();
    let mut invalid_profile: toml::Table = std::fs::read_to_string(&profile_path)
        .unwrap()
        .parse()
        .unwrap();
    invalid_profile.insert("propagation_interval".into(), toml::Value::Integer(0));
    std::fs::write(&profile_path, toml::to_string(&invalid_profile).unwrap()).unwrap();
    assert!(
        crate::commands::cert::validation::provider::provider_adapter(
            &record,
            fixture.temp.path(),
            progress(),
            aster_acme_dns_http::ForgeDnsHttp::default()
        )
        .await
        .is_err()
    );
    assert!(
        crate::commands::cert::validation::provider::provider_adapter(
            &record,
            &fixture.temp.path().join("missing-data"),
            progress(),
            aster_acme_dns_http::ForgeDnsHttp::default()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn provider_cleanup_rejects_records_saved_for_a_different_solver() {
    let fixture = Fixture::new(ValidationMethod::ManualDns).await;
    let session = fixture.session.as_ref().unwrap();
    let error = crate::commands::cert::validation::provider::cleanup_provider(
        fixture.temp.path(),
        session.as_ref(),
        crate::common::session::OutputSession::new(true),
        &aster_acme::solver::ExecutionContext {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: std::time::Instant::now() + Duration::from_secs(1),
        },
        aster_acme_dns_http::ForgeDnsHttp::default(),
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("requires DNS provider validation")
    );
    assert_eq!(
        fixture
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == "/vendor/create")
            .count(),
        0
    );
}

#[tokio::test]
async fn provider_adapter_rejects_unknown_profiles_and_invalid_saved_profile_limits() {
    let fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        fixture.temp.path().into(),
        Duration::from_secs(1),
    );
    let profile = aster_acme_cli_storage::provider::ProviderProfile::builtin(
        BACKEND_ID.into(),
        config().custom,
        vec![],
    )
    .unwrap();
    store.add("invalid".into(), profile).await.unwrap();
    let profile_path = store.path("invalid").unwrap();
    let mut invalid_profile: toml::Table = std::fs::read_to_string(&profile_path)
        .unwrap()
        .parse()
        .unwrap();
    invalid_profile.insert("propagation_interval".into(), toml::Value::Integer(0));
    std::fs::write(&profile_path, toml::to_string(&invalid_profile).unwrap()).unwrap();
    let mut record = fixture.session.as_ref().unwrap().record().await.unwrap();
    record.solver_config =
        crate::commands::cert::validation::provider::provider_configuration(Some("missing"))
            .unwrap();
    assert!(
        crate::commands::cert::validation::provider::provider_adapter(
            &record,
            fixture.temp.path(),
            progress(),
            aster_acme_dns_http::ForgeDnsHttp::default()
        )
        .await
        .is_err()
    );
    record.solver_config =
        crate::commands::cert::validation::provider::provider_configuration(Some("invalid"))
            .unwrap();
    assert!(
        crate::commands::cert::validation::provider::provider_adapter(
            &record,
            fixture.temp.path(),
            progress(),
            aster_acme_dns_http::ForgeDnsHttp::default()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn new_request_provider_binding_rejects_profile_drift_and_accepts_pinned_targets() {
    let fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        fixture.temp.path().into(),
        Duration::from_secs(1),
    );
    store
        .add(
            "native".into(),
            aster_acme_cli_storage::provider::ProviderProfile::builtin(
                BACKEND_ID.into(),
                config().custom,
                vec![],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let mut request = fixture.session.as_ref().unwrap().record().await.unwrap();
    request.solver_config =
        crate::commands::cert::validation::provider::bound_provider_configuration(
            Some("native"),
            fixture.temp.path(),
        )
        .await
        .unwrap();
    request.solver_config["dns_targets"] = json!({"example.com":"verify.validation.net."});
    let start = crate::commands::cert::execute::Start::Issue(
        crate::commands::cert::execute::IssueInput::New {
            request: aster_acme::issuance::IssueRequest {
                challenge: aster_acme::challenge::ChallengeKind::Dns01,
                solver_id: "dns_provider".into(),
                solver_config: request.solver_config.clone(),
                name: request.name.clone(),
                identifiers: request.identifiers.clone(),
                account_name: request.account_name.clone(),
                key_algorithm: request.key_algorithm,
            },
            naming: crate::commands::cert::execute::Naming::Explicit,
        },
    );
    crate::commands::cert::execute::transaction::validate_new_provider_binding(
        &start,
        fixture.temp.path(),
    )
    .await
    .unwrap();
    request.solver_config["backend_binding"] = json!("changed");
    let start = crate::commands::cert::execute::Start::Issue(
        crate::commands::cert::execute::IssueInput::New {
            request: aster_acme::issuance::IssueRequest {
                challenge: aster_acme::challenge::ChallengeKind::Dns01,
                solver_id: "dns_provider".into(),
                solver_config: request.solver_config,
                name: request.name,
                identifiers: request.identifiers,
                account_name: request.account_name,
                key_algorithm: request.key_algorithm,
            },
            naming: crate::commands::cert::execute::Naming::Explicit,
        },
    );
    assert!(
        crate::commands::cert::execute::transaction::validate_new_provider_binding(
            &start,
            fixture.temp.path()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn cancellation_after_native_api_success_saves_receipt_and_resumes_without_recreating() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::default());
    cloud.cancel_after_write.store(true, Ordering::SeqCst);
    let first = solver(cloud.clone(), fixture.temp.path(), &config());
    assert!(run(&mut fixture, &first, &controls()).await.is_err());
    let saved = fixture.session.as_ref().unwrap().record().await.unwrap();
    assert!(saved.authorizations[0].publication_receipt.is_some());
    assert!(saved.authorizations[0].cleanup_pending);
    assert_eq!(fixture.count("/dns-challenge").await, 0);
    cloud.cancel_after_write.store(false, Ordering::SeqCst);
    fixture.reopen().await;
    let restored = solver(cloud.clone(), fixture.temp.path(), &config());
    assert!(matches!(
        run(&mut fixture, &restored, &controls()).await.unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.deletes.load(Ordering::SeqCst), 1);
}

struct CancelAfterCheckpoint {
    store: aster_acme_cli_storage::provider_publication::ProviderPublicationStore,
    once: Arc<AtomicBool>,
}
struct CancelSession {
    inner: Box<dyn aster_acme_dns::operation::PublicationSession>,
    once: Arc<AtomicBool>,
    cancellation: tokio_util::sync::CancellationToken,
}
#[async_trait]
impl aster_acme_dns::operation::PublicationStore for CancelAfterCheckpoint {
    async fn open(
        &self,
        backend: &str,
        binding: &str,
        record: &aster_acme_dns::DnsRecord,
        execution: &ProviderExecution,
    ) -> Result<Box<dyn aster_acme_dns::operation::PublicationSession>, aster_acme_dns::ProviderError>
    {
        Ok(Box::new(CancelSession {
            inner: self.store.open(backend, binding, record, execution).await?,
            once: self.once.clone(),
            cancellation: execution.cancellation.clone(),
        }))
    }
}
#[async_trait]
impl aster_acme_dns::operation::PublicationSession for CancelSession {
    fn state(&self) -> Option<aster_acme_dns::operation::RecoveryState> {
        self.inner.state()
    }
    async fn save(
        &mut self,
        state: aster_acme_dns::operation::RecoveryState,
    ) -> Result<(), aster_acme_dns::ProviderError> {
        self.inner.save(state).await?;
        if self.once.swap(false, Ordering::SeqCst) {
            self.cancellation.cancel();
        }
        Ok(())
    }
}
#[tokio::test]
async fn cancellation_between_intent_and_post_persists_no_effect_and_can_retry() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::default());
    let mut first = solver(cloud.clone(), fixture.temp.path(), &config());
    first.provider = crate::commands::provider::runtime::registry()
        .unwrap()
        .provider(
            BACKEND_ID,
            &config(),
            ProviderHost {
                timeout: Duration::from_secs(5),
                http: cloud.clone(),
                credentials: None,
                publications: Arc::new(CancelAfterCheckpoint {
                    store:
                        aster_acme_cli_storage::provider_publication::ProviderPublicationStore::new(
                            fixture.temp.path().into(),
                        ),
                    once: Arc::new(AtomicBool::new(true)),
                }),
            },
        )
        .unwrap();
    assert!(run(&mut fixture, &first, &controls()).await.is_err());
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.count("/dns-challenge").await, 0);
    fixture.reopen().await;
    let restored = solver(cloud.clone(), fixture.temp.path(), &config());
    assert!(matches!(
        run(&mut fixture, &restored, &controls()).await.unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.deletes.load(Ordering::SeqCst), 1);
}
