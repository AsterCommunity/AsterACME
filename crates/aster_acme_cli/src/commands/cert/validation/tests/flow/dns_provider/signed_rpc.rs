//! Real ACME service and file-backed publication leases with mocked vendor HTTP.
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
use aster_acme::issuance::IssueOutcome;
use aster_acme_cli_storage::provider_publication::ProviderPublicationStore;
use aster_acme_dns::{
    DnsRecord, ProviderContext, ProviderErrorCode, ProviderExecution, SideEffect,
    backend::BackendConfig,
    operation::{
        HttpExecutor, HttpFailure, HttpRequest, HttpResponse, ProviderHost, PublicationStore,
    },
    propagation::PropagationPolicy,
    routing::{DnsLookup, LookupError},
};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const OWNER: &str = "delegated.validation.net.";
const ZONE: &str = "validation.net";

#[derive(Clone, Copy)]
enum Vendor {
    #[cfg(feature = "dns-aliyun")]
    Aliyun,
    #[cfg(feature = "dns-tencent-cloud")]
    DnsPod,
    #[cfg(feature = "dns-huawei-cloud")]
    Huawei,
}

impl Vendor {
    const fn id(self) -> &'static str {
        match self {
            #[cfg(feature = "dns-aliyun")]
            Self::Aliyun => aster_acme_dns_builtin::provider::aliyun::BACKEND_ID,
            #[cfg(feature = "dns-tencent-cloud")]
            Self::DnsPod => aster_acme_dns_builtin::provider::tencent_cloud::BACKEND_ID,
            #[cfg(feature = "dns-huawei-cloud")]
            Self::Huawei => aster_acme_dns_builtin::provider::huawei_cloud::BACKEND_ID,
        }
    }

    fn config(self) -> BackendConfig {
        let custom = match self {
            #[cfg(feature = "dns-aliyun")]
            Self::Aliyun => {
                json!({"access_key_id":"test-key-id", "access_key_secret":"fixture-secret"})
            }
            #[cfg(feature = "dns-tencent-cloud")]
            Self::DnsPod => json!({"secret_id":"test-key-id", "secret_key":"fixture-secret"}),
            #[cfg(feature = "dns-huawei-cloud")]
            Self::Huawei => {
                json!({"access_key_id":"test-key-id", "access_key_secret":"fixture-secret"})
            }
        };
        BackendConfig {
            custom: serde_json::from_value(custom).unwrap(),
            ..BackendConfig::default()
        }
    }
}

struct Cloud {
    vendor: Vendor,
    root: PathBuf,
    remote: Mutex<Option<Value>>,
    writes: AtomicUsize,
    deletes: AtomicUsize,
    discoveries: AtomicUsize,
    #[cfg(feature = "dns-huawei-cloud")]
    iam_queries: AtomicUsize,
    lose_response: AtomicBool,
    throttle: AtomicBool,
    check_lease: AtomicBool,
    cancel_after_write: AtomicBool,
}

impl Cloud {
    fn new(vendor: Vendor, root: &Path) -> Self {
        Self {
            vendor,
            root: root.into(),
            remote: Mutex::new(None),
            writes: AtomicUsize::new(0),
            deletes: AtomicUsize::new(0),
            discoveries: AtomicUsize::new(0),
            #[cfg(feature = "dns-huawei-cloud")]
            iam_queries: AtomicUsize::new(0),
            lose_response: AtomicBool::new(false),
            throttle: AtomicBool::new(false),
            check_lease: AtomicBool::new(true),
            cancel_after_write: AtomicBool::new(false),
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
        let contents = std::str::from_utf8(&bytes).unwrap();
        assert!(!contents.contains("fixture-secret"));
        assert!(!contents.contains("test-key-id"));
        serde_json::from_slice(&bytes).unwrap()
    }

    fn solver(self: &Arc<Self>) -> ProviderDns {
        let provider = crate::commands::provider::runtime::registry()
            .unwrap()
            .provider(
                self.vendor.id(),
                &self.vendor.config(),
                ProviderHost {
                    timeout: Duration::from_secs(5),
                    credentials: None,
                    http: self.clone(),
                    publications: Arc::new(ProviderPublicationStore::new(self.root.clone())),
                },
            )
            .unwrap();
        ProviderDns {
            ttl_seconds: 120,
            context: ProviderContext {
                provider_instance_id: "native".into(),
                provider_profile_version: 1,
                provider_custom: std::collections::BTreeMap::new(),
            },
            provider,
            lookup: self.clone(),
            allowed_zones: vec![ZONE.into()],
            dns_targets: std::collections::BTreeMap::new(),
            propagation: PropagationPolicy {
                initial_delay: Duration::from_millis(1),
                fallback_delay: Duration::from_millis(1),
                timeout: Duration::from_secs(1),
            },
            progress: progress(),
        }
    }

    fn request(&self, request: &HttpRequest, action: &str) -> Value {
        #[cfg(not(any(feature = "dns-aliyun", feature = "dns-tencent-cloud")))]
        let _ = action;
        let mut remote = self.remote.lock().unwrap();
        match self.vendor {
            #[cfg(feature = "dns-aliyun")]
            Vendor::Aliyun => self.ali(request, action, &mut remote),
            #[cfg(feature = "dns-tencent-cloud")]
            Vendor::DnsPod => self.dnspod(request, action, &mut remote),
            #[cfg(feature = "dns-huawei-cloud")]
            Vendor::Huawei => self.huawei(request, &mut remote),
        }
    }

    #[cfg(feature = "dns-aliyun")]
    fn ali(&self, request: &HttpRequest, action: &str, remote: &mut Option<Value>) -> Value {
        assert!(request.url.starts_with("https://alidns.aliyuncs.com/"));
        assert_eq!(request.method.as_str(), "GET");
        let (_, query) = request.url.split_once('?').unwrap();
        let params: std::collections::BTreeMap<_, _> = query
            .split('&')
            .map(|pair| pair.split_once('=').unwrap())
            .collect();
        let zone = json!({"DomainId":"ali-zone-id","DomainName":ZONE,"MinTtl":300});
        match action {
            "DescribeDomains" => {
                self.discoveries.fetch_add(1, Ordering::SeqCst);
                json!({"TotalCount":1,"PageSize":100,"PageNumber":1,"Domains":{"Domain":[zone]}})
            }
            "DescribeDomainInfo" => {
                assert_eq!(params["DomainName"], ZONE);
                assert_eq!(params["NeedDetailAttributes"], "true");
                zone
            }
            "DescribeDomainRecords" => {
                assert_eq!(params["RRKeyWord"], "delegated");
                json!({"TotalCount":usize::from(remote.is_some()),"PageSize":100,"PageNumber":1,
                    "DomainRecords":{"Record":remote.iter().collect::<Vec<_>>()}})
            }
            "AddDomainRecord" => {
                assert_eq!(params["RR"], "delegated");
                assert_eq!(params["TTL"], "300");
                assert!(remote.is_none());
                *remote = Some(
                    json!({"DomainId":"ali-zone-id","DomainName":ZONE,"RR":"delegated","Type":"TXT",
                    "Value":params["Value"],"RecordId":"23","TTL":300,"Line":"default","Status":"Enable"}),
                );
                self.writes.fetch_add(1, Ordering::SeqCst);
                json!({"RecordId":"23"})
            }
            "UpdateDomainRecordRemark" => {
                assert_eq!(params["RecordId"], "23");
                let remark = params["Remark"].replace("%2D", "-");
                assert!(remark.starts_with("acme-"));
                let record = remote
                    .as_mut()
                    .expect("remark update requires created record");
                record["Remark"] = json!(remark);
                json!({"RequestId":"ali-remark-request"})
            }
            "DescribeDomainRecordInfo" => {
                assert_eq!(params["RecordId"], "23");
                let mut body = remote.clone().unwrap();
                body.as_object_mut().unwrap().remove("DomainId");
                body
            }
            "DeleteDomainRecord" => {
                assert_eq!(params["RecordId"], "23");
                self.deletes.fetch_add(1, Ordering::SeqCst);
                *remote = None;
                json!({"RecordId":"23"})
            }
            _ => panic!("unexpected action {action}"),
        }
    }

    #[cfg(feature = "dns-tencent-cloud")]
    fn dnspod(&self, request: &HttpRequest, action: &str, remote: &mut Option<Value>) -> Value {
        assert_eq!(request.url, "https://dnspod.tencentcloudapi.com/");
        assert_eq!(request.method.as_str(), "POST");
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        if action != "DescribeDomainList" {
            assert_eq!(body["DomainId"], 42);
        }
        let mut result = match action {
            "DescribeDomainList" => {
                self.discoveries.fetch_add(1, Ordering::SeqCst);
                json!({"DomainCountInfo":{"DomainTotal":1},"DomainList":[{"Name":ZONE,"DomainId":42}]})
            }
            "DescribeRecordList" => {
                assert_eq!(body["SubDomain"], "delegated");
                let count = usize::from(remote.is_some());
                json!({"RecordCountInfo":{"TotalCount":count,"ListCount":count},"RecordList":remote.iter().collect::<Vec<_>>()})
            }
            "CreateTXTRecord" => {
                assert_eq!(body["Domain"], "validation.net");
                assert_eq!(body["SubDomain"], "delegated");
                assert_eq!(body["RecordLine"], "默认");
                assert_eq!(body["TTL"], 600);
                assert!(remote.is_none());
                assert!(body["Remark"].as_str().unwrap().starts_with("asteracme-"));
                *remote = Some(
                    json!({"RecordId":23,"Name":"delegated","Type":"TXT","Value":body["Value"],
                    "Remark":body["Remark"],"TTL":600,"LineId":"0","Status":"ENABLE"}),
                );
                self.writes.fetch_add(1, Ordering::SeqCst);
                json!({"RecordId":23})
            }
            "DescribeRecord" => {
                assert_eq!(body["RecordId"], 23);
                let record = remote.as_ref().unwrap();
                json!({"RecordInfo":{"Id":23,"DomainId":42,"SubDomain":"delegated","RecordType":"TXT","RecordLineId":"0",
                    "Value":record["Value"],"Remark":record["Remark"],"TTL":600,"Enabled":1}})
            }
            "DeleteRecord" => {
                assert_eq!(body["RecordId"], 23);
                self.deletes.fetch_add(1, Ordering::SeqCst);
                *remote = None;
                json!({})
            }
            _ => panic!("unexpected action {action}"),
        };
        result["RequestId"] = json!("req-mock");
        json!({"Response":result})
    }

    #[cfg(feature = "dns-huawei-cloud")]
    fn huawei(&self, request: &HttpRequest, remote: &mut Option<Value>) -> Value {
        assert!(request.url.starts_with("https://") && request.url.contains("myhuaweicloud.com/"));
        if request.url.contains("iam.") {
            assert!(request.url.contains("/v3/projects?name=cn-north-4"));
            assert!(
                request
                    .headers
                    .iter()
                    .any(|(key, value)| key == "authorization"
                        && value.contains("SignedHeaders=x-sdk-date"))
            );
        } else {
            assert!(request.url.contains("/v2/"));
            assert!(
                request
                    .headers
                    .iter()
                    .any(|(key, value)| key == "x-project-id"
                        && value == "0123456789abcdef0123456789abcdef")
            );
            assert!(
                request
                    .headers
                    .iter()
                    .any(|(key, value)| key == "authorization"
                        && value.contains("SignedHeaders=x-project-id;x-sdk-date"))
            );
        }
        let url = url::Url::parse(&request.url).unwrap();
        if url.path() == "/v3/projects" {
            self.iam_queries.fetch_add(1, Ordering::SeqCst);
            assert!(
                url.query_pairs()
                    .any(|(name, value)| name == "name" && value == "cn-north-4")
            );
            return json!({"projects":[{"id":"0123456789abcdef0123456789abcdef", "name":"cn-north-4"}]});
        }
        if url.path() == "/v2/zones" {
            self.discoveries.fetch_add(1, Ordering::SeqCst);
            return json!({"zones":[{"id":"huawei-zone-id", "name":"validation.net."}]});
        }
        match request.method.as_str() {
            "GET" => json!({"recordsets":remote.iter().collect::<Vec<_>>()}),
            "POST" => {
                assert!(remote.is_none());
                let mut body: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["name"], OWNER);
                assert_eq!(body["ttl"], 300);
                let value: String =
                    serde_json::from_str(body["records"][0].as_str().unwrap()).unwrap();
                body["Value"] = json!(value);
                body["id"] = json!("huawei-recordset-id");
                body["zone_id"] = json!("huawei-zone-id");
                body["status"] = json!("ACTIVE");
                *remote = Some(body.clone());
                self.writes.fetch_add(1, Ordering::SeqCst);
                body
            }
            "PUT" => {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let set = remote.as_mut().unwrap();
                set["records"] = body["records"].clone();
                set["description"] = body["description"].clone();
                set.clone()
            }
            "DELETE" => {
                assert!(request.url.ends_with("/recordsets/huawei-recordset-id"));
                self.deletes.fetch_add(1, Ordering::SeqCst);
                *remote = None;
                json!({})
            }
            _ => panic!("unexpected Huawei request"),
        }
    }

    fn throttle_body(&self) -> Value {
        match self.vendor {
            #[cfg(feature = "dns-aliyun")]
            Vendor::Aliyun => json!({"Code":"Throttling.User","Message":"fixture-secret"}),
            #[cfg(feature = "dns-huawei-cloud")]
            Vendor::Huawei => json!({"code":"APIG.0308", "message":"fixture-secret"}),
            #[cfg(feature = "dns-tencent-cloud")]
            Vendor::DnsPod => {
                json!({"Response":{"Error":{"Code":"RequestLimitExceeded","Message":"fixture-secret"}}})
            }
        }
    }
}

#[async_trait]
impl HttpExecutor for Cloud {
    async fn execute(
        &self,
        request: HttpRequest,
        execution: &ProviderExecution,
    ) -> Result<HttpResponse, HttpFailure> {
        let action = request
            .headers
            .iter()
            .find(|(key, _)| matches!(key.as_str(), "x-acs-action" | "x-tc-action"))
            .map_or("", |(_, value)| value.as_str());
        let creating = matches!(action, "AddDomainRecord" | "CreateTXTRecord")
            || request.method == aster_acme_dns::operation::HttpMethod::Post && action.is_empty();
        let remarking = action == "UpdateDomainRecordRemark";
        if request.mutation {
            let cp = self.checkpoint();
            assert_eq!(cp["record"]["name"], OWNER);
            assert_eq!(cp["record"]["ttl_seconds"], 120);
            let phase = &cp["state"]["data"]["phase"];
            if phase.is_string() {
                assert_eq!(
                    phase,
                    if creating {
                        "present_intent"
                    } else {
                        "cleanup_intent"
                    }
                );
            } else {
                assert_eq!(
                    phase["state"],
                    if creating {
                        "create_intent"
                    } else if remarking {
                        "remark_intent"
                    } else {
                        "delete_intent"
                    }
                );
            }
            if self.check_lease.swap(false, Ordering::SeqCst) {
                let root = self.root.clone();
                let backend = self.vendor.id();
                let status = tokio::task::spawn_blocking(move || {
                    std::process::Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--ignored",
                            "--exact",
                            concat!(module_path!(), "::cross_process_contender")
                                .split_once("::")
                                .unwrap()
                                .1,
                        ])
                        .env("ASTER_SIGNED_DNS_TEST_ROOT", root)
                        .env("ASTER_SIGNED_DNS_TEST_BACKEND", backend)
                        .output()
                        .unwrap()
                })
                .await
                .unwrap();
                assert!(
                    status.status.success(),
                    "{}",
                    String::from_utf8_lossy(&status.stdout)
                );
                assert!(String::from_utf8_lossy(&status.stdout).contains("1 passed"));
            }
        }
        if creating && self.throttle.swap(false, Ordering::SeqCst) {
            return Ok(HttpResponse {
                status: 429,
                headers: vec![("retry-after".into(), b"75".to_vec())],
                body: serde_json::to_vec(&self.throttle_body()).unwrap(),
            });
        }
        let body = self.request(&request, action);
        if creating && self.cancel_after_write.load(Ordering::SeqCst) {
            execution.cancellation.cancel();
        }
        if creating && self.lose_response.swap(false, Ordering::SeqCst) {
            return Err(HttpFailure {
                code: ProviderErrorCode::ProviderTimeout,
                side_effect: SideEffect::Unknown,
            });
        }
        Ok(HttpResponse {
            status: 200,
            body: serde_json::to_vec(&body).unwrap(),
            headers: vec![],
        })
    }
}

#[async_trait]
impl DnsLookup for Cloud {
    async fn cname(&self, name: &str) -> Result<Option<String>, LookupError> {
        Ok((name == "_acme-challenge.example.com.").then(|| OWNER.into()))
    }

    async fn txt(&self, name: &str) -> Result<Vec<Vec<u8>>, LookupError> {
        assert_eq!(name, "_acme-challenge.example.com.");
        Ok(self
            .remote
            .lock()
            .unwrap()
            .iter()
            .map(|record| record["Value"].as_str().unwrap().as_bytes().to_vec())
            .collect())
    }
}

#[tokio::test]
#[ignore = "child process fixture"]
async fn cross_process_contender() {
    let Ok(root) = std::env::var("ASTER_SIGNED_DNS_TEST_ROOT") else {
        return;
    };
    let backend = std::env::var("ASTER_SIGNED_DNS_TEST_BACKEND").unwrap();
    let other = DnsRecord {
        publication_id: "competing-process".into(),
        challenge_name: "elsewhere.example.".into(),
        cname_chain: vec![],
        name: OWNER.into(),
        value: "other-value".into(),
        ttl_seconds: None,
    };
    let store = ProviderPublicationStore::new(root.into());
    let deadline = Instant::now() + Duration::from_millis(100);
    let result = store
        .open(
            &backend,
            "other-scope",
            &other,
            &ProviderExecution {
                cancellation: tokio_util::sync::CancellationToken::new(),
                deadline,
            },
        )
        .await;
    assert!(result.is_err());
    assert!(
        Instant::now() >= deadline,
        "the other process did not contend for the lease"
    );
}

#[cfg(feature = "dns-aliyun")]
#[tokio::test]
async fn aliyun_persists_record_id_and_effective_ttl_through_issuance_and_cleanup() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::new(Vendor::Aliyun, fixture.temp.path()));
    let IssueOutcome::Completed { record, .. } = run(&mut fixture, &cloud.solver(), &controls())
        .await
        .unwrap()
    else {
        panic!("issuance did not complete");
    };
    let receipt = record.authorizations[0]
        .publication_receipt
        .as_ref()
        .unwrap();
    assert_eq!(receipt.record_id, "23");
    assert_eq!(receipt.effective_ttl_seconds, Some(300));
    assert_eq!(cloud.checkpoint()["state"]["data"]["phase"]["id"], "23");
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.deletes.load(Ordering::SeqCst), 1);
    assert!(cloud.remote.lock().unwrap().is_none());
}

#[cfg(feature = "dns-aliyun")]
#[tokio::test]
async fn aliyun_unknown_create_never_replays_or_acknowledges_an_unowned_txt() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::new(Vendor::Aliyun, fixture.temp.path()));
    cloud.lose_response.store(true, Ordering::SeqCst);
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
    assert_eq!(cloud.discoveries.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.deletes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.count("/dns-challenge").await, 0);
    assert_eq!(
        cloud.checkpoint()["state"]["data"]["phase"]["state"],
        "create_intent"
    );
    assert!(cloud.remote.lock().unwrap().is_some());
}

#[cfg(feature = "dns-tencent-cloud")]
#[tokio::test]
async fn dnspod_lost_create_recovers_from_files_and_cleans_after_loopback_ca_ack() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::new(Vendor::DnsPod, fixture.temp.path()));
    cloud.lose_response.store(true, Ordering::SeqCst);
    assert!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .is_err()
    );
    assert_eq!(fixture.count("/dns-challenge").await, 0);
    fixture.reopen().await;
    assert!(matches!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(fixture.count("/orders/create").await, 1);
    assert_eq!(fixture.count("/dns-challenge").await, 1);
    assert_eq!(cloud.discoveries.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.deletes.load(Ordering::SeqCst), 1);
    assert!(cloud.remote.lock().unwrap().is_none());
}

#[tokio::test]
async fn vendor_throttle_persists_retry_floor_and_blocks_an_early_restart() {
    let vendors = [
        #[cfg(feature = "dns-aliyun")]
        Vendor::Aliyun,
        #[cfg(feature = "dns-tencent-cloud")]
        Vendor::DnsPod,
        #[cfg(feature = "dns-huawei-cloud")]
        Vendor::Huawei,
    ];
    for vendor in vendors {
        let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
        let cloud = Arc::new(Cloud::new(vendor, fixture.temp.path()));
        cloud.throttle.store(true, Ordering::SeqCst);
        let start = time::OffsetDateTime::now_utc();
        let Err(error) = run(&mut fixture, &cloud.solver(), &controls()).await else {
            panic!("throttled publication unexpectedly completed")
        };
        assert!(!error.to_string().contains("fixture-secret"));
        let saved = fixture.session.as_ref().unwrap().record().await.unwrap();
        assert!(
            saved.authorizations[0].publication_retry_at.unwrap()
                >= start + time::Duration::seconds(74)
        );
        let phase = cloud.checkpoint()["state"]["data"]["phase"].clone();
        assert_eq!(
            phase
                .as_str()
                .unwrap_or_else(|| phase["state"].as_str().unwrap()),
            "rejected"
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
}

#[cfg(feature = "dns-huawei-cloud")]
#[tokio::test]
async fn huawei_lost_create_reconciles_files_and_validates_then_cleans_exact_rrset() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::new(Vendor::Huawei, fixture.temp.path()));
    cloud.lose_response.store(true, Ordering::SeqCst);
    assert!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .is_err()
    );
    assert_eq!(fixture.count("/dns-challenge").await, 0);
    assert_eq!(cloud.iam_queries.load(Ordering::SeqCst), 1);
    assert_eq!(
        cloud.checkpoint()["state"]["data"]["resolved_project_id"],
        "0123456789abcdef0123456789abcdef"
    );
    assert_eq!(
        cloud.checkpoint()["state"]["data"]["phase"],
        "present_intent"
    );
    fixture.reopen().await;
    let IssueOutcome::Completed { record, .. } = run(&mut fixture, &cloud.solver(), &controls())
        .await
        .unwrap()
    else {
        panic!("issuance did not finish");
    };
    assert_eq!(
        record.authorizations[0]
            .publication_receipt
            .as_ref()
            .unwrap()
            .effective_ttl_seconds,
        Some(300)
    );
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.iam_queries.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.discoveries.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.deletes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.count("/dns-challenge").await, 1);
    assert!(cloud.remote.lock().unwrap().is_none());
}

#[cfg(feature = "dns-huawei-cloud")]
#[tokio::test]
async fn huawei_cancel_after_remote_write_keeps_durable_id_and_resumes_without_replay() {
    let mut fixture = Fixture::new(ValidationMethod::DnsProvider).await;
    let cloud = Arc::new(Cloud::new(Vendor::Huawei, fixture.temp.path()));
    cloud.cancel_after_write.store(true, Ordering::SeqCst);
    assert!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .is_err()
    );
    assert_eq!(fixture.count("/dns-challenge").await, 0);
    assert_eq!(
        cloud.checkpoint()["state"]["data"]["recordset_id"],
        "huawei-recordset-id"
    );
    cloud.cancel_after_write.store(false, Ordering::SeqCst);
    fixture.reopen().await;
    assert!(matches!(
        run(&mut fixture, &cloud.solver(), &controls())
            .await
            .unwrap(),
        IssueOutcome::Completed { .. }
    ));
    assert_eq!(cloud.writes.load(Ordering::SeqCst), 1);
    assert_eq!(cloud.deletes.load(Ordering::SeqCst), 1);
}
