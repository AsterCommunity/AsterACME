use crate::{
    DnsRecord, ProviderContext, ProviderError, ProviderErrorCode, ProviderExecution,
    RecordOwnership, SideEffect,
    backend::{
        BackendConfig, BackendDescriptor, BackendImplementation, DnsBackend, ProviderRegistry,
        configuration_error,
    },
    operation::{
        CredentialReader, HttpExecutor, HttpFailure, HttpRequest, HttpResponse, OperationFactory,
        ProviderAction, ProviderEffect, ProviderEvent, ProviderHost, ProviderOperation,
        ProviderOutcome, PublicationSession, PublicationStore, RecoveryState,
    },
};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
#[derive(Default, PartialEq)]
enum CancellationPoint {
    #[default]
    Never,
    Response,
    Checkpoint,
}

#[derive(Clone, Copy)]
enum SpecialMode {
    Secret,
    Wait,
    InvalidCheckpoint,
    MutationWithoutCheckpoint,
    WrongOutcome,
}

struct SpecialBackend(SpecialMode);
struct SpecialFactory(SpecialMode);
struct SpecialOperation {
    record: DnsRecord,
    mode: SpecialMode,
}

impl DnsBackend for SpecialBackend {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            id: "com.example.dns.special",
            label: "Special",
            config_version: 1,
            executable: false,
            mutation_model: crate::backend::MutationModel::IndividualRecords,
            fields: &[],
        }
    }
    fn validate(&self, _: &BackendConfig) -> Result<(), ProviderError> {
        Ok(())
    }
    fn binding(&self, _: &BackendConfig) -> Result<String, ProviderError> {
        Ok("special".into())
    }
    fn create(&self, _: &BackendConfig) -> Result<BackendImplementation, ProviderError> {
        let mode = self.0;
        Ok(BackendImplementation::Native(Arc::new(SpecialFactory(
            mode,
        ))))
    }
}

impl OperationFactory for SpecialFactory {
    fn start(
        &self,
        action: ProviderAction,
        _: Option<RecoveryState>,
    ) -> Result<Box<dyn ProviderOperation>, ProviderError> {
        let ProviderAction::Present(record) = action else {
            return Err(configuration_error("special backend only presents"));
        };
        let mode = self.0;
        Ok(Box::new(SpecialOperation { record, mode }))
    }
}

impl ProviderOperation for SpecialOperation {
    fn advance(&mut self, event: ProviderEvent) -> Result<ProviderEffect, ProviderError> {
        match (&self.mode, event) {
            (SpecialMode::Secret, ProviderEvent::Start) => {
                Ok(ProviderEffect::ReadSecret("/private/token".into()))
            }
            (SpecialMode::Secret, ProviderEvent::Secret(value)) => {
                if value == "token" {
                    Ok(ProviderEffect::Complete(ProviderOutcome::Presented(
                        crate::PublicationReceipt {
                            effective_ttl_seconds: None,
                            record_id: "secret-record".into(),
                            ownership: RecordOwnership::Created,
                            record_name: self.record.name.clone(),
                            cname_chain: self.record.cname_chain.clone(),
                        },
                    )))
                } else {
                    Err(configuration_error("unexpected secret"))
                }
            }
            (SpecialMode::Wait, ProviderEvent::Start) => Ok(ProviderEffect::WaitUntil(
                Instant::now() + Duration::from_millis(1),
            )),
            (SpecialMode::Wait, ProviderEvent::Timer) => Ok(ProviderEffect::Complete(
                ProviderOutcome::Presented(crate::PublicationReceipt {
                    effective_ttl_seconds: None,
                    record_id: "wait-record".into(),
                    ownership: RecordOwnership::Created,
                    record_name: self.record.name.clone(),
                    cname_chain: self.record.cname_chain.clone(),
                }),
            )),
            (SpecialMode::InvalidCheckpoint, ProviderEvent::Start) => {
                Ok(ProviderEffect::Checkpoint(RecoveryState {
                    version: 0,
                    data: serde_json::json!({}),
                }))
            }
            (SpecialMode::MutationWithoutCheckpoint, ProviderEvent::Start) => {
                Ok(ProviderEffect::Http(HttpRequest {
                    method: "POST".into(),
                    url: "https://dns.example/mutation".into(),
                    headers: vec![],
                    body: vec![],
                    mutation: true,
                }))
            }
            (SpecialMode::WrongOutcome, ProviderEvent::Start) => Ok(ProviderEffect::Complete(
                ProviderOutcome::Cleaned(crate::CleanupStatus::Removed),
            )),
            _ => Err(configuration_error("unexpected special event")),
        }
    }
}

struct SecretReader;
#[async_trait]
impl CredentialReader for SecretReader {
    async fn read(
        &self,
        _: &std::path::Path,
        _: &ProviderExecution,
    ) -> Result<String, ProviderError> {
        Ok("token".into())
    }
}

fn special_provider(mode: SpecialMode, credentials: bool) -> Arc<dyn crate::DnsProvider> {
    let host = Arc::new(Host::default());
    ProviderRegistry::new(vec![Arc::new(SpecialBackend(mode))])
        .unwrap()
        .provider(
            "com.example.dns.special",
            &BackendConfig::default(),
            ProviderHost {
                timeout: Duration::from_secs(1),
                credentials: credentials
                    .then(|| Arc::new(SecretReader) as Arc<dyn CredentialReader>),
                http: host.clone(),
                publications: Arc::new(Store(host)),
            },
        )
        .unwrap()
}
#[derive(Default)]
struct Host {
    trace: Mutex<Vec<&'static str>>,
    states: Mutex<BTreeMap<String, RecoveryState>>,
    fail_save: bool,
    fail_record: bool,
    delay: bool,
    cancellation_point: CancellationPoint,
}
struct Session {
    host: Arc<Host>,
    id: String,
    cancellation: tokio_util::sync::CancellationToken,
}
struct Store(Arc<Host>);
#[async_trait]
impl PublicationStore for Store {
    async fn open(
        &self,
        _: &str,
        _: &str,
        record: &DnsRecord,
        execution: &ProviderExecution,
    ) -> Result<Box<dyn PublicationSession>, ProviderError> {
        self.0.trace.lock().unwrap().push("bind");
        Ok(Box::new(Session {
            host: self.0.clone(),
            id: record.publication_id.clone(),
            cancellation: execution.cancellation.clone(),
        }))
    }
}
#[async_trait]
impl PublicationSession for Session {
    fn state(&self) -> Option<RecoveryState> {
        self.host.states.lock().unwrap().get(&self.id).cloned()
    }
    async fn save(&mut self, state: RecoveryState) -> Result<(), ProviderError> {
        self.host.trace.lock().unwrap().push("save");
        if self.host.fail_save {
            return Err(configuration_error("checkpoint failed"));
        }
        self.host
            .states
            .lock()
            .unwrap()
            .insert(self.id.clone(), state);
        if self.host.cancellation_point == CancellationPoint::Checkpoint {
            self.cancellation.cancel();
        }
        Ok(())
    }
}
#[async_trait]
impl HttpExecutor for Host {
    async fn execute(
        &self,
        request: HttpRequest,
        execution: &ProviderExecution,
    ) -> Result<HttpResponse, HttpFailure> {
        self.trace.lock().unwrap().push("http");
        if self.delay {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        if self.cancellation_point == CancellationPoint::Response {
            execution.cancellation.cancel();
        }
        Ok(HttpResponse {
            status: if self.fail_record && request.url.ends_with("second") {
                403
            } else {
                200
            },
            headers: vec![],
            body: vec![],
        })
    }
}
struct Backend {
    id: &'static str,
    checkpoint: bool,
}
impl DnsBackend for Backend {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            id: self.id,
            label: "Test",
            config_version: 1,
            executable: false,
            mutation_model: crate::backend::MutationModel::IndividualRecords,
            fields: &[],
        }
    }
    fn validate(&self, _: &BackendConfig) -> Result<(), ProviderError> {
        Ok(())
    }
    fn binding(&self, _: &BackendConfig) -> Result<String, ProviderError> {
        Ok("zone".into())
    }
    fn create(&self, _: &BackendConfig) -> Result<BackendImplementation, ProviderError> {
        Ok(BackendImplementation::Native(Arc::new(Factory(
            self.checkpoint,
        ))))
    }
}
struct Factory(bool);
struct Operation {
    record: DnsRecord,
    checkpoint: bool,
}
impl OperationFactory for Factory {
    fn start(
        &self,
        action: ProviderAction,
        _: Option<RecoveryState>,
    ) -> Result<Box<dyn ProviderOperation>, ProviderError> {
        let ProviderAction::Present(record) = action else {
            return Err(configuration_error("only present"));
        };
        Ok(Box::new(Operation {
            record,
            checkpoint: self.0,
        }))
    }
}
impl ProviderOperation for Operation {
    fn advance(&mut self, event: ProviderEvent) -> Result<ProviderEffect, ProviderError> {
        match event {
            ProviderEvent::Start if self.checkpoint => {
                Ok(ProviderEffect::Checkpoint(RecoveryState {
                    version: 1,
                    data: serde_json::json!({"intent":"present"}),
                }))
            }
            ProviderEvent::Start | ProviderEvent::CheckpointSaved => {
                Ok(ProviderEffect::Http(HttpRequest {
                    method: "POST".into(),
                    url: format!("https://dns.example/{}", self.record.publication_id),
                    headers: vec![],
                    body: vec![],
                    mutation: true,
                }))
            }
            ProviderEvent::Http(Ok(response)) if response.status == 200 => Ok(
                ProviderEffect::Complete(ProviderOutcome::Presented(crate::PublicationReceipt {
                    effective_ttl_seconds: None,
                    record_id: "record".into(),
                    ownership: RecordOwnership::Created,
                    record_name: self.record.name.clone(),
                    cname_chain: self.record.cname_chain.clone(),
                })),
            ),
            ProviderEvent::Http(Err(failure)) => Err(ProviderError {
                code: failure.code,
                side_effect: failure.side_effect,
                message: "HTTP execution failed".into(),
                retry_after_seconds: None,
                provider_code: None,
            }),
            ProviderEvent::Http(Ok(_)) => Err(configuration_error("provider operation failed")),
            _ => Err(configuration_error("unexpected event")),
        }
    }
}
fn record(id: &str) -> DnsRecord {
    DnsRecord {
        publication_id: id.into(),
        challenge_name: "_acme-challenge.example.com.".into(),
        cname_chain: vec!["_acme-challenge.example.com.".into()],
        name: "_acme-challenge.example.com.".into(),
        value: "value".into(),
        ttl_seconds: None,
    }
}
fn scope() -> ProviderExecution {
    ProviderExecution {
        cancellation: tokio_util::sync::CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(2),
    }
}
fn context() -> ProviderContext {
    ProviderContext {
        provider_instance_id: "test".into(),
        provider_profile_version: 1,
        provider_custom: BTreeMap::new(),
    }
}
fn provider(host: Arc<Host>, checkpoint: bool) -> Arc<dyn crate::DnsProvider> {
    ProviderRegistry::new(vec![Arc::new(Backend {
        id: "com.example.dns.test",
        checkpoint,
    })])
    .unwrap()
    .provider(
        "com.example.dns.test",
        &BackendConfig::default(),
        ProviderHost {
            timeout: Duration::from_secs(1),
            credentials: None,
            http: host.clone(),
            publications: Arc::new(Store(host)),
        },
    )
    .unwrap()
}
#[tokio::test]
async fn writes_follow_durable_binding_and_checkpoint_and_partial_success_is_preserved() {
    let host = Arc::new(Host {
        fail_record: true,
        ..Host::default()
    });
    let result = provider(host.clone(), true)
        .present(&context(), &[record("first"), record("second")], &scope())
        .await
        .unwrap();
    assert!(result[0].result.is_ok());
    assert!(result[1].result.is_err());
    assert_eq!(
        *host.trace.lock().unwrap(),
        ["bind", "save", "http", "bind", "save", "http"]
    );
}
#[tokio::test]
async fn failed_checkpoint_or_missing_intent_never_sends_a_mutation() {
    for (fail_save, checkpoint) in [(true, true), (false, false)] {
        let host = Arc::new(Host {
            fail_save,
            ..Host::default()
        });
        let result = provider(host.clone(), checkpoint)
            .present(&context(), &[record("first")], &scope())
            .await
            .unwrap();
        assert!(result[0].result.is_err());
        assert!(!host.trace.lock().unwrap().contains(&"http"));
    }
}
#[tokio::test]
async fn cancellation_and_timeout_stop_even_a_transport_that_ignores_the_budget() {
    for cancelled in [false, true] {
        let host = Arc::new(Host {
            delay: true,
            ..Host::default()
        });
        let provider = provider(host, true);
        let mut execution = scope();
        execution.deadline = Instant::now() + Duration::from_millis(30);
        if cancelled {
            execution.cancellation.cancel();
        }
        let before = Instant::now();
        let result = provider
            .present(&context(), &[record("first")], &execution)
            .await
            .unwrap();
        assert!(before.elapsed() < Duration::from_secs(1));
        assert!(
            matches!(&result[0].result,Err(error) if error.code==ProviderErrorCode::ProviderTimeout && (cancelled || error.side_effect==SideEffect::Unknown))
        );
    }
}
#[test]
fn isolated_registry_rejects_duplicates_unknown_ids_and_invalid_descriptors() {
    assert!(
        ProviderRegistry::new(vec![
            Arc::new(Backend {
                id: "com.example.dns.test",
                checkpoint: true
            }),
            Arc::new(Backend {
                id: "com.example.dns.test",
                checkpoint: true
            })
        ])
        .is_err()
    );
    assert!(
        ProviderRegistry::new(vec![Arc::new(Backend {
            id: "bad",
            checkpoint: true
        })])
        .is_err()
    );
    let registry = ProviderRegistry::new(vec![
        Arc::new(Backend {
            id: "com.example.dns.z",
            checkpoint: true,
        }),
        Arc::new(Backend {
            id: "com.example.dns.a",
            checkpoint: true,
        }),
    ])
    .unwrap();
    assert_eq!(
        registry
            .descriptors()
            .iter()
            .map(|d| d.id)
            .collect::<Vec<_>>(),
        ["com.example.dns.a", "com.example.dns.z"]
    );
    assert!(registry.require("com.example.dns.missing").is_err());
    assert!(
        ProviderRegistry::new(vec![])
            .unwrap()
            .descriptors()
            .is_empty()
    );
}

#[tokio::test]
async fn invalid_batch_size_or_duplicate_identity_is_rejected_before_any_host_effect() {
    let host = Arc::new(Host::default());
    let provider = provider(host.clone(), true);
    for records in [
        vec![],
        vec![record("same"), record("same")],
        vec![record("bad/id")],
        (0..101).map(|id| record(&format!("pub-{id}"))).collect(),
    ] {
        assert!(
            provider
                .present(&context(), &records, &scope())
                .await
                .is_err()
        );
        assert!(host.trace.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn cancellation_does_not_discard_an_already_observed_success() {
    let host = Arc::new(Host {
        cancellation_point: CancellationPoint::Response,
        ..Host::default()
    });
    let provider = provider(host.clone(), true);
    let execution = scope();
    let result = provider
        .present(&context(), &[record("first")], &execution)
        .await
        .unwrap();
    assert!(execution.cancellation.is_cancelled());
    assert!(result[0].result.is_ok());
    assert_eq!(*host.trace.lock().unwrap(), ["bind", "save", "http"]);
}

#[tokio::test]
async fn cancellation_after_checkpoint_synthesizes_no_effect_without_dispatch() {
    let host = Arc::new(Host {
        cancellation_point: CancellationPoint::Checkpoint,
        ..Host::default()
    });
    let provider = provider(host.clone(), true);
    let result = provider
        .present(&context(), &[record("first")], &scope())
        .await
        .unwrap();
    assert!(matches!(&result[0].result,Err(error) if error.side_effect==SideEffect::None));
    assert_eq!(*host.trace.lock().unwrap(), ["bind", "save"]);
}

#[tokio::test]
async fn special_operations_cover_secret_wait_checkpoint_and_outcome_boundaries() {
    let secret = special_provider(SpecialMode::Secret, true)
        .present(&context(), &[record("secret")], &scope())
        .await
        .unwrap();
    assert!(secret[0].result.is_ok());

    let missing = special_provider(SpecialMode::Secret, false)
        .present(&context(), &[record("missing")], &scope())
        .await
        .unwrap();
    assert!(matches!(
        missing[0].result,
        Err(ref error) if error.code == ProviderErrorCode::CredentialsUnavailable
    ));

    let waited = special_provider(SpecialMode::Wait, false)
        .present(&context(), &[record("wait")], &scope())
        .await
        .unwrap();
    assert!(waited[0].result.is_ok());

    for mode in [
        SpecialMode::InvalidCheckpoint,
        SpecialMode::MutationWithoutCheckpoint,
    ] {
        let failed = special_provider(mode, false)
            .present(&context(), &[record("invalid")], &scope())
            .await
            .unwrap();
        assert!(failed[0].result.is_err());
    }

    let wrong = special_provider(SpecialMode::WrongOutcome, false)
        .present(&context(), &[record("wrong")], &scope())
        .await
        .unwrap();
    assert!(matches!(
        wrong[0].result,
        Err(ref error) if error.code == ProviderErrorCode::InvalidRequest
    ));
}
