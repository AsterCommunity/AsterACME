//! Batch outcomes and cancellation are independent of transport timing and terminal state.
use super::*;
use aster_acme::issuance::{DnsRequirement, IssueOutcome};
use std::cell::RefCell;

fn record(name: &str) -> IssueRecord {
    let mut record: IssueRecord = serde_json::from_value(serde_json::json!({
        "key_algorithm":"ecdsa-p256","solver_id":"manual_dns","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":name,
        "created_at":"2026-01-01T00:00:00Z","account_name":"default","account_id":"id","account_thumbprint":"key",
        "directory":"https://ca.example/directory","account_url":"https://ca.example/account","identifiers":["example.com"],
        "phase":"completed","creation_submitted":true,"authorizations":[],"finalize_submitted":"submitted"
    })).unwrap();
    record.is_in_use = true;
    record
}

struct Executor {
    calls: RefCell<Vec<String>>,
}
#[async_trait(?Send)]
impl RenewalExecutor for Executor {
    async fn run(&self, record: &IssueRecord) -> CliResult<CertificateResult> {
        self.calls.borrow_mut().push(record.name.as_str().into());
        match record.name.as_str() {
            "failed" => Err("injected failure".into()),
            "not-due" => Ok(CertificateResult::NotDue(Box::new(record.clone()))),
            "manual" => Ok(CertificateResult::Issuance(IssueOutcome::ActionRequired {
                record: Box::new(record.clone()),
                records: vec![DnsRequirement {
                    name: "_acme-challenge.example.com".into(),
                    value: "value".into(),
                }],
            })),
            "blocked" => {
                std::future::pending::<()>().await;
                Err("unreachable after cancellation".into())
            }
            _ => Ok(CertificateResult::Issuance(IssueOutcome::Completed {
                record: Box::new(record.clone()),
                cleanup: vec![],
            })),
        }
    }
}

#[tokio::test]
async fn batch_continues_after_failure_and_manual_action_without_treating_either_as_success() {
    let executor = Executor {
        calls: RefCell::new(vec![]),
    };
    let mut missing = record("missing");
    missing.is_in_use = false;
    let report = run_batch(
        vec![
            record("failed"),
            record("manual"),
            record("not-due"),
            missing,
            record("completed"),
        ],
        &executor,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(
        *executor.calls.borrow(),
        ["failed", "manual", "not-due", "completed"]
    );
    assert_eq!(
        report.summary(),
        super::super::report::RenewalSummary {
            completed: 1,
            action_required: 1,
            not_due: 1,
            skipped: 1,
            failed: 1,
            cancelled: 0
        }
    );
    let json: serde_json::Value =
        serde_json::from_str(&render::batch(&report, true, std::path::Path::new("/data")).unwrap())
            .unwrap();
    assert_eq!(json["status"], "partial_failure");
    assert_eq!(json["results"][0]["result"]["status"], "failed");
    assert_eq!(json["results"][1]["result"]["status"], "action_required");
    assert_eq!(json["results"][2]["result"]["status"], "not_due");
    assert_eq!(
        json["results"][3]["result"]["reason"],
        "no_in_use_certificate"
    );
    assert_eq!(json["results"][4]["result"]["status"], "completed");
    assert!(json["results"][1]["result"].get("artifacts").is_none());
    assert!(json["results"][4]["result"].get("resume").is_none());
    let text = render::batch(&report, false, std::path::Path::new("/data")).unwrap();
    assert!(text.contains("action required"));
    assert!(text.starts_with("[ERROR] Batch renewal results:"));
    assert!(text.contains("\n\n[ERROR] Completed:"));
    assert!(text.contains("injected failure"));
    assert!(!text.contains("cancelled: 0"));
}

#[tokio::test]
async fn cancellation_stops_in_flight_work_and_marks_remaining_items_unattempted() {
    let executor = Executor {
        calls: RefCell::new(vec![]),
    };
    let token = CancellationToken::new();
    let cancel = token.clone();
    let report = tokio::join!(
        run_batch(
            vec![record("completed"), record("blocked"), record("later")],
            &executor,
            &token
        ),
        async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel.cancel();
        }
    )
    .0;
    assert_eq!(*executor.calls.borrow(), ["completed", "blocked"]);
    assert_eq!(report.summary().cancelled, 1);
    assert!(matches!(
        report.entries[2].result,
        RenewalResult::Skipped(SkipReason::BatchCancelled)
    ));
    let json: serde_json::Value =
        serde_json::from_str(&render::batch(&report, true, std::path::Path::new("/data")).unwrap())
            .unwrap();
    assert_eq!(json["status"], "cancelled");
}

#[tokio::test]
async fn empty_inventory_and_pre_cancelled_batches_do_not_execute() {
    let executor = Executor {
        calls: RefCell::new(vec![]),
    };
    let token = CancellationToken::new();
    let empty = run_batch(vec![], &executor, &token).await;
    assert_eq!(
        empty.summary(),
        super::super::report::RenewalSummary::default()
    );
    token.cancel();
    let report = run_batch(vec![record("later")], &executor, &token).await;
    assert!(executor.calls.borrow().is_empty());
    assert_eq!(report.summary().skipped, 1);
}

struct LocalFixture {
    _temp: tempfile::TempDir,
    settings: CliSettings,
    store: CliIssueStore,
    account: aster_acme::account::AccountRecord,
    run: RunArgs,
}

impl LocalFixture {
    async fn create() -> Self {
        use aster_acme::account::{AccountKeyStore, AccountStore};
        let temp = tempfile::tempdir().unwrap();
        let directory =
            aster_acme_protocol::url::AcmeUrl::new("https://127.0.0.1:1/directory").unwrap();
        let accounts = aster_acme_cli_storage::CliAccountStore::open(
            temp.path(),
            "default",
            Duration::from_secs(1),
        )
        .unwrap();
        let signer = accounts.signer(&directory, "default", true).await.unwrap();
        let thumb = signer.jwk().unwrap().thumbprint().unwrap();
        let mut account = accounts.load(&directory, &thumb).await.unwrap().unwrap();
        account.state = aster_acme_core::account::AccountRecordState::Registered;
        account.last_status = Some(aster_acme_core::protocol::AccountStatus::Valid);
        account.account_url =
            Some(aster_acme_protocol::url::AcmeUrl::new("https://127.0.0.1:1/account").unwrap());
        accounts.save(&account).await.unwrap();
        let run = RunArgs {
            yes: false,
            skip_dns_check: false,
            wait_timeout: 1,
            http: crate::common::args::HttpArgs {
                timeout: Some(1),
                ..crate::common::args::HttpArgs::default()
            },
            local: crate::common::args::LocalArgs {
                data_dir: Some(temp.path().into()),
                json: true,
            },
        };
        let options = super::super::execute::options(&run.local, &run.http, None);
        let settings = CliSettings::load(&options).await.unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_millis(100));
        Self {
            _temp: temp,
            settings,
            store,
            account,
            run,
        }
    }

    async fn seed(&self, name: &str, complete: bool) -> IssueRecord {
        use aster_acme::issuance::{
            CertificateName, IssueRequest, key_algorithm::CertificateKeyAlgorithm,
        };
        use rcgen::{CertificateParams, Issuer, KeyPair};
        let request = IssueRequest {
            name: CertificateName::new(name).unwrap(),
            identifiers: vec![aster_acme::identifier::DnsIdentifier::new("example.com").unwrap()],
            key_algorithm: CertificateKeyAlgorithm::EcdsaP256,
            account_name: "default".into(),
        };
        let session = self.store.create(&request, &self.account).await.unwrap();
        let mut record = session.record().await.unwrap();
        if complete {
            let folder = self
                .settings
                .data_dir
                .join("certs")
                .join(name)
                .join(record.generation_name());
            let bytes =
                zeroize::Zeroizing::new(std::fs::read(folder.join("private-key.pk8")).unwrap());
            let key = KeyPair::try_from(bytes.as_slice()).unwrap();
            let issuer = Issuer::new(
                CertificateParams::new(Vec::<String>::new()).unwrap(),
                KeyPair::generate().unwrap(),
            );
            let mut params = CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
            params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(89);
            let leaf = params.signed_by(&key, &issuer).unwrap().pem();
            record.phase = aster_acme_core::workflow::IssuancePhase::Completed;
            record = session.complete(&record, leaf.as_bytes()).await.unwrap();
        }
        record
    }
}

#[tokio::test]
async fn real_transactions_keep_not_due_material_unchanged_skip_unissued_and_continue_after_missing_account()
 {
    use aster_acme::account::AccountKeyStore;
    let fixture = LocalFixture::create().await;
    let broken = fixture.seed("a-missing-account", true).await;
    let good = fixture.seed("b-not-due", true).await;
    fixture.seed("c-not-issued", false).await;
    let session = fixture
        .store
        .open(&broken.name, &broken.operation_id)
        .await
        .unwrap();
    // Change only the snapshot passed to the executor: failure must not mutate any generation.
    drop(session);
    let mut records = selection::managed_records(fixture.store.list().await.unwrap()).unwrap();
    records[0].account_name = "missing".into();
    let work = super::super::report::RenewalWork::from_records(
        &records,
        false,
        time::OffsetDateTime::now_utc(),
    );
    assert_eq!(work.scheduled, 0);
    assert_eq!(work.not_due, 2);
    let early = super::super::report::RenewalWork::from_records(
        &records,
        true,
        time::OffsetDateTime::now_utc(),
    );
    assert_eq!(early.scheduled, 2);
    assert_eq!(early.not_due, 0);
    let before = records
        .iter()
        .map(|record| {
            let folder = fixture
                .settings
                .data_dir
                .join("certs")
                .join(record.name.as_str())
                .join(record.generation_name());
            (
                folder.clone(),
                std::fs::read(folder.join("operation.toml")).unwrap(),
                std::fs::read(folder.join("private-key.pk8")).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let token = CancellationToken::new();
    let executor = Transaction {
        settings: &fixture.settings,
        store: &fixture.store,
        run: &fixture.run,
        immediate: false,
        cancellation: Some(&token),
    };
    let report = run_batch(records, &executor, &token).await;
    assert_eq!(report.summary().failed, 1);
    assert_eq!(report.summary().not_due, 1);
    assert_eq!(report.summary().skipped, 1);
    assert!(matches!(
        report.entries[1].result,
        RenewalResult::Outcome(CertificateResult::NotDue(_))
    ));
    for (folder, journal, key) in before {
        assert_eq!(
            std::fs::read(folder.join("operation.toml")).unwrap(),
            journal
        );
        assert_eq!(std::fs::read(folder.join("private-key.pk8")).unwrap(), key);
    }
    assert_eq!(fixture.store.list().await.unwrap().len(), 3);
    assert!(good.is_in_use);
    let accounts = aster_acme_cli_storage::CliAccountStore::open(
        &fixture.settings.data_dir,
        "default",
        Duration::from_secs(1),
    )
    .unwrap();
    assert!(
        accounts
            .signer(&fixture.account.directory_url, "default", false)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn now_failure_is_reported_per_item_and_preserves_the_previous_in_use_certificate() {
    let fixture = LocalFixture::create().await;
    let old = fixture.seed("web", true).await;
    let token = CancellationToken::new();
    let executor = Transaction {
        settings: &fixture.settings,
        store: &fixture.store,
        run: &fixture.run,
        immediate: true,
        cancellation: Some(&token),
    };
    let report = run_batch(fixture.store.list().await.unwrap(), &executor, &token).await;
    assert_eq!(report.summary().failed, 1);
    let records = fixture.store.list().await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records.iter().filter(|record| record.is_in_use).count(), 1);
    assert!(
        records
            .iter()
            .any(|record| record.is_in_use && record.operation_id == old.operation_id)
    );
    assert!(records.iter().any(|record| {
        record.unfinished()
            && record
                .renewal_of
                .as_ref()
                .is_some_and(|previous| previous.operation_id == old.operation_id)
    }));
}

#[tokio::test]
async fn manual_only_batch_reports_action_required_and_pre_cancelled_batch_reports_cancelled() {
    let executor = Executor {
        calls: RefCell::new(vec![]),
    };
    let token = CancellationToken::new();
    let report = run_batch(vec![record("manual")], &executor, &token).await;
    let json: serde_json::Value =
        serde_json::from_str(&render::batch(&report, true, std::path::Path::new("/data")).unwrap())
            .unwrap();
    assert_eq!(json["status"], "action_required");
    assert_eq!(json["summary"]["completed"], 0);
    token.cancel();
    let report = run_batch(vec![record("later")], &executor, &token).await;
    let json: serde_json::Value =
        serde_json::from_str(&render::batch(&report, true, std::path::Path::new("/data")).unwrap())
            .unwrap();
    assert_eq!(json["status"], "cancelled");
    assert_eq!(json["results"][0]["result"]["reason"], "batch_cancelled");
}

struct CommitThenCancel(CancellationToken);
#[async_trait(?Send)]
impl RenewalExecutor for CommitThenCancel {
    async fn run(&self, record: &IssueRecord) -> CliResult<CertificateResult> {
        self.0.cancel();
        Ok(CertificateResult::Issuance(IssueOutcome::Completed {
            record: Box::new(record.clone()),
            cleanup: vec![],
        }))
    }
}

#[tokio::test]
async fn completed_result_is_not_discarded_when_cancellation_arrives_after_commit() {
    let token = CancellationToken::new();
    let report = run_batch(
        vec![record("committed"), record("later")],
        &CommitThenCancel(token.clone()),
        &token,
    )
    .await;
    assert_eq!(report.summary().completed, 1);
    assert_eq!(report.summary().cancelled, 0);
    assert_eq!(report.summary().skipped, 1);
    assert!(report.was_cancelled());
    let json: serde_json::Value =
        serde_json::from_str(&render::batch(&report, true, std::path::Path::new("/data")).unwrap())
            .unwrap();
    assert_eq!(json["status"], "cancelled");
    assert_eq!(json["results"][0]["result"]["status"], "completed");
}

#[tokio::test]
async fn certificate_lock_timeout_is_one_failure_and_does_not_stop_the_next_due_check() {
    let fixture = LocalFixture::create().await;
    let locked = fixture.seed("a-locked", true).await;
    fixture.seed("b-not-due", true).await;
    let lease = fixture
        .store
        .open(&locked.name, &locked.operation_id)
        .await
        .unwrap();
    let records = selection::managed_records(fixture.store.list().await.unwrap()).unwrap();
    let token = CancellationToken::new();
    let executor = Transaction {
        settings: &fixture.settings,
        store: &fixture.store,
        run: &fixture.run,
        immediate: false,
        cancellation: Some(&token),
    };
    let report = run_batch(records, &executor, &token).await;
    assert_eq!(report.summary().failed, 1);
    assert_eq!(report.summary().not_due, 1);
    assert_eq!(
        report.disposition(),
        super::super::report::BatchDisposition::PartialFailure
    );
    assert_eq!(fixture.store.list().await.unwrap().len(), 2);
    assert_eq!(
        lease.record().await.unwrap().operation_id,
        locked.operation_id
    );
}

#[tokio::test]
async fn all_not_due_report_has_one_table_and_one_sentence_without_zero_counters() {
    let executor = Executor {
        calls: RefCell::new(vec![]),
    };
    let mut second = record("not-due");
    second.operation_id = "b".repeat(43);
    let report = run_batch(
        vec![record("not-due"), second],
        &executor,
        &CancellationToken::new(),
    )
    .await;
    let human = render::batch(&report, false, std::path::Path::new("/data")).unwrap();
    assert!(human.contains("2 certificates checked; none due for renewal."));
    assert_eq!(human.matches("Batch renewal results:").count(), 1);
    assert!(!human.contains("Completed: 0"));
    assert!(!human.contains("failed: 0"));
    let machine: serde_json::Value =
        serde_json::from_str(&render::batch(&report, true, std::path::Path::new("/data")).unwrap())
            .unwrap();
    assert_eq!(machine["summary"]["not_due"], 2);
    assert_eq!(machine["summary"]["failed"], 0);
    assert_eq!(machine["results"].as_array().unwrap().len(), 2);
}
