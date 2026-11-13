//! Real journals + unsigned loopback ARI; no foreground issuance or account access.
use crate::issuance::tests::{Fixture, fixture, leaf_for, request};
use crate::issuance::{CliIssueStore, RenewalPreparation};
use aster_acme::storage::account::AccountStore;
use aster_acme::{
    issuance::{CertificateName, IssueError, IssueRecord},
    maintenance::{self, Options, Outcome, Report},
    storage::{issuance::IssueStore, query::IssueQuery},
    transport::{HttpPool, TransportOptions},
};
use aster_acme_core::{revocation::RevocationState, workflow::IssuancePhase};
use std::{fs, time::Duration};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

fn options() -> Options {
    Options {
        transport: TransportOptions {
            allow_loopback_http: true,
            ..TransportOptions::default()
        },
        certificate_timeout: Duration::from_secs(10),
    }
}
async fn cycle(f: &Fixture) -> Report {
    maintenance::run_once(
        &f.store,
        &HttpPool::default(),
        &options(),
        &CancellationToken::new(),
        None,
    )
    .await
    .unwrap()
}
async fn completed(f: &Fixture, name: &str) -> IssueRecord {
    let mut req = request();
    req.name = CertificateName::new(name).unwrap();
    let session = f.store.create(&req, &f.account).await.unwrap();
    let mut record = session.record().await.unwrap();
    let generation = f.store.slot(&record.name).join(record.generation_name());
    let chain = leaf_for(&generation, &record.identifiers);
    record.phase = IssuancePhase::Completed;
    session.complete(&record, chain.as_bytes()).await.unwrap()
}
async fn save(f: &Fixture, record: &IssueRecord) {
    f.store
        .open_observation(&record.name, &record.operation_id)
        .await
        .unwrap()
        .save(record)
        .await
        .unwrap();
}
async fn read(f: &Fixture, record: &IssueRecord) -> IssueRecord {
    f.store
        .open_observation(&record.name, &record.operation_id)
        .await
        .unwrap()
        .record()
        .await
        .unwrap()
}
async fn directory(f: &Fixture, ari: bool) {
    Mock::given(method("GET")).and(path("/directory")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "newNonce":format!("{}/nonce",f.server.uri()),"newAccount":format!("{}/unused",f.server.uri()),
        "renewalInfo":ari.then(||format!("{}/ari",f.server.uri()))
    }))).with_priority(2).mount(&f.server).await;
}
fn response() -> ResponseTemplate {
    let now = OffsetDateTime::now_utc();
    ResponseTemplate::new(200).insert_header("Retry-After", "120").set_body_json(serde_json::json!({"suggestedWindow": {
        "start": (now + time::Duration::days(1)).format(&time::format_description::well_known::Rfc3339).unwrap(),
        "end": (now + time::Duration::days(2)).format(&time::format_description::well_known::Rfc3339).unwrap()
    }}))
}
async fn ari(f: &Fixture, record: &IssueRecord, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/ari/{}",
            record
                .renewal
                .as_ref()
                .unwrap()
                .certificate_id
                .as_ref()
                .unwrap()
        )))
        .respond_with(response)
        .mount(&f.server)
        .await;
}
async fn count(f: &Fixture, prefix: &str) -> usize {
    f.server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().starts_with(prefix))
        .count()
}

#[tokio::test]
async fn ari_due_query_has_exact_boundaries_and_excludes_noneligible_states() {
    let f = fixture().await;
    let base = completed(&f, "eligible").await;
    let now = OffsetDateTime::now_utc();
    assert!(aster_acme::renewal::refresh_due(&base, now));
    let mut at = base.clone();
    at.renewal.as_mut().unwrap().next_check_at = Some(now);
    assert!(aster_acme::renewal::refresh_due(&at, now));
    at.renewal.as_mut().unwrap().next_check_at = Some(now + time::Duration::nanoseconds(1));
    assert!(!aster_acme::renewal::refresh_due(&at, now));
    let mut variants = vec![];
    let mut r = base.clone();
    r.is_in_use = false;
    variants.push(r);
    let mut r = base.clone();
    r.phase = IssuancePhase::Authorizing;
    variants.push(r);
    let mut r = base.clone();
    r.renewal = None;
    variants.push(r);
    let mut r = base.clone();
    r.renewal.as_mut().unwrap().certificate_id = None;
    variants.push(r);
    let mut r = base.clone();
    r.renewal.as_mut().unwrap().not_after = now;
    variants.push(r);
    for state in [RevocationState::Pending, RevocationState::Confirmed] {
        let mut r = base.clone();
        r.revocation.state = state;
        variants.push(r);
    }
    for r in variants {
        assert!(
            !IssueQuery {
                ari_due_at: Some(now),
                ..IssueQuery::default()
            }
            .matches(&r)
        );
    }
    save(&f, &at).await;
    assert!(
        f.store
            .query(IssueQuery {
                ari_due_at: Some(now),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        f.store
            .query(IssueQuery {
                ari_due_at: Some(now + time::Duration::nanoseconds(1)),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn refresh_is_unsigned_reuses_directory_and_retains_keys_artifacts_and_generations() {
    let f = fixture().await;
    let a = completed(&f, "a").await;
    let b = completed(&f, "b").await;
    directory(&f, true).await;
    let reply = response();
    ari(&f, &a, reply.clone()).await;
    ari(&f, &b, reply).await;
    let gen_path = f.store.slot(&a.name).join(a.generation_name());
    let key = fs::read(gen_path.join("private-key.pk8")).unwrap();
    let chain = fs::read(gen_path.join("fullchain.pem")).unwrap();
    let before = count(&f, "/directory").await;
    // No account is needed for discovery or RFC 9773 GETs.
    fs::rename(
        f.temp.path().join("accounts"),
        f.temp.path().join("offline-accounts"),
    )
    .unwrap();
    let report = cycle(&f).await;
    assert_eq!(report.entries.len(), 2);
    assert!(
        report
            .entries
            .iter()
            .all(|e| matches!(e.outcome, Outcome::Refreshed))
    );
    assert_eq!(count(&f, "/directory").await - before, 1);
    assert_eq!(count(&f, "/ari/").await, 2);
    for r in f
        .server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().starts_with("/ari/"))
    {
        assert_eq!(r.method, "GET");
        assert_eq!(r.body, [] as [u8; 0]);
        assert!(!r.headers.contains_key("authorization"));
    }
    let selected = read(&f, &a).await;
    assert!(selected.is_in_use);
    assert_eq!(selected.operation_id, a.operation_id);
    let plan = selected.renewal.unwrap();
    assert!(plan.suggested_window.as_ref().unwrap().start <= plan.renew_at);
    assert!(plan.renew_at < plan.suggested_window.as_ref().unwrap().end);
    assert!(plan.next_check_at.unwrap() > OffsetDateTime::now_utc());
    assert_eq!(report.entries[0].next_check_at, plan.next_check_at);
    assert_eq!(fs::read(gen_path.join("private-key.pk8")).unwrap(), key);
    assert_eq!(fs::read(gen_path.join("fullchain.pem")).unwrap(), chain);
    assert_eq!(f.store.query(IssueQuery::default()).await.unwrap().len(), 2);
    let requests = f.server.received_requests().await.unwrap().len();
    assert!(cycle(&f).await.entries.is_empty());
    assert_eq!(f.server.received_requests().await.unwrap().len(), requests);
    // Reaching the next query with an identical window must not draw a new time.
    let mut selected = read(&f, &a).await;
    selected.renewal.as_mut().unwrap().next_check_at = None;
    save(&f, &selected).await;
    assert!(matches!(
        cycle(&f).await.entries[0].outcome,
        Outcome::Refreshed
    ));
    assert_eq!(read(&f, &a).await.renewal.unwrap().renew_at, plan.renew_at);
}

#[tokio::test]
async fn metadata_observation_does_not_load_certificate_private_key_or_csr() {
    let f = fixture().await;
    let r = completed(&f, "test").await;
    directory(&f, true).await;
    ari(&f, &r, response()).await;
    let generation = f.store.slot(&r.name).join(r.generation_name());
    fs::rename(
        generation.join("private-key.pk8"),
        generation.join("offline-key"),
    )
    .unwrap();
    fs::rename(
        generation.join("request.der"),
        generation.join("offline-csr"),
    )
    .unwrap();
    assert!(f.store.open(&r.name, &r.operation_id).await.is_err());
    assert!(matches!(
        cycle(&f).await.entries[0].outcome,
        Outcome::Refreshed
    ));
}

#[tokio::test]
async fn unavailable_ca_defers_discovery_and_keeps_fallback() {
    let f = fixture().await;
    let r = completed(&f, "test").await;
    let before = r.renewal.as_ref().unwrap();
    let report = cycle(&f).await;
    assert!(matches!(report.entries[0].outcome, Outcome::Unavailable));
    let saved = read(&f, &r).await.renewal.unwrap();
    assert_eq!(saved.renew_at, before.renew_at);
    assert_eq!(saved.last_checked_at, before.last_checked_at);
    assert!(saved.next_check_at.unwrap() > OffsetDateTime::now_utc() + time::Duration::hours(5));
    assert!(cycle(&f).await.entries.is_empty());
    assert_eq!(count(&f, "/ari/").await, 0);
}

#[tokio::test]
async fn failed_or_malformed_ari_preserves_plan_and_schedules_retry() {
    for response in [
        ResponseTemplate::new(400),
        ResponseTemplate::new(200).set_body_string("{}"),
        ResponseTemplate::new(200).set_body_string("not json"),
    ] {
        let f = fixture().await;
        let r = completed(&f, "test").await;
        directory(&f, true).await;
        ari(&f, &r, response).await;
        let report = cycle(&f).await;
        assert!(matches!(report.entries[0].outcome, Outcome::RetryScheduled));
        let saved = read(&f, &r).await.renewal.unwrap();
        assert_eq!(saved.renew_at, r.renewal.unwrap().renew_at);
        assert!(saved.last_query_failed);
        assert_eq!(report.entries[0].next_check_at, saved.next_check_at);
        assert!(cycle(&f).await.entries.is_empty());
    }
}

#[tokio::test]
async fn missing_retry_after_keeps_valid_window_with_conservative_recheck() {
    let f = fixture().await;
    let r = completed(&f, "test").await;
    directory(&f, true).await;
    let now = OffsetDateTime::now_utc();
    ari(&f, &r, ResponseTemplate::new(200).set_body_json(serde_json::json!({"suggestedWindow": {
        "start": now.format(&time::format_description::well_known::Rfc3339).unwrap(),
        "end": (now+time::Duration::days(1)).format(&time::format_description::well_known::Rfc3339).unwrap()
    }}))).await;
    assert!(matches!(
        cycle(&f).await.entries[0].outcome,
        Outcome::RetryScheduled
    ));
    assert!(
        read(&f, &r)
            .await
            .renewal
            .unwrap()
            .suggested_window
            .is_some()
    );
}

#[tokio::test]
async fn discovery_failure_is_durable_and_does_not_abort_other_certificates() {
    let f = fixture().await;
    let a = completed(&f, "a").await;
    let b = completed(&f, "b").await;
    directory(&f, true).await;
    // First request gets a definite discovery error, second succeeds.
    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(ResponseTemplate::new(400))
        .with_priority(1)
        .up_to_n_times(1)
        .mount(&f.server)
        .await;
    ari(&f, &b, response()).await;
    let report = cycle(&f).await;
    assert!(matches!(report.entries[0].outcome, Outcome::Failed(_)));
    assert!(matches!(report.entries[1].outcome, Outcome::Refreshed));
    assert_eq!(
        read(&f, &a).await.renewal.unwrap().renew_at,
        a.renewal.unwrap().renew_at
    );
    assert!(report.entries[0].next_check_at.is_some());
    assert!(cycle(&f).await.entries.is_empty());
}

#[tokio::test]
async fn per_certificate_deadline_retains_saved_retry_and_continues() {
    let f = fixture().await;
    let a = completed(&f, "a").await;
    let b = completed(&f, "b").await;
    directory(&f, true).await;
    ari(&f, &a, response().set_delay(Duration::from_secs(5))).await;
    ari(&f, &b, response()).await;
    let report = maintenance::run_once(
        &f.store,
        &HttpPool::default(),
        &Options {
            certificate_timeout: Duration::from_millis(500),
            ..options()
        },
        &CancellationToken::new(),
        None,
    )
    .await
    .unwrap();
    assert!(!report.cancelled);
    assert!(matches!(
        report.entries[0].outcome,
        Outcome::Failed(IssueError::Interrupted)
    ));
    assert!(report.entries[0].next_check_at.is_some());
    assert!(matches!(report.entries[1].outcome, Outcome::Refreshed));
}

#[tokio::test]
async fn pre_cancelled_cycle_never_contacts_ca() {
    let f = fixture().await;
    completed(&f, "a").await;
    let token = CancellationToken::new();
    token.cancel();
    let before = f.server.received_requests().await.unwrap().len();
    let report = maintenance::run_once(&f.store, &HttpPool::default(), &options(), &token, None)
        .await
        .unwrap();
    assert!(report.cancelled);
    assert!(matches!(report.entries[0].outcome, Outcome::NotStarted));
    assert_eq!(f.server.received_requests().await.unwrap().len(), before);
}

async fn wait_for_ari(f: &Fixture) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while count(f, "/ari/").await == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancellation_during_get_retains_retry_intent_and_does_not_start_next_item() {
    let f = fixture().await;
    let a = completed(&f, "a").await;
    completed(&f, "b").await;
    directory(&f, true).await;
    ari(&f, &a, response().set_delay(Duration::from_secs(5))).await;
    let token = CancellationToken::new();
    let cancel = async {
        wait_for_ari(&f).await;
        token.cancel();
    };
    let pool = HttpPool::default();
    let opts = options();
    let (result, ()) = tokio::join!(
        maintenance::run_once(&f.store, &pool, &opts, &token, None),
        cancel
    );
    let report = result.unwrap();
    assert!(report.cancelled);
    assert!(matches!(report.entries[0].outcome, Outcome::Cancelled));
    assert!(matches!(report.entries[1].outcome, Outcome::NotStarted));
    let saved = read(&f, &a).await.renewal.unwrap();
    assert!(saved.last_query_failed);
    assert_eq!(saved.next_check_at, report.entries[0].next_check_at);
    assert_eq!(count(&f, "/ari/").await, 1);
}

#[tokio::test]
async fn overlapping_cycles_recheck_under_lease_and_only_one_refresh_occurs() {
    let f = fixture().await;
    let r = completed(&f, "a").await;
    directory(&f, true).await;
    ari(&f, &r, response().set_delay(Duration::from_millis(100))).await;
    let pool = HttpPool::default();
    let opts = options();
    let token = CancellationToken::new();
    // Both queries see a due snapshot before either obtains its execution lease.
    let held = f
        .store
        .open_observation(&r.name, &r.operation_id)
        .await
        .unwrap();
    let release = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(held);
    };
    let (a, b, ()) = tokio::join!(
        maintenance::run_once(&f.store, &pool, &opts, &token, None),
        maintenance::run_once(&f.store, &pool, &opts, &token, None),
        release
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(count(&f, "/ari/").await, 1);
    assert!(
        a.entries
            .iter()
            .chain(&b.entries)
            .any(|e| matches!(e.outcome, Outcome::Refreshed))
    );
    // With the fixture's short lock budget the other cycle may be contended;
    // after release a fresh invocation is empty, never a duplicate query.
    assert!(cycle(&f).await.entries.is_empty());
}

#[tokio::test]
async fn invalid_cycle_settings_fail_before_storage_or_network_work() {
    let f = fixture().await;
    for timeout in [Duration::ZERO, Duration::MAX] {
        assert!(
            maintenance::run_once(
                &f.store,
                &HttpPool::default(),
                &Options {
                    certificate_timeout: timeout,
                    ..options()
                },
                &CancellationToken::new(),
                None
            )
            .await
            .is_err()
        );
    }
    assert!(cycle(&f).await.entries.is_empty());
}

#[derive(Clone, Copy)]
enum Change {
    Defer,
    Revoke,
    Replace,
}
struct ChangedAfterQuery<'a> {
    f: &'a Fixture,
    change: Change,
}
#[async_trait::async_trait]
impl IssueStore for ChangedAfterQuery<'_> {
    async fn create(
        &self,
        r: &aster_acme::issuance::IssueRequest,
        a: &aster_acme::account::AccountRecord,
    ) -> Result<Box<dyn aster_acme::storage::issuance::IssueSession>, IssueError> {
        self.f.store.create(r, a).await
    }
    async fn renew(
        &self,
        n: &CertificateName,
        a: &aster_acme::account::AccountRecord,
    ) -> Result<Box<dyn aster_acme::storage::issuance::IssueSession>, IssueError> {
        self.f.store.renew(n, a).await
    }
    async fn open(
        &self,
        n: &CertificateName,
        id: &str,
    ) -> Result<Box<dyn aster_acme::storage::issuance::IssueSession>, IssueError> {
        self.f.store.open(n, id).await
    }
    async fn open_observation(
        &self,
        n: &CertificateName,
        id: &str,
    ) -> Result<Box<dyn aster_acme::storage::issuance::IssueSession>, IssueError> {
        self.f.store.open_observation(n, id).await
    }
    async fn query(&self, q: IssueQuery) -> Result<Vec<IssueRecord>, IssueError> {
        let snapshots = self.f.store.query(q).await?;
        match self.change {
            Change::Replace => {
                crate::issuance::tests::completed_generation(self.f).await;
            }
            Change::Defer | Change::Revoke => {
                let mut updated = snapshots[0].clone();
                match self.change {
                    Change::Defer => {
                        updated.renewal.as_mut().unwrap().next_check_at =
                            Some(OffsetDateTime::now_utc() + time::Duration::days(1));
                    }
                    Change::Revoke => updated.revocation.state = RevocationState::Pending,
                    Change::Replace => unreachable!(),
                }
                save(self.f, &updated).await;
            }
        }
        Ok(snapshots)
    }
}

#[tokio::test]
async fn stale_snapshot_is_revalidated_for_due_revocation_and_current_generation() {
    for change in [Change::Defer, Change::Revoke, Change::Replace] {
        let f = fixture().await;
        crate::issuance::tests::completed_generation(&f).await;
        let before = f.server.received_requests().await.unwrap().len();
        let report = maintenance::run_once(
            &ChangedAfterQuery { f: &f, change },
            &HttpPool::default(),
            &options(),
            &CancellationToken::new(),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(report.entries[0].outcome, Outcome::Skipped));
        assert_eq!(f.server.received_requests().await.unwrap().len(), before);
    }
}

#[tokio::test]
async fn lock_contention_is_an_item_failure_and_next_certificate_is_processed() {
    let f = fixture().await;
    let a = completed(&f, "a").await;
    let b = completed(&f, "b").await;
    directory(&f, true).await;
    ari(&f, &b, response()).await;
    let held = f
        .store
        .open_observation(&a.name, &a.operation_id)
        .await
        .unwrap();
    let report = cycle(&f).await;
    assert!(matches!(report.entries[0].outcome, Outcome::Failed(_)));
    assert!(matches!(report.entries[1].outcome, Outcome::Refreshed));
    assert_eq!(count(&f, "/ari/").await, 1);
    drop(held);
}

struct StopAfterFirst(CancellationToken);
impl maintenance::Observer for StopAfterFirst {
    fn observed(&self, _: &maintenance::Entry) {
        self.0.cancel();
    }
}
#[tokio::test]
async fn completed_entries_survive_cancellation_between_certificates() {
    let f = fixture().await;
    let a = completed(&f, "a").await;
    completed(&f, "b").await;
    directory(&f, true).await;
    ari(&f, &a, response()).await;
    let token = CancellationToken::new();
    let report = maintenance::run_once(
        &f.store,
        &HttpPool::default(),
        &options(),
        &token,
        Some(&StopAfterFirst(token.clone())),
    )
    .await
    .unwrap();
    assert!(report.cancelled);
    assert!(matches!(report.entries[0].outcome, Outcome::Refreshed));
    assert!(matches!(report.entries[1].outcome, Outcome::NotStarted));
    assert_eq!(
        read(&f, &a).await.renewal.unwrap().next_check_at,
        report.entries[0].next_check_at
    );
    assert_eq!(count(&f, "/ari/").await, 1);
}

#[tokio::test]
#[ignore = "subprocess renewal concurrency helper"]
async fn cross_process_renewal_child() {
    let Ok(root) = std::env::var("ASTER_ACME_RENEW_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let account: aster_acme::account::AccountRecord =
        serde_json::from_slice(&fs::read(root.join("account.json")).unwrap()).unwrap();
    let accounts =
        crate::account::CliAccountStore::open(&root, "default", Duration::from_secs(5)).unwrap();
    while !root.join("start-renewal").exists() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let account_lease = accounts
        .lock_account(&account.directory_url, &account.key_thumbprint)
        .await
        .unwrap();
    let store = CliIssueStore::new(root.clone(), Duration::from_secs(5));
    let name = CertificateName::new("concurrent").unwrap();
    if std::env::var("ASTER_ACME_RENEW_ROLE").as_deref() == Ok("daemon") {
        let selected = store
            .query(IssueQuery {
                in_use: Some(true),
                renewal_due_at: Some(OffsetDateTime::now_utc()),
                ..IssueQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].operation_id,
            std::env::var("ASTER_ACME_RENEW_IN_USE").unwrap()
        );
    }
    let prep = store
        .prepare_renewal(
            &name,
            &std::env::var("ASTER_ACME_RENEW_IN_USE").unwrap(),
            true,
            &account,
        )
        .await
        .unwrap();
    let RenewalPreparation::Ready(session) = prep else {
        panic!("immediate concurrent renewal unexpectedly not due")
    };
    fs::write(
        root.join(std::env::var("ASTER_ACME_RENEW_RESULT").unwrap()),
        session.record().await.unwrap().operation_id,
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    drop(session);
    drop(account_lease);
}

#[tokio::test]
async fn daemon_candidate_selection_and_foreground_renew_share_one_cross_process_generation() {
    let f = fixture().await;
    let mut current = completed(&f, "concurrent").await;
    current.renewal.as_mut().unwrap().renew_at =
        OffsetDateTime::now_utc() - time::Duration::seconds(1);
    save(&f, &current).await;
    fs::write(
        f.temp.path().join("account.json"),
        serde_json::to_vec(&f.account).unwrap(),
    )
    .unwrap();
    let executable = std::env::current_exe().unwrap();
    let test_name = "issuance::tests::maintenance::cross_process_renewal_child";
    let mut children = Vec::new();
    for role in ["daemon", "foreground-renew"] {
        let result = format!("renewal-result-{role}");
        let child = std::process::Command::new(&executable)
            .args(["--exact", test_name, "--ignored", "--nocapture"])
            .env("ASTER_ACME_RENEW_ROOT", f.temp.path())
            .env("ASTER_ACME_RENEW_IN_USE", &current.operation_id)
            .env("ASTER_ACME_RENEW_RESULT", &result)
            .env("ASTER_ACME_RENEW_ROLE", role)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        children.push((child, result));
    }
    fs::write(f.temp.path().join("start-renewal"), "start").unwrap();
    let mut identifiers = Vec::new();
    for (child, result) in children {
        let output = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "child process failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        identifiers.push(fs::read_to_string(f.temp.path().join(result)).unwrap());
    }
    assert_eq!(identifiers[0], identifiers[1]);
    let all = f.store.query(IssueQuery::default()).await.unwrap();
    assert_eq!(
        all.len(),
        2,
        "only one new operation generation may be created"
    );
    let renewals = all
        .iter()
        .filter(|record| {
            record
                .renewal_of
                .as_ref()
                .is_some_and(|previous| previous.operation_id == current.operation_id)
        })
        .collect::<Vec<_>>();
    assert_eq!(renewals.len(), 1);
    assert_eq!(renewals[0].operation_id, identifiers[0]);
    assert!(renewals[0].unfinished());
    assert!(
        all.iter()
            .any(|record| record.is_in_use && record.operation_id == current.operation_id)
    );
}

#[tokio::test]
#[ignore = "subprocess renewal retry helper"]
async fn cross_process_renewal_retry_child() {
    let Ok(root) = std::env::var("ASTER_ACME_RETRY_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let account: aster_acme::account::AccountRecord =
        serde_json::from_slice(&fs::read(root.join("account.json")).unwrap()).unwrap();
    let store = CliIssueStore::new(root.clone(), Duration::from_secs(5));
    let name = CertificateName::new("retry-race").unwrap();
    let in_use = std::env::var("ASTER_ACME_RETRY_IN_USE").unwrap();
    match std::env::var("ASTER_ACME_RETRY_ROLE").as_deref() {
        Ok("daemon") => {
            let RenewalPreparation::Ready(session) = store
                .prepare_renewal(&name, &in_use, false, &account)
                .await
                .unwrap()
            else {
                panic!("first daemon must acquire the due renewal")
            };
            fs::write(root.join("retry-session-open"), "open").unwrap();
            while !root.join("retry-schedule-now").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            session
                .record_renewal_failure(OffsetDateTime::now_utc(), None, None)
                .await
                .unwrap();
            drop(session);
            fs::write(root.join("retry-daemon-result"), "scheduled").unwrap();
        }
        Ok("foreground") => {
            let candidate = store
                .query(IssueQuery {
                    in_use: Some(true),
                    renewal_due_at: Some(OffsetDateTime::now_utc()),
                    ..IssueQuery::default()
                })
                .await
                .unwrap();
            assert_eq!(candidate.len(), 1);
            fs::write(root.join("retry-foreground-snapshot"), "due").unwrap();
            let result = store
                .prepare_renewal(&name, &in_use, false, &account)
                .await
                .unwrap();
            assert!(matches!(result, RenewalPreparation::NotDue(_)));
            fs::write(root.join("retry-foreground-result"), "not-due").unwrap();
        }
        _ => panic!("unknown retry test role"),
    }
}

#[tokio::test]
async fn failed_renewal_deadline_serializes_cross_process_daemon_and_foreground_workers() {
    let f = fixture().await;
    let mut current = completed(&f, "retry-race").await;
    current.renewal.as_mut().unwrap().renew_at =
        OffsetDateTime::now_utc() - time::Duration::seconds(1);
    save(&f, &current).await;
    fs::write(
        f.temp.path().join("account.json"),
        serde_json::to_vec(&f.account).unwrap(),
    )
    .unwrap();
    let executable = std::env::current_exe().unwrap();
    let test_name = "issuance::tests::maintenance::cross_process_renewal_retry_child";
    let daemon = std::process::Command::new(&executable)
        .args(["--exact", test_name, "--ignored", "--nocapture"])
        .env("ASTER_ACME_RETRY_ROOT", f.temp.path())
        .env("ASTER_ACME_RETRY_IN_USE", &current.operation_id)
        .env("ASTER_ACME_RETRY_ROLE", "daemon")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !f.temp.path().join("retry-session-open").exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("daemon did not acquire renewal lease");
    let foreground = std::process::Command::new(&executable)
        .args(["--exact", test_name, "--ignored", "--nocapture"])
        .env("ASTER_ACME_RETRY_ROOT", f.temp.path())
        .env("ASTER_ACME_RETRY_IN_USE", &current.operation_id)
        .env("ASTER_ACME_RETRY_ROLE", "foreground")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !f.temp.path().join("retry-foreground-snapshot").exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("foreground worker did not read the due snapshot");
    fs::write(f.temp.path().join("retry-schedule-now"), "continue").unwrap();

    for (child, result) in [
        (daemon, "retry-daemon-result"),
        (foreground, "retry-foreground-result"),
    ] {
        let output = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "retry child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = if result == "retry-daemon-result" {
            "scheduled"
        } else {
            "not-due"
        };
        assert_eq!(
            fs::read_to_string(f.temp.path().join(result)).unwrap(),
            expected
        );
    }
    let generations = f.store.query(IssueQuery::default()).await.unwrap();
    assert_eq!(
        generations.len(),
        2,
        "one failed attempt must not fork a second generation"
    );
    let saved = read(&f, &current).await;
    assert_eq!(saved.renewal_retry.as_ref().unwrap().failures, 1);
}

#[tokio::test]
async fn renewal_failure_backoff_persists_on_predecessor_and_admin_now_only_bypasses_deadline() {
    let f = fixture().await;
    let mut current = completed(&f, "retry-state").await;
    let now = OffsetDateTime::now_utc();
    current.renewal.as_mut().unwrap().renew_at = now - time::Duration::seconds(1);
    save(&f, &current).await;

    let RenewalPreparation::Ready(attempt) = f
        .store
        .prepare_renewal(&current.name, &current.operation_id, true, &f.account)
        .await
        .unwrap()
    else {
        panic!("initial due renewal expected")
    };
    let attempt_id = attempt.record().await.unwrap().operation_id;
    let first = attempt
        .record_renewal_failure(now, None, None)
        .await
        .unwrap();
    assert_eq!(first.failures, 1);
    let retry_at = now + time::Duration::minutes(1);
    assert_eq!(first.retry_at, Some(retry_at));
    drop(attempt);

    let saved = read(&f, &current).await;
    assert_eq!(saved.renewal_retry, Some(first.clone()));
    let before_deadline = f
        .store
        .query(IssueQuery {
            in_use: Some(true),
            renewal_due_at: Some(retry_at - time::Duration::nanoseconds(1)),
            ..IssueQuery::default()
        })
        .await
        .unwrap();
    assert!(before_deadline.is_empty());
    let at_deadline = f
        .store
        .query(IssueQuery {
            in_use: Some(true),
            renewal_due_at: Some(retry_at),
            ..IssueQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(at_deadline.len(), 1);

    let normal = f
        .store
        .prepare_renewal(&current.name, &current.operation_id, false, &f.account)
        .await
        .unwrap();
    assert!(matches!(normal, RenewalPreparation::NotDue(_)));
    let RenewalPreparation::Ready(manual) = f
        .store
        .prepare_renewal(&current.name, &current.operation_id, true, &f.account)
        .await
        .unwrap()
    else {
        panic!("--now should bypass local retry timing")
    };
    assert_eq!(manual.record().await.unwrap().operation_id, attempt_id);
    let second = manual
        .record_renewal_failure(now + time::Duration::minutes(11), None, None)
        .await
        .unwrap();
    assert_eq!(second.failures, 2);
    assert_eq!(second.retry_at, Some(now + time::Duration::minutes(21)));
}

#[tokio::test]
async fn ca_retry_after_is_not_bypassed_by_manual_now() {
    let f = fixture().await;
    let mut current = completed(&f, "ca-retry-after").await;
    current.renewal.as_mut().unwrap().renew_at =
        OffsetDateTime::now_utc() - time::Duration::seconds(1);
    save(&f, &current).await;
    let RenewalPreparation::Ready(attempt) = f
        .store
        .prepare_renewal(&current.name, &current.operation_id, true, &f.account)
        .await
        .unwrap()
    else {
        panic!("renewal expected")
    };
    let now = OffsetDateTime::now_utc();
    let ca_retry_at =
        OffsetDateTime::from_unix_timestamp((now + time::Duration::minutes(10)).unix_timestamp())
            .unwrap();
    let state = attempt
        .record_renewal_failure(now, Some(ca_retry_at), None)
        .await
        .unwrap();
    assert!(state.retry_at.is_some_and(|at| at < ca_retry_at));
    assert_eq!(state.ca_retry_at, Some(ca_retry_at));
    drop(attempt);

    for immediate in [false, true] {
        assert!(
            f.store
                .prepare_renewal(&current.name, &current.operation_id, immediate, &f.account)
                .await
                .is_err()
        );
    }
    let mut elapsed = read(&f, &current).await;
    elapsed.renewal_retry.as_mut().unwrap().retry_at = Some(now - time::Duration::seconds(1));
    elapsed.renewal_retry.as_mut().unwrap().ca_retry_at = Some(now - time::Duration::seconds(1));
    save(&f, &elapsed).await;
    assert!(matches!(
        f.store
            .prepare_renewal(&current.name, &current.operation_id, false, &f.account)
            .await
            .unwrap(),
        RenewalPreparation::Ready(_)
    ));
}

#[tokio::test]
async fn uncertain_new_order_outcome_blocks_automatic_and_manual_new_attempts() {
    let f = fixture().await;
    let mut current = completed(&f, "retry-blocked").await;
    current.renewal.as_mut().unwrap().renew_at = OffsetDateTime::now_utc();
    save(&f, &current).await;
    let RenewalPreparation::Ready(attempt) = f
        .store
        .prepare_renewal(&current.name, &current.operation_id, true, &f.account)
        .await
        .unwrap()
    else {
        panic!("renewal expected")
    };
    let state = attempt
        .record_renewal_failure(
            OffsetDateTime::now_utc(),
            None,
            Some("newOrder outcome is uncertain".into()),
        )
        .await
        .unwrap();
    assert!(state.retry_at.is_none());
    assert!(state.blocked_reason.is_some());
    drop(attempt);

    for immediate in [false, true] {
        assert!(
            f.store
                .prepare_renewal(&current.name, &current.operation_id, immediate, &f.account)
                .await
                .is_err()
        );
    }
    let observed = read(&f, &current).await;
    assert_eq!(observed.renewal_retry, Some(state));
}

#[tokio::test]
async fn renewal_due_inventory_query_prunes_history_revocation_and_time_boundaries() {
    let f = fixture().await;
    let first = completed(&f, "first").await;
    let second = completed(&f, "second").await;
    let eligible = completed(&f, "eligible").await;
    let now = OffsetDateTime::now_utc();
    for original in [&first, &second, &eligible] {
        let mut due = read(&f, original).await;
        due.renewal.as_mut().unwrap().renew_at = now;
        save(&f, &due).await;
    }
    let mut revoked = read(&f, &second).await;
    revoked.revocation.state = RevocationState::Pending;
    save(&f, &revoked).await;
    let due = f
        .store
        .query(IssueQuery {
            renewal_due_at: Some(now),
            ..IssueQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(due.len(), 2);
    assert!(
        due.iter()
            .any(|record| record.operation_id == first.operation_id)
    );
    assert!(
        due.iter()
            .any(|record| record.operation_id == eligible.operation_id)
    );
    assert!(
        f.store
            .query(IssueQuery {
                renewal_due_at: Some(now - time::Duration::nanoseconds(1)),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .is_empty()
    );
    let session = f.store.renew(&first.name, &f.account).await.unwrap();
    let mut current = session.record().await.unwrap();
    let generation = f.store.slot(&current.name).join(current.generation_name());
    let chain = leaf_for(&generation, &current.identifiers);
    current.phase = IssuancePhase::Completed;
    let latest = session.complete(&current, chain.as_bytes()).await.unwrap();
    assert!(latest.is_in_use);
    drop(session);
    let historical = read(&f, &first).await;
    assert!(!historical.is_in_use);
    assert!(
        !IssueQuery {
            renewal_due_at: Some(now),
            ..IssueQuery::default()
        }
        .matches(&historical)
    );
    let due = f
        .store
        .query(IssueQuery {
            renewal_due_at: Some(now),
            ..IssueQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].operation_id, eligible.operation_id);
}
