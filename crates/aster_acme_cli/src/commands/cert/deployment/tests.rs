//! Deployment regression and resource lifecycle tests.
mod hardening;
mod retry;
use crate::commands::cert::deployment::*;
use aster_acme::storage::query::{IssueQuery, IssueView};

struct Fixture {
    temp: tempfile::TempDir,
    store: CliIssueStore,
    account: aster_acme::account::AccountRecord,
    name: CertificateName,
    progress: Progress,
}

async fn managed_candidates(store: &CliIssueStore) -> Vec<aster_acme::issuance::IssueRecord> {
    store
        .query(IssueQuery {
            view: IssueView::Managed,
            in_use: Some(true),
            ..IssueQuery::default()
        })
        .await
        .unwrap()
}

impl Fixture {
    async fn generation(&self) -> String {
        self.store
            .query(IssueQuery {
                name: Some(self.name.clone()),
                in_use: Some(true),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .remove(0)
            .generation_name()
    }
    async fn new() -> Self {
        use aster_acme::storage::account::{AccountKeyStore, AccountStore, KeyAccess};

        let temp = tempfile::tempdir().unwrap();
        let directory =
            aster_acme_protocol::url::AcmeUrl::new("https://ca.example/directory").unwrap();
        let accounts = aster_acme_cli_storage::account::CliAccountStore::open(
            temp.path(),
            "default",
            Duration::from_secs(1),
        )
        .unwrap();
        let signer = accounts
            .signer(&directory, "default", KeyAccess::Create(None))
            .await
            .unwrap();
        let thumb = signer.jwk().unwrap().thumbprint().unwrap();
        let mut account = accounts.load(&directory, &thumb).await.unwrap().unwrap();
        account.state = aster_acme_core::account::AccountRecordState::Registered;
        account.last_status = Some(aster_acme_core::protocol::AccountStatus::Valid);
        account.account_url =
            Some(aster_acme_protocol::url::AcmeUrl::new("https://ca.example/account/1").unwrap());
        accounts.save(&account).await.unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_millis(100));
        let fixture = Self {
            temp,
            store,
            account,
            name: CertificateName::new("web").unwrap(),
            progress: Progress::new(crate::common::session::OutputSession::new(true)),
        };
        fixture.complete(false).await;
        fixture
    }

    async fn complete(&self, renewal: bool) -> aster_acme::issuance::IssueRecord {
        use aster_acme::{
            crypto::key_algorithm::KeyAlgorithm, identifier::DnsIdentifier, issuance::IssueRequest,
        };
        let session = if renewal {
            self.store.renew(&self.name, &self.account).await.unwrap()
        } else {
            self.store
                .create(
                    &IssueRequest {
                        name: self.name.clone(),
                        identifiers: vec![DnsIdentifier::new("example.com").unwrap()],
                        account_name: "default".into(),
                        challenge: aster_acme::challenge::ChallengeKind::Dns01,
                        solver_id: "manual_dns".into(),
                        solver_config: serde_json::json!({}),
                        key_algorithm: KeyAlgorithm::EcdsaP256,
                    },
                    &self.account,
                )
                .await
                .unwrap()
        };
        let mut record = session.record().await.unwrap();
        let path = self
            .temp
            .path()
            .join("certs")
            .join(self.name.as_str())
            .join(record.generation_name());
        let key = zeroize::Zeroizing::new(std::fs::read(path.join("private-key.pk8")).unwrap());
        let key = rcgen::KeyPair::try_from(key.as_slice()).unwrap();
        let issuer = rcgen::Issuer::new(
            rcgen::CertificateParams::new(Vec::<String>::new()).unwrap(),
            rcgen::KeyPair::generate().unwrap(),
        );
        let params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
        let leaf = params.signed_by(&key, &issuer).unwrap().pem();
        record.phase = aster_acme_core::workflow::IssuancePhase::Completed;
        session.complete(&record, leaf.as_bytes()).await.unwrap()
    }

    async fn pending(&self, name: &str) {
        use aster_acme::storage::issuance::IssueStore;
        use aster_acme::{
            crypto::key_algorithm::KeyAlgorithm, identifier::DnsIdentifier, issuance::IssueRequest,
        };
        self.store
            .create(
                &IssueRequest {
                    name: CertificateName::new(name).unwrap(),
                    identifiers: vec![DnsIdentifier::new("pending.example.com").unwrap()],
                    account_name: "default".into(),
                    challenge: aster_acme::challenge::ChallengeKind::Dns01,
                    solver_id: "manual_dns".into(),
                    solver_config: serde_json::json!({}),
                    key_algorithm: KeyAlgorithm::EcdsaP256,
                },
                &self.account,
            )
            .await
            .unwrap();
    }

    async fn add(&self, id: &str, command: Vec<String>, retries: u8) -> PathBuf {
        let target = self.temp.path().join(id);
        std::fs::create_dir(&target).unwrap();
        self.store
            .add_deployment(
                &self.name,
                DeploymentDefinition {
                    permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
                    name: Some(id.into()),
                    target: DeploymentTarget::Directory {
                        path: target.clone(),
                    },
                    reload_command: command,
                    timeout_seconds: 1,
                    max_retries: retries,
                },
            )
            .await
            .unwrap();
        target
    }

    async fn automatic(&self, store: &CliIssueStore) -> Vec<DeploymentBinding> {
        let generation = store
            .query(IssueQuery {
                name: Some(self.name.clone()),
                in_use: Some(true),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .remove(0)
            .generation_name();
        after_issuance(
            store,
            &self.name,
            &generation,
            &aster_acme::solver::ExecutionContext {
                cancellation: tokio_util::sync::CancellationToken::new(),
                deadline: std::time::Instant::now() + Duration::from_secs(30),
            },
        )
        .await
        .0
    }

    async fn status(&self, id: &str) -> DeploymentBinding {
        self.store
            .deployments(&self.name)
            .await
            .unwrap()
            .into_iter()
            .find(|entry| entry.id == id)
            .unwrap()
    }
}

fn as_definition(binding: DeploymentBinding) -> DeploymentDefinition {
    DeploymentDefinition {
        permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
        name: Some(binding.id),
        target: binding.target,
        reload_command: binding.reload_command,
        timeout_seconds: binding.timeout_seconds,
        max_retries: binding.max_retries,
    }
}

pub(crate) fn child_command(mode: &str) -> Vec<String> {
    vec![
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        "--exact".into(),
        "commands::cert::deployment::tests::reload_child".into(),
        "--ignored".into(),
        "--nocapture".into(),
        mode.into(),
    ]
}

async fn manage_binding(
    fixture: &Fixture,
    arguments: &[&str],
) -> CliResult<super::super::report::CertificateReport> {
    use clap::Parser as _;
    let mut words = vec![
        "aster-acme",
        "cert",
        "deploy",
        arguments[0],
        "web",
        "--json",
        "--data-dir",
    ];
    words.push(fixture.temp.path().to_str().unwrap());
    words.extend_from_slice(&arguments[1..]);
    let parsed = crate::app::Args::try_parse_from(words).unwrap();
    let crate::app::Command::Cert {
        command: crate::commands::cert::args::CertCommand::Deploy(args),
    } = parsed.command
    else {
        panic!("expected deploy");
    };
    execute(
        args,
        &crate::common::context::CommandContext::new(true),
        tokio_util::sync::CancellationToken::new(),
    )
    .await
}

#[tokio::test]
async fn daemon_retries_only_due_known_deployment_failures_and_reschedules_them() {
    let fixture = Fixture::new().await;
    fixture
        .add("scheduled-failure", child_command("failure"), 0)
        .await;
    let binding = fixture.status("scheduled-failure").await;
    let mut session = fixture
        .store
        .open_deployment(&fixture.name, &binding.id)
        .await
        .unwrap();
    session
        .save_state(
            DeploymentPhase::ReloadFailed,
            1,
            Some("injected reload failure".into()),
        )
        .await
        .unwrap();
    let now = time::OffsetDateTime::now_utc();
    let first = session
        .record_failure(
            DeploymentPhase::ReloadFailed,
            1,
            "injected reload failure".into(),
            now,
        )
        .await
        .unwrap();
    drop(session);

    let cancellation = tokio_util::sync::CancellationToken::new();
    let idle = retry_due(
        &fixture.store,
        Duration::from_secs(5),
        &cancellation,
        &crate::common::context::CommandContext::new(true),
        managed_candidates(&fixture.store).await,
    )
    .await;
    assert!(idle.is_empty(), "future retry must not execute early");

    let mut session = fixture
        .store
        .open_deployment(&fixture.name, &binding.id)
        .await
        .unwrap();
    session
        .save_state(
            DeploymentPhase::ReloadFailed,
            1,
            Some("injected reload failure".into()),
        )
        .await
        .unwrap();
    session
        .record_failure(
            DeploymentPhase::ReloadFailed,
            1,
            "injected reload failure".into(),
            now - time::Duration::minutes(30),
        )
        .await
        .unwrap();
    drop(session);

    let attempted = retry_due(
        &fixture.store,
        Duration::from_secs(5),
        &cancellation,
        &crate::common::context::CommandContext::new(true),
        managed_candidates(&fixture.store).await,
    )
    .await;
    assert_eq!(attempted.len(), 1);
    assert!(attempted[0].has_failures());
    let saved = fixture.status("scheduled-failure").await;
    assert_eq!(saved.phase, DeploymentPhase::ReloadFailed);
    assert_eq!(saved.retry_failures, 3);
    assert!(saved.retry_at.is_some_and(|retry_at| retry_at > now));
    assert!(first.retry_at.is_some_and(|retry_at| retry_at > now));
}

#[tokio::test]
async fn daemon_never_replays_uncertain_reload_and_recovers_interrupted_publication() {
    let fixture = Fixture::new().await;
    fixture.add("uncertain", child_command("success"), 0).await;
    let binding = fixture.status("uncertain").await;
    let mut session = fixture
        .store
        .open_deployment(&fixture.name, &binding.id)
        .await
        .unwrap();
    session
        .save_state(DeploymentPhase::Publishing, 0, None)
        .await
        .unwrap();
    session
        .save_state(
            DeploymentPhase::ReloadUncertain,
            1,
            Some("reload result unknown".into()),
        )
        .await
        .unwrap();
    drop(session);

    fixture
        .add("publication-crash", child_command("success"), 0)
        .await;
    let binding = fixture.status("publication-crash").await;
    let mut session = fixture
        .store
        .open_deployment(&fixture.name, &binding.id)
        .await
        .unwrap();
    session
        .save_state(DeploymentPhase::Publishing, 0, None)
        .await
        .unwrap();
    drop(session);

    let recovered = retry_due(
        &fixture.store,
        Duration::from_secs(5),
        &tokio_util::sync::CancellationToken::new(),
        &crate::common::context::CommandContext::new(true),
        managed_candidates(&fixture.store).await,
    )
    .await;
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        fixture.status("publication-crash").await.phase,
        DeploymentPhase::Deployed
    );
    assert_eq!(
        fixture.status("uncertain").await.phase,
        DeploymentPhase::ReloadUncertain
    );
}

#[tokio::test]
async fn list_and_remove_bindings_work_after_revocation_or_loss_of_current_version() {
    use aster_acme_core::revocation::RevocationState;
    for state in [
        Some(RevocationState::Pending),
        Some(RevocationState::Confirmed),
        None,
    ] {
        let fixture = Fixture::new().await;
        let target = fixture.add("nginx", child_command("success"), 0).await;
        let original = run_one(
            &fixture.store,
            &fixture.name,
            "nginx",
            aster_acme::deployment::DeploymentIntent::Explicit,
            None,
            None,
        )
        .await
        .unwrap()
        .binding;
        let current = fixture
            .store
            .query(IssueQuery {
                name: Some(fixture.name.clone()),
                in_use: Some(true),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .remove(0);
        if let Some(state) = state {
            let session = fixture
                .store
                .open(&current.name, &current.operation_id)
                .await
                .unwrap();
            let mut record = session.record().await.unwrap();
            record.revocation.state = state;
            session.save(&record).await.unwrap();
        } else {
            let path = fixture.temp.path().join("certs/web/cert.toml");
            let text = std::fs::read_to_string(&path).unwrap();
            let cleared = text
                .lines()
                .filter(|line| !line.starts_with("in_use = "))
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(path, cleared).unwrap();
        }
        let published = std::fs::read(target.join("private-key.pem")).unwrap();
        assert!(manage_binding(&fixture, &["run"]).await.is_err());
        assert!(
            manage_binding(&fixture, &["run", "-n", "nginx"])
                .await
                .is_err()
        );
        let report = manage_binding(&fixture, &["list"]).await.unwrap();
        let crate::commands::cert::report::CertificateReport::Deployment(report) = report else {
            panic!("expected deployment report");
        };
        assert_eq!(report.entries, [original]);
        assert!(!report.attempted);
        manage_binding(&fixture, &["remove", "-n", "nginx"])
            .await
            .unwrap();
        assert_eq!(fixture.store.deployments(&fixture.name).await.unwrap(), []);
        assert_eq!(
            std::fs::read(target.join("private-key.pem")).unwrap(),
            published
        );
    }
}

#[tokio::test]
async fn deploy_entry_uses_shared_selection_for_missing_name_and_lists_explicit_targets() {
    use clap::Parser as _;
    let fixture = Fixture::new().await;
    for named in [false, true] {
        let mut words = vec![
            "aster-acme",
            "cert",
            "deploy",
            "list",
            "--json",
            "--data-dir",
        ];
        let root = fixture.temp.path().to_str().unwrap();
        words.push(root);
        if named {
            words.push("web");
        }
        let parsed = crate::app::Args::try_parse_from(words).unwrap();
        let crate::app::Command::Cert {
            command: super::super::args::CertCommand::Deploy(args),
        } = parsed.command
        else {
            panic!("expected deploy");
        };
        let cli = crate::common::context::CommandContext::new(true);
        let result = execute(args, &cli, tokio_util::sync::CancellationToken::new()).await;
        if named {
            let super::super::report::CertificateReport::Deployment(report) = result.unwrap()
            else {
                panic!("expected report");
            };
            assert_eq!(report.name, "web");
            assert_eq!(report.entries, []);
            assert!(!report.attempted);
        } else {
            let error = result.err().unwrap().to_string();
            assert!(error.contains("interactive terminal to select a certificate"));
        }
    }
}

#[test]
#[ignore = "subprocess reload fixture only"]
#[expect(
    clippy::zombie_processes,
    reason = "fixture models a successful parent leaving a descendant for the reload owner to terminate"
)]
fn reload_child() {
    match std::env::args().next_back().unwrap().as_str() {
        "failure" => std::process::exit(7),
        "timeout" => std::thread::sleep(Duration::from_secs(30)),
        "success" => {}
        "output-success" => {
            println!("reload stdout message");
            eprintln!("reload stderr message");
        }
        "output-failure" => {
            println!("failure stdout");
            eprintln!("failure stderr");
            std::process::exit(7);
        }
        "output-timeout" => {
            println!("output before timeout");
            std::thread::sleep(Duration::from_secs(30));
        }
        value if value.starts_with("verify-publication:") => {
            let target = Path::new(value.trim_start_matches("verify-publication:"));
            for name in ["cert.pem", "fullchain.pem", "ca.pem", "private-key.pem"] {
                assert_eq!(
                    std::fs::read(target.join(name)).unwrap(),
                    std::fs::read(target.join(format!("expected-{name}"))).unwrap()
                );
                let metadata = std::fs::symlink_metadata(target.join(name)).unwrap();
                assert!(metadata.is_file() && !metadata.file_type().is_symlink());
            }
            assert!(std::fs::read_dir(target).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".aster-acme-deploy-")
            }));
            std::fs::write(target.join("reload-observed"), b"complete set").unwrap();
        }
        "large-output" => {
            use std::io::Write as _;
            let out = std::thread::spawn(|| {
                let _ = std::io::stdout().write_all(&vec![b'o'; 256 * 1024]);
            });
            let err = std::thread::spawn(|| {
                let _ = std::io::stderr().write_all(&vec![b'e'; 256 * 1024]);
            });
            out.join().unwrap();
            err.join().unwrap();
        }
        value if value.starts_with("heartbeat:") => {
            heartbeat_child(value.trim_start_matches("heartbeat:"));
        }
        value if value.starts_with("tree-success:") || value.starts_with("tree-inherited:") => {
            let file = value
                .strip_prefix("tree-success:")
                .or_else(|| value.strip_prefix("tree-inherited:"))
                .unwrap();
            let mut command = child_command(&format!("heartbeat:{file}"));
            let program = command.remove(0);
            let mut child = std::process::Command::new(program);
            child.args(command);
            if value.starts_with("tree-success:") {
                child
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
            }
            let _child = child.spawn().unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !Path::new(file).exists() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        value if value.starts_with("tree:") || value.starts_with("tree-wait-inherited:") => {
            // Unlike tree-inherited, this parent stays alive while the child
            // holds its pipes, exercising timeout rather than successful exit.
            let inherited = value.starts_with("tree-wait-inherited:");
            let file = value
                .strip_prefix("tree-wait-inherited:")
                .or_else(|| value.strip_prefix("tree:"))
                .unwrap();
            let mut command = child_command(&format!("heartbeat:{file}"));
            let program = command.remove(0);
            let mut process = std::process::Command::new(program);
            process.args(command);
            if !inherited {
                process
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
            }
            let mut child = process.spawn().unwrap();
            println!("descendant started");
            let _ = child.wait();
        }
        _ => panic!("unknown reload fixture mode"),
    }
}

fn heartbeat_child(file: &str) {
    // This lock is held for the entire infinite fixture lifetime.
    // The kernel releases it on process termination, independently
    // of whether the heartbeat happened to receive CPU time.
    let lifetime = std::fs::File::create(Path::new(file).with_extension("alive")).unwrap();
    lifetime.lock().unwrap();
    std::fs::write(
        Path::new(file).with_extension("pid"),
        std::process::id().to_string(),
    )
    .unwrap();
    loop {
        std::fs::write(file, format!("{:?}", std::time::SystemTime::now())).unwrap();
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The fixture never unlocks voluntarily. Acquiring this kernel lock is an
/// exit notification, unlike observing an unchanged heartbeat after a sleep.
pub(in crate::commands::cert::deployment) async fn assert_descendant_exited(heartbeat: &Path) {
    let pid = std::fs::read_to_string(heartbeat.with_extension("pid")).unwrap();
    let lifetime = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(heartbeat.with_extension("alive"))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match lifetime.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("cannot observe descendant {pid} termination: {error}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("descendant {pid} still owns its lifetime lock"));
}

#[tokio::test]
#[ignore = "PTY interaction fixture only"]
async fn interactive_selection_child() {
    use clap::Parser as _;
    let fixture = Fixture::new().await;
    fixture.pending("z-pending").await;
    let action_value = std::env::var("ASTER_DEPLOY_TEST_ACTION").unwrap_or_else(|_| "run".into());
    let action = if action_value == "add-bare" {
        "add"
    } else if action_value == "show-named" {
        "show"
    } else {
        action_value.as_str()
    };
    if action != "add" {
        fixture
            .add("nginx", child_command("output-success"), 0)
            .await;
    }
    let root = fixture.temp.path().to_str().unwrap();
    let command = shlex::try_join(child_command("success").iter().map(String::as_str)).unwrap();
    let target = fixture.temp.path().join("interactive target");
    std::fs::create_dir(&target).unwrap();
    let mut words = vec!["aster-acme", "cert", "deploy", action, "--data-dir", root];
    if action == "update" {
        words.push("--clear-reload");
    }
    if action_value == "show-named" {
        words.push("web");
    }
    if action_value == "add-bare" {
        println!("TEST_TARGET={}", target.display());
    }
    if action == "add" && action_value != "add-bare" {
        words.extend([
            "--target",
            target.to_str().unwrap(),
            "--reload-cmd",
            &command,
        ]);
    }
    let parsed = crate::app::Args::try_parse_from(words).unwrap();
    let crate::app::Command::Cert {
        command: super::super::args::CertCommand::Deploy(args),
    } = parsed.command
    else {
        panic!("expected deploy");
    };
    let cli = crate::common::context::CommandContext::new(false);
    match execute(args, &cli, tokio_util::sync::CancellationToken::new()).await {
        Ok(report) => {
            let text =
                super::super::render::render(&report, crate::common::session::Format::plain(false))
                    .unwrap();
            println!("{text}");
        }
        Err(error) if error.is::<crate::common::terminal::Canceled>() => {
            println!("selection cancelled");
        }
        Err(error) => panic!("unexpected selection error: {error}"),
    }
}

#[tokio::test]
async fn explicit_retry_recovers_failed_publication_and_binding_validation_is_durable() {
    let fixture = Fixture::new().await;
    let generation = fixture.generation().await;
    let target = fixture.add("nginx", child_command("success"), 0).await;
    let definition = fixture.status("nginx").await;
    assert!(
        fixture
            .store
            .add_deployment(&fixture.name, as_definition(definition))
            .await
            .is_err()
    );
    std::fs::create_dir(target.join("fullchain.pem")).unwrap();
    assert_eq!(
        run_one(
            &fixture.store,
            &fixture.name,
            "nginx",
            DeploymentIntent::AfterIssuance {
                generation: &generation
            },
            Some(&fixture.progress),
            None
        )
        .await
        .unwrap()
        .binding
        .phase,
        DeploymentPhase::PublishFailed
    );
    std::fs::remove_dir(target.join("fullchain.pem")).unwrap();
    let recovered = run_one(
        &fixture.store,
        &fixture.name,
        "nginx",
        aster_acme::deployment::DeploymentIntent::Explicit,
        Some(&fixture.progress),
        None,
    )
    .await
    .unwrap();
    assert_eq!(recovered.binding.phase, DeploymentPhase::Deployed);
    assert_eq!(recovered.binding.attempts, 1);
    assert_eq!(recovered.binding.last_error, None);
    fixture
        .store
        .remove_deployment(&fixture.name, "nginx")
        .await
        .unwrap();
    assert!(target.join("private-key.pem").exists());
    assert!(
        fixture
            .store
            .remove_deployment(&fixture.name, "nginx")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn deploy_and_renewal_publish_current_generation_skip_completed_and_keep_bindings() {
    let fixture = Fixture::new().await;
    let generation = fixture.generation().await;
    let target = fixture.add("nginx", child_command("success"), 0).await;
    let first = run_one(
        &fixture.store,
        &fixture.name,
        "nginx",
        DeploymentIntent::AfterIssuance {
            generation: &generation,
        },
        Some(&fixture.progress),
        None,
    )
    .await
    .unwrap();
    assert_eq!(first.binding.phase, DeploymentPhase::Deployed);
    let initial = std::fs::read(target.join("private-key.pem")).unwrap();
    std::fs::write(target.join("cert.pem"), b"sentinel").unwrap();
    let repeated = fixture.automatic(&fixture.store).await;
    assert_eq!(repeated.as_slice(), std::slice::from_ref(&first.binding));
    assert_eq!(std::fs::read(target.join("cert.pem")).unwrap(), b"sentinel");
    let renewal = fixture.complete(true).await;
    let renewed = fixture.automatic(&fixture.store).await;
    assert_eq!(renewed.len(), 1);
    assert_eq!(renewed[0].phase, DeploymentPhase::Deployed);
    assert_eq!(
        renewed[0].generation.as_deref(),
        Some(renewal.generation_name().as_str())
    );
    assert_ne!(renewed[0].generation, first.binding.generation);
    assert_ne!(
        std::fs::read(target.join("private-key.pem")).unwrap(),
        initial
    );
    let source = fixture
        .temp
        .path()
        .join("certs/web")
        .join(renewal.generation_name());
    for filename in ["cert.pem", "fullchain.pem", "ca.pem", "private-key.pem"] {
        assert_eq!(
            std::fs::read(target.join(filename)).unwrap(),
            std::fs::read(source.join(filename)).unwrap()
        );
    }
}

#[tokio::test]
async fn reload_failures_are_bounded_and_other_targets_continue() {
    let fixture = Fixture::new().await;
    fixture.add("bad", child_command("failure"), 2).await;
    fixture.add("good", child_command("success"), 0).await;
    let results = fixture.automatic(&fixture.store).await;
    assert_eq!(results[0].phase, DeploymentPhase::ReloadFailed);
    assert_eq!(results[0].attempts, 3);
    assert_eq!(results[1].phase, DeploymentPhase::Deployed);
    assert_eq!(results[1].attempts, 1);
    assert!(
        fixture
            .store
            .query(IssueQuery::default())
            .await
            .unwrap()
            .iter()
            .any(|r| r.is_in_use && !r.unfinished())
    );
}

#[tokio::test]
async fn timeout_is_uncertain_survives_reopen_and_is_not_automatically_replayed() {
    let fixture = Fixture::new().await;
    let generation = fixture.generation().await;
    let target = fixture.add("slow", child_command("timeout"), 3).await;
    assert_ne!(
        run_one(
            &fixture.store,
            &fixture.name,
            "slow",
            DeploymentIntent::AfterIssuance {
                generation: &generation
            },
            Some(&fixture.progress),
            None
        )
        .await
        .unwrap()
        .binding
        .phase,
        DeploymentPhase::Deployed
    );
    let saved = fixture.status("slow").await;
    assert_eq!(saved.phase, DeploymentPhase::ReloadUncertain);
    assert_eq!(saved.attempts, 1);
    std::fs::write(target.join("cert.pem"), b"unchanged").unwrap();
    let reopened = CliIssueStore::new(fixture.temp.path().into(), Duration::from_millis(100));
    let result = fixture.automatic(&reopened).await;
    assert_eq!(result, [saved]);
    assert_eq!(
        std::fs::read(target.join("cert.pem")).unwrap(),
        b"unchanged"
    );
}

#[tokio::test]
async fn cancelling_reload_preserves_intent_releases_lease_and_prevents_automatic_replay() {
    let fixture = Fixture::new().await;
    let generation = fixture.generation().await;
    fixture.add("slow", child_command("timeout"), 0).await;
    let catalog = fixture.temp.path().join("certs/web/cert.toml");
    {
        let execution = run_one(
            &fixture.store,
            &fixture.name,
            "slow",
            DeploymentIntent::AfterIssuance {
                generation: &generation,
            },
            Some(&fixture.progress),
            None,
        );
        tokio::pin!(execution);
        tokio::select! {
            result = &mut execution => panic!("reload finished before cancellation: {}", result.is_ok()),
            () = async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        let text = std::fs::read_to_string(&catalog).unwrap();
                        if text.contains("phase = \"reloading\"") { break; }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }).await.unwrap();
            } => {},
        }
    }
    let saved = fixture.status("slow").await;
    assert_eq!(saved.phase, DeploymentPhase::Reloading);
    assert_eq!(saved.attempts, 1);
    assert_eq!(fixture.automatic(&fixture.store).await, [saved]);
}

#[tokio::test]
async fn publication_failure_does_not_run_reload_and_missing_program_is_saved() {
    let fixture = Fixture::new().await;
    let target = fixture.add("badpath", child_command("success"), 0).await;
    std::fs::create_dir(target.join("fullchain.pem")).unwrap();
    assert_ne!(
        run_one(
            &fixture.store,
            &fixture.name,
            "badpath",
            aster_acme::deployment::DeploymentIntent::Explicit,
            Some(&fixture.progress),
            None
        )
        .await
        .unwrap()
        .binding
        .phase,
        DeploymentPhase::Deployed
    );
    let entry = fixture.status("badpath").await;
    assert_eq!(entry.phase, DeploymentPhase::PublishFailed);
    assert_eq!(entry.attempts, 0);
    fixture
        .add(
            "missing",
            vec![
                fixture
                    .temp
                    .path()
                    .join("nonexistent-program")
                    .to_string_lossy()
                    .into_owned(),
            ],
            0,
        )
        .await;
    assert_ne!(
        run_one(
            &fixture.store,
            &fixture.name,
            "missing",
            aster_acme::deployment::DeploymentIntent::Explicit,
            Some(&fixture.progress),
            None
        )
        .await
        .unwrap()
        .binding
        .phase,
        DeploymentPhase::Deployed
    );
    let entry = fixture.status("missing").await;
    assert_eq!(entry.phase, DeploymentPhase::ReloadFailed);
    assert_eq!(entry.attempts, 1);
}

#[tokio::test]
async fn deployment_lease_excludes_removal_and_binding_changes_and_releases_after_drop() {
    let fixture = Fixture::new().await;
    fixture.add("nginx", child_command("success"), 0).await;
    let session = fixture
        .store
        .open_deployment(&fixture.name, "nginx")
        .await
        .unwrap();
    assert!(
        fixture
            .store
            .remove_deployment(&fixture.name, "nginx")
            .await
            .is_err()
    );
    assert!(
        fixture
            .store
            .renew(&fixture.name, &fixture.account)
            .await
            .is_err()
    );
    drop(session);
    fixture
        .store
        .remove_deployment(&fixture.name, "nginx")
        .await
        .unwrap();
    assert_eq!(fixture.store.deployments(&fixture.name).await.unwrap(), []);
}

#[test]
fn reload_command_uses_shell_quoting_only_for_argv_and_rejects_bad_bounds() {
    assert_eq!(
        parse_command("systemctl restart nginx").unwrap(),
        ["systemctl", "restart", "nginx"]
    );
    assert_eq!(
        parse_command("/usr/bin/env SERVICE='nginx web' restart").unwrap(),
        ["/usr/bin/env", "SERVICE=nginx web", "restart"]
    );
    assert_eq!(
        parse_command("printf '%s' 'a | b'").unwrap(),
        ["printf", "%s", "a | b"]
    );
    assert!(parse_command("").is_err());
    assert!(parse_command("systemctl 'restart").is_err());
    assert!(parse_command(&format!("program {}", "x".repeat(4097))).is_err());
    assert!(parse_command(&format!("program{}", " arg".repeat(64))).is_err());
}

#[test]
fn deployment_selection_is_exact_and_empty_inventory_is_explicit() {
    let entries = vec![DeploymentBinding {
        permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
        id: "nginx".into(),
        target: DeploymentTarget::Directory {
            path: PathBuf::from("/tmp"),
        },
        reload_command: vec!["true".into()],
        timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        max_retries: DEFAULT_RETRIES,
        generation: None,
        phase: DeploymentPhase::Configured,
        attempts: 0,
        retry_failures: 0,
        retry_at: None,
        last_error: None,
    }];
    assert_eq!(
        select_targets(entries.clone(), Some("nginx"))
            .unwrap()
            .len(),
        1
    );
    assert!(select_targets(entries, Some("Nginx")).is_err());
    assert_eq!(select_targets(Vec::new(), None).unwrap(), []);
}

#[tokio::test]
async fn storage_rechecks_revocation_before_opening_or_adding_deployment() {
    let fixture = Fixture::new().await;
    fixture.add("nginx", child_command("success"), 0).await;
    let current = fixture
        .store
        .query(IssueQuery {
            name: Some(fixture.name.clone()),
            in_use: Some(true),
            ..IssueQuery::default()
        })
        .await
        .unwrap()
        .remove(0);
    let session = fixture
        .store
        .open(&current.name, &current.operation_id)
        .await
        .unwrap();
    let mut saved = session.record().await.unwrap();
    saved.revocation.state = aster_acme_core::revocation::RevocationState::Confirmed;
    session.save(&saved).await.unwrap();
    drop(session);
    assert!(
        fixture
            .store
            .open_deployment(&fixture.name, "nginx")
            .await
            .is_err()
    );
    let mut binding = fixture.status("nginx").await;
    binding.id = "second".into();
    assert!(
        fixture
            .store
            .add_deployment(&fixture.name, as_definition(binding))
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .store
            .deployments(&fixture.name)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn cli_subcommands_add_run_all_or_one_list_and_remove_without_reissuing() {
    let fixture = Fixture::new().await;
    let command = shlex::try_join(child_command("success").iter().map(String::as_str)).unwrap();
    let original = fixture.store.query(IssueQuery::default()).await.unwrap()[0]
        .operation_id
        .clone();
    for id in ["nginx", "service"] {
        let target = fixture.temp.path().join(format!("{id} with spaces"));
        std::fs::create_dir(&target).unwrap();
        let report = manage_binding(
            &fixture,
            &[
                "add",
                "-n",
                id,
                "--target",
                target.to_str().unwrap(),
                "--reload-cmd",
                &command,
                "--reload-timeout",
                "1",
                "--max-retries",
                "0",
            ],
        )
        .await
        .unwrap();
        assert!(matches!(
            report.exit_status(),
            crate::common::session::ExitStatus::Success
        ));
        let saved = fixture.status(id).await;
        assert_eq!(saved.phase, DeploymentPhase::Deployed);
        assert_eq!(saved.timeout_seconds, 1);
        assert_eq!(saved.max_retries, 0);
        assert!(target.join("private-key.pem").is_file());
    }
    for (arguments, count) in [
        (vec!["run"], 2),
        (vec!["run", "-n", "nginx"], 1),
        (vec!["list"], 2),
    ] {
        let crate::commands::cert::report::CertificateReport::Deployment(report) =
            manage_binding(&fixture, &arguments).await.unwrap()
        else {
            panic!("expected deployment report");
        };
        assert_eq!(report.entries.len(), count);
        assert_eq!(report.attempted, arguments[0] == "run");
        assert!(
            report
                .entries
                .iter()
                .all(|entry| entry.phase == DeploymentPhase::Deployed)
        );
    }
    assert!(
        manage_binding(&fixture, &["run", "-n", "missing"])
            .await
            .is_err()
    );
    manage_binding(&fixture, &["remove", "-n", "nginx"])
        .await
        .unwrap();
    assert_eq!(
        fixture
            .store
            .deployments(&fixture.name)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        fixture
            .temp
            .path()
            .join("nginx with spaces/private-key.pem")
            .exists()
    );
    let records = fixture.store.query(IssueQuery::default()).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].operation_id, original);
}

#[tokio::test]
async fn automation_generates_add_name_but_requires_explicit_remove_name() {
    let fixture = Fixture::new().await;
    let report = manage_binding(
        &fixture,
        &["add", "--target", fixture.temp.path().to_str().unwrap()],
    )
    .await
    .unwrap();
    let crate::commands::cert::report::CertificateReport::Deployment(report) = report else {
        panic!("expected deployment report");
    };
    assert!(report.entries[0].id.starts_with("deploy-"));
    let error = manage_binding(&fixture, &["remove"]).await.err().unwrap();
    assert!(error.to_string().contains("Specify a deployment name"));
    assert_eq!(
        fixture
            .store
            .deployments(&fixture.name)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn query_counts_bindings_per_certificate_without_persisting_inventory_snapshots() {
    let fixture = Fixture::new().await;
    for (id, count) in [(Some("nginx"), 0), (Some("service"), 1), (None, 2)] {
        for view in [IssueView::All, IssueView::Managed] {
            let records = fixture
                .store
                .query(IssueQuery {
                    name: Some(fixture.name.clone()),
                    view,
                    ..IssueQuery::default()
                })
                .await
                .unwrap();
            assert!(
                records
                    .iter()
                    .all(|record| record.deployment_count == Some(count))
            );
            for record in records {
                assert!(
                    serde_json::to_value(record)
                        .unwrap()
                        .get("deployment_count")
                        .is_none()
                );
            }
        }
        if let Some(id) = id {
            fixture.add(id, child_command("success"), 0).await;
        }
    }
    let renewed = fixture.complete(true).await;
    assert_eq!(
        fixture
            .store
            .query(IssueQuery::default())
            .await
            .unwrap()
            .len(),
        2
    );
    fixture
        .store
        .remove_deployment(&fixture.name, "nginx")
        .await
        .unwrap();
    assert!(
        fixture
            .store
            .query(IssueQuery::default())
            .await
            .unwrap()
            .iter()
            .all(|record| record.deployment_count == Some(1))
    );
    fixture
        .store
        .remove_deployment(&fixture.name, "service")
        .await
        .unwrap();
    let session = fixture
        .store
        .open(&fixture.name, &renewed.operation_id)
        .await
        .unwrap();
    assert_eq!(session.record().await.unwrap().deployment_count, Some(0));
    let journal = fixture
        .temp
        .path()
        .join("certs/web")
        .join(renewed.generation_name())
        .join("operation.toml");
    assert!(
        !std::fs::read_to_string(journal)
            .unwrap()
            .contains("deployment_count")
    );
}

#[tokio::test]
async fn remove_returns_only_the_removed_identity_for_last_or_remaining_bindings() {
    let fixture = Fixture::new().await;
    for id in ["nginx", "service"] {
        fixture.add(id, child_command("success"), 0).await;
    }
    for id in ["nginx", "service"] {
        let report = manage_binding(&fixture, &["remove", "-n", id])
            .await
            .unwrap();
        assert!(matches!(
            report.exit_status(),
            crate::common::session::ExitStatus::Success
        ));
        let human = crate::commands::cert::render::render(
            &report,
            crate::common::session::Format::plain(false),
        )
        .unwrap();
        assert_eq!(human, format!("[DONE] Deployment '{id}' removed."));
        assert!(!human.contains("Tips:"));
        assert!(!human.contains("Local deployments"));
        let json: serde_json::Value = serde_json::from_str(
            &crate::commands::cert::render::render(
                &report,
                crate::common::session::Format::plain(true),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["status"], "removed");
        assert_eq!(json["certificate"], "web");
        assert_eq!(json["deployment"], id);
        assert!(json.get("deployments").is_none());
        assert!(
            manage_binding(&fixture, &["remove", "-n", id])
                .await
                .is_err()
        );
    }
    assert_eq!(fixture.store.deployments(&fixture.name).await.unwrap(), []);
}

#[tokio::test]
async fn optional_reload_publishes_and_renews_without_any_process_attempt() {
    let fixture = Fixture::new().await;
    let target = fixture.temp.path().join("publication only");
    std::fs::create_dir(&target).unwrap();
    let report = manage_binding(
        &fixture,
        &["add", "-n", "files", "--target", target.to_str().unwrap()],
    )
    .await
    .unwrap();
    assert!(matches!(
        report.exit_status(),
        crate::common::session::ExitStatus::Success
    ));
    let saved = fixture.status("files").await;
    assert_eq!(saved.phase, DeploymentPhase::Deployed);
    assert_eq!(saved.attempts, 0);
    assert_eq!(saved.reload_command, [] as [&str; 0]);
    let old_key = std::fs::read(target.join("private-key.pem")).unwrap();
    let renewal = fixture.complete(true).await;
    let (bindings, events) = after_issuance(
        &fixture.store,
        &fixture.name,
        &renewal.generation_name(),
        &aster_acme::solver::ExecutionContext {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: std::time::Instant::now() + Duration::from_secs(30),
        },
    )
    .await;
    assert_eq!(bindings[0].phase, DeploymentPhase::Deployed);
    assert_eq!(bindings[0].attempts, 0);
    assert!(
        events
            .iter()
            .any(|event| event.message.contains("no reload command configured"))
    );
    assert!(
        !events
            .iter()
            .any(|event| event.message.contains("reload succeeded"))
    );
    assert_ne!(
        std::fs::read(target.join("private-key.pem")).unwrap(),
        old_key
    );
}

#[tokio::test]
async fn scripts_can_publish_exact_paths_without_reload_but_cannot_omit_destinations() {
    let fixture = Fixture::new().await;
    let root = fixture.temp.path();
    let error = manage_binding(&fixture, &["add", "-n", "missing-target"])
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("--target"));
    assert_eq!(fixture.store.deployments(&fixture.name).await.unwrap(), []);
    let cert = root.join("leaf.pem");
    let key = root.join("key.pem");
    manage_binding(
        &fixture,
        &[
            "add",
            "-n",
            "files",
            "--cert-path",
            cert.to_str().unwrap(),
            "--key-path",
            key.to_str().unwrap(),
        ],
    )
    .await
    .unwrap();
    assert!(cert.is_file());
    assert!(key.is_file());
    assert_eq!(fixture.status("files").await.attempts, 0);
    for command in ["", "'unbalanced"] {
        assert!(
            manage_binding(
                &fixture,
                &[
                    "add",
                    "-n",
                    "invalid",
                    "--target",
                    root.to_str().unwrap(),
                    "--reload-cmd",
                    command
                ]
            )
            .await
            .is_err()
        );
    }
    assert_eq!(
        fixture
            .store
            .deployments(&fixture.name)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn generated_names_are_persisted_unique_under_concurrency_and_bounded_by_inventory_limit() {
    let fixture = Fixture::new().await;
    let store = CliIssueStore::new(fixture.temp.path().into(), Duration::from_secs(2));
    let first_target = fixture.temp.path().join("auto-first");
    let second_target = fixture.temp.path().join("auto-second");
    std::fs::create_dir(&first_target).unwrap();
    std::fs::create_dir(&second_target).unwrap();
    let definition = DeploymentDefinition {
        permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
        name: None,
        target: DeploymentTarget::Directory { path: first_target },
        reload_command: Vec::new(),
        timeout_seconds: 30,
        max_retries: 3,
    };
    let mut other = definition.clone();
    other.target = DeploymentTarget::Directory {
        path: second_target,
    };
    let (first, second) = tokio::join!(
        store.add_deployment(&fixture.name, definition.clone()),
        store.add_deployment(&fixture.name, other)
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first.id, second.id);
    assert!(first.id.starts_with("deploy-"));
    assert!(second.id.starts_with("deploy-"));
    let reopened = CliIssueStore::new(fixture.temp.path().into(), Duration::from_secs(2));
    let reopened = reopened.deployments(&fixture.name).await.unwrap();
    assert_eq!(reopened.len(), 2);
    assert!(reopened.contains(&first));
    assert!(reopened.contains(&second));
    for index in 2..32 {
        let target = fixture.temp.path().join(format!("auto-{index}"));
        std::fs::create_dir(&target).unwrap();
        let mut next = definition.clone();
        next.target = DeploymentTarget::Directory { path: target };
        store.add_deployment(&fixture.name, next).await.unwrap();
    }
    assert!(
        store
            .add_deployment(&fixture.name, definition)
            .await
            .is_err()
    );
    assert_eq!(store.deployments(&fixture.name).await.unwrap().len(), 32);
}

#[tokio::test]
async fn every_nonempty_exact_artifact_subset_publishes_only_selected_files_and_renews() {
    let fixture = Fixture::new().await;
    let artifacts = [
        ("--cert-path", "cert.pem"),
        ("--key-path", "private-key.pem"),
        ("--ca-path", "ca.pem"),
        ("--fullchain-path", "fullchain.pem"),
    ];
    for mask in 1_u32..16 {
        let root = fixture.temp.path().join(format!("subset-{mask}"));
        std::fs::create_dir(&root).unwrap();
        let mut words = vec!["add".to_owned(), "-n".into(), format!("subset-{mask}")];
        for (bit, (flag, file)) in artifacts.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                words.extend([
                    (*flag).into(),
                    root.join(file).to_string_lossy().into_owned(),
                ]);
            }
        }
        let refs = words.iter().map(String::as_str).collect::<Vec<_>>();
        let report = manage_binding(&fixture, &refs).await.unwrap();
        assert!(matches!(
            report.exit_status(),
            crate::common::session::ExitStatus::Success
        ));
        assert_eq!(
            std::fs::read_dir(root).unwrap().count(),
            usize::try_from(mask.count_ones()).unwrap()
        );
    }
    for renewal in [false, true] {
        if renewal {
            fixture.complete(true).await;
            fixture.automatic(&fixture.store).await;
        }
        let current = fixture
            .store
            .query(IssueQuery {
                in_use: Some(true),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .remove(0);
        let source = fixture
            .temp
            .path()
            .join("certs/web")
            .join(current.generation_name());
        for mask in 1_u32..16 {
            let root = fixture.temp.path().join(format!("subset-{mask}"));
            for (bit, (_, file)) in artifacts.iter().enumerate() {
                if mask & (1 << bit) != 0 {
                    assert_eq!(
                        std::fs::read(root.join(file)).unwrap(),
                        std::fs::read(source.join(file)).unwrap(),
                        "mask={mask}, artifact={file}, renewal={renewal}"
                    );
                } else {
                    assert!(!root.join(file).exists());
                }
            }
        }
    }
    assert!(
        fixture
            .store
            .deployments(&fixture.name)
            .await
            .unwrap()
            .iter()
            .all(|binding| binding.attempts == 0)
    );
}

#[tokio::test]
async fn show_exact_binding_is_offline_reads_config_without_private_keys_and_never_reloads() {
    let fixture = Fixture::new().await;
    fixture.add("nginx", child_command("failure"), 2).await;
    fixture.add("other", child_command("timeout"), 0).await;
    let current = fixture
        .store
        .query(IssueQuery {
            in_use: Some(true),
            ..IssueQuery::default()
        })
        .await
        .unwrap()
        .remove(0);
    let root = fixture.temp.path().join("certs/web");
    let generation = root.join(current.generation_name());
    std::fs::remove_file(generation.join("private-key.pk8")).unwrap();
    let before = std::fs::read(root.join("cert.toml")).unwrap();
    let journal = std::fs::read(generation.join("operation.toml")).unwrap();
    let report = manage_binding(&fixture, &["show", "nginx"]).await.unwrap();
    assert!(matches!(
        report.exit_status(),
        crate::common::session::ExitStatus::Success
    ));
    let crate::commands::cert::report::CertificateReport::DeploymentDetails { name, binding } =
        &report
    else {
        panic!("expected details");
    };
    assert_eq!(name, "web");
    assert_eq!(binding.id, "nginx");
    assert_eq!(binding.reload_command, child_command("failure"));
    assert_eq!(binding.attempts, 0);
    assert_eq!(binding.phase, DeploymentPhase::Configured);
    let json: serde_json::Value = serde_json::from_str(
        &crate::commands::cert::render::render(
            &report,
            crate::common::session::Format::plain(true),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(json["deployment"]["max_retries"], 2);
    assert_eq!(json["deployment"]["timeout_seconds"], 1);
    assert!(!fixture.temp.path().join("nginx/fullchain.pem").exists());
    assert!(
        manage_binding(&fixture, &["show", "missing"])
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("not found")
    );
    assert!(
        manage_binding(&fixture, &["show"])
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("cert deploy show CERT_NAME DEPLOY_NAME")
    );
    assert_eq!(std::fs::read(root.join("cert.toml")).unwrap(), before);
    assert_eq!(
        std::fs::read(generation.join("operation.toml")).unwrap(),
        journal
    );
}

#[tokio::test]
async fn show_works_for_revocation_pending_revoked_and_missing_current_version() {
    use aster_acme_core::revocation::RevocationState;
    for state in [
        Some(RevocationState::Pending),
        Some(RevocationState::Confirmed),
        None,
    ] {
        let fixture = Fixture::new().await;
        fixture.add("nginx", child_command("failure"), 0).await;
        let original = fixture.status("nginx").await;
        let current = fixture
            .store
            .query(IssueQuery {
                in_use: Some(true),
                ..IssueQuery::default()
            })
            .await
            .unwrap()
            .remove(0);
        if let Some(state) = state {
            let session = fixture
                .store
                .open(&current.name, &current.operation_id)
                .await
                .unwrap();
            let mut record = session.record().await.unwrap();
            record.revocation.state = state;
            session.save(&record).await.unwrap();
        } else {
            let path = fixture.temp.path().join("certs/web/cert.toml");
            let text = std::fs::read_to_string(&path).unwrap();
            let cleared = text
                .lines()
                .filter(|line| !line.starts_with("in_use = "))
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(path, cleared).unwrap();
        }
        let crate::commands::cert::report::CertificateReport::DeploymentDetails { binding, .. } =
            manage_binding(&fixture, &["show", "nginx"]).await.unwrap()
        else {
            panic!("expected details");
        };
        assert_eq!(*binding, original);
        assert!(!fixture.temp.path().join("nginx/fullchain.pem").exists());
    }
}

#[tokio::test]
async fn bare_show_in_json_requires_certificate_and_missing_deployments_never_guess() {
    use clap::Parser as _;
    let fixture = Fixture::new().await;
    let root = fixture.temp.path().to_str().unwrap();
    let parsed = crate::app::Args::try_parse_from([
        "aster-acme",
        "cert",
        "deploy",
        "show",
        "--json",
        "--data-dir",
        root,
    ])
    .unwrap();
    let crate::app::Command::Cert {
        command: crate::commands::cert::args::CertCommand::Deploy(args),
    } = parsed.command
    else {
        panic!("expected show");
    };
    assert!(
        execute(
            args,
            &crate::common::context::CommandContext::new(true),
            tokio_util::sync::CancellationToken::new()
        )
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("Specify a certificate")
    );
    assert!(manage_binding(&fixture, &["show"]).await.is_err());
    assert!(
        manage_binding(&fixture, &["show", "missing"])
            .await
            .is_err()
    );
    assert_eq!(fixture.store.deployments(&fixture.name).await.unwrap(), []);
}

#[test]
fn bare_deployment_filename_resolves_against_current_directory() {
    assert_eq!(
        canonical_file_path(Path::new("cert.pem")).unwrap(),
        std::env::current_dir()
            .unwrap()
            .canonicalize()
            .unwrap()
            .join("cert.pem")
    );
}

mod lifecycle;
mod reliability;
