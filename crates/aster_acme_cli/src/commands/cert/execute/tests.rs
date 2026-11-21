//! Execute regression tests.

use crate::commands::cert::execute::failure::report_issue_failure;
use crate::commands::cert::execute::issuance::allocate_certificate;
use crate::commands::cert::execute::transaction::{attach_deployment_results, report_material};
use crate::commands::cert::execute::*;
use crate::commands::cert::progress::Progress;
use crate::common::args::{HttpArgs, LocalArgs};
use crate::{commands::account::args::AccountArgs, common::context::CliSettings};
use aster_acme::storage::account::{AccountKeyStore, AccountStore};
use aster_acme::storage::issuance::IssueStore;
use aster_acme::storage::query::IssueQuery;
use aster_acme::{
    identifier::{DnsIdentifier, Identifier},
    issuance::{CertificateName, IssueError, IssueOutcome, IssueRecord, IssueRequest},
    solver::ExecutionContext,
};
use aster_acme_cli_storage::issuance::CliIssueStore;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Regression matrix covers initial issue and renewal deployment in one transaction"
)]
async fn external_dns_renewal_uses_the_shared_automatic_deployment_path() {
    use aster_acme_cli_storage::issuance::{
        DeploymentDefinition, DeploymentPermissions, DeploymentTarget,
    };
    let temp = tempfile::tempdir().unwrap();
    let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(2));
    let account = allocation_account();
    let mut request = IssueRequest {
        name: CertificateName::new("dns-cert").unwrap(),
        identifiers: vec![Identifier::Dns(DnsIdentifier::new("example.com").unwrap())],
        profile: None,
        account_name: "default".into(),
        key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
        challenge: aster_acme::challenge::ChallengeKind::Dns01,
        solver_id: "dns_provider".into(),
        solver_config: crate::commands::cert::validation::provider::provider_configuration(Some(
            "prod",
        ))
        .unwrap(),
    };
    request.solver_config["dns_targets"] = serde_json::json!({
        "example.com": "verify.validation.net."
    });
    let target = temp.path().join("published");
    std::fs::create_dir(&target).unwrap();
    let mut predecessor: Option<String> = None;
    for renewal in [false, true] {
        let session = if renewal {
            store.renew(&request.name, &account).await.unwrap()
        } else {
            store.create(&request, &account).await.unwrap()
        };
        let mut record = session.record().await.unwrap();
        assert_eq!(
            record.solver_config["dns_targets"]["example.com"],
            "verify.validation.net."
        );
        if renewal {
            assert_eq!(
                record.renewal_of.as_ref().unwrap().operation_id,
                predecessor.as_ref().unwrap().as_str()
            );
        }
        let generation = temp
            .path()
            .join("certs/dns-cert")
            .join(record.generation_name());
        let key = rcgen::KeyPair::try_from(
            std::fs::read(generation.join("private-key.pk8"))
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["example.com".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();
        record.phase = aster_acme_core::workflow::IssuancePhase::Completed;
        let record = session
            .complete(&record, certificate.as_bytes())
            .await
            .unwrap();
        drop(session);
        if renewal {
            let result = attach_deployment_results(
                IssueOutcome::Completed {
                    record: Box::new(record),
                    cleanup: Vec::new(),
                },
                &store,
                &ExecutionContext {
                    cancellation: CancellationToken::new(),
                    deadline: Instant::now() + Duration::from_secs(10),
                },
                &crate::common::session::OutputSession::new(true),
            )
            .await;
            let crate::commands::cert::report::CertificateResult::Issued { deployments, .. } =
                result
            else {
                panic!("renewal did not run configured deployments");
            };
            assert_eq!(deployments.len(), 1);
            assert_eq!(
                deployments[0].phase,
                aster_acme::deployment::DeploymentPhase::Deployed
            );
            assert_eq!(
                std::fs::read(target.join("fullchain.pem")).unwrap(),
                std::fs::read(generation.join("fullchain.pem")).unwrap()
            );
            assert!(target.join("private-key.pem").is_file());
        } else {
            predecessor = Some(record.operation_id.clone());
            store
                .add_deployment(
                    &request.name,
                    DeploymentDefinition {
                        name: Some("web".into()),
                        target: DeploymentTarget::Directory {
                            path: target.clone(),
                        },
                        permissions: DeploymentPermissions::default(),
                        reload_command: Vec::new(),
                        timeout_seconds: 30,
                        max_retries: 0,
                    },
                )
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn renewal_failures_retain_ca_deadlines_but_user_cancellation_does_not_count() {
    // Explicit failures take their maximum; poll Retry-After remains the
    // fallback only when neither failure has a CA-provided deadline.
    for (
        cancelled,
        creation_minutes,
        finalize_minutes,
        poll_minutes,
        poll_is_ca,
        expected_minutes,
    ) in [
        (false, None, None, None, false, None),
        (true, None, None, None, false, None),
        (false, None, Some(60), None, false, Some(60)),
        (false, Some(90), Some(60), None, false, Some(90)),
        (false, Some(30), Some(60), None, false, Some(60)),
        (false, Some(30), None, None, false, Some(30)),
        (false, None, None, Some(45), true, Some(45)),
        (false, None, None, Some(45), false, None),
        (false, Some(30), Some(60), Some(90), true, Some(60)),
        (true, None, Some(60), None, false, None),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
        let account = allocation_account();
        let current = renewal_failure_predecessor(&store, temp.path(), &account).await;
        let mut attempt = store.renew(&current.name, &account).await.unwrap();
        let mut record = attempt.record().await.unwrap();
        let observed_at = time::OffsetDateTime::now_utc();
        let deadline = |minutes| observed_at + time::Duration::minutes(minutes);
        let rejection = |minutes| aster_acme::issuance::RequestFailure {
            status: 400,
            problem: None,
            retry_at: Some(deadline(minutes)),
        };
        record.creation_failure = creation_minutes.map(rejection);
        record.finalize_rejection = finalize_minutes.map(rejection);
        record.next_poll_at = poll_minutes.map(deadline);
        record.poll_wait_source = poll_minutes.map(|_| {
            if poll_is_ca {
                aster_acme::issuance::PollWaitSource::RetryAfter
            } else {
                aster_acme::issuance::PollWaitSource::LocalInterval
            }
        });
        attempt.save(&record).await.unwrap();
        let execution = ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now(),
        };
        if cancelled {
            execution.cancellation.cancel();
        }
        let progress = Progress::new(crate::common::session::OutputSession::new(true));
        let error = report_issue_failure(
            attempt.as_mut(),
            &record,
            &progress,
            &execution,
            Box::new(IssueError::Cancelled),
        )
        .await
        .err()
        .unwrap();
        assert!(error.is::<IssueError>());
        drop(attempt);
        let saved = store
            .open_observation(&current.name, &current.operation_id)
            .await
            .unwrap()
            .record()
            .await
            .unwrap();
        assert_eq!(saved.renewal_retry.is_some(), !cancelled);
        if let Some(retry) = saved.renewal_retry {
            assert_eq!(retry.failures, 1);
            assert_eq!(retry.ca_retry_at, expected_minutes.map(deadline));
            if expected_minutes.is_some() {
                let error = store
                    .prepare_renewal(&current.name, &current.operation_id, true, &account)
                    .await
                    .err()
                    .expect("--now must preserve the CA deadline");
                assert!(
                    error.to_string().contains("CA Retry-After has not elapsed"),
                    "{error}"
                );
            }
        }
    }
}

async fn renewal_failure_predecessor(
    store: &CliIssueStore,
    root: &std::path::Path,
    account: &aster_acme::account::AccountRecord,
) -> IssueRecord {
    use rcgen::{CertificateParams, Issuer, KeyPair};
    let request = IssueRequest {
        name: CertificateName::new("deadline").unwrap(),
        identifiers: vec![Identifier::Dns(DnsIdentifier::new("example.com").unwrap())],
        profile: None,
        account_name: "default".into(),
        key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
        challenge: aster_acme::challenge::ChallengeKind::Dns01,
        solver_id: "manual_dns".into(),
        solver_config: serde_json::json!({}),
    };
    let session = store.create(&request, account).await.unwrap();
    let mut current = session.record().await.unwrap();
    let key = zeroize::Zeroizing::new(
        std::fs::read(
            root.join("certs/deadline")
                .join(current.generation_name())
                .join("private-key.pk8"),
        )
        .unwrap(),
    );
    let key = KeyPair::try_from(key.as_slice()).unwrap();
    let issuer = Issuer::new(
        CertificateParams::new(Vec::<String>::new()).unwrap(),
        KeyPair::generate().unwrap(),
    );
    let chain = CertificateParams::new(vec!["example.com".to_owned()])
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap()
        .pem();
    current.phase = aster_acme_core::workflow::IssuancePhase::Completed;
    session.complete(&current, chain.as_bytes()).await.unwrap()
}
fn allocation_account() -> aster_acme::account::AccountRecord {
    serde_json::from_value(serde_json::json!({
            "key_algorithm":"ecdsa-p256","account_id":"test-account","directory_url":"https://ca.example/directory","account_url":"https://ca.example/account",
            "key_thumbprint":"test-key","contacts":[],"server_contacts":null,"last_status":"valid","deactivation":"not_requested",
            "key_rotation":null,"accepted_terms_url":null,"state":"registered"
        })).unwrap()
}

#[tokio::test]
async fn renewal_material_logs_name_before_ca_for_each_batch_item() {
    use aster_acme::issuance::progress::{IssueEvent, IssueObserver};
    let temp = tempfile::tempdir().unwrap();
    let options = AccountArgs {
        data_dir: Some(temp.path().into()),
        ca_directory: Some("https://ca.example/directory".into()),
        ..AccountArgs::default()
    };
    let context = CliSettings::load(&options)
        .await
        .unwrap()
        .account(&options)
        .await
        .unwrap();
    let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
    for json in [false, true] {
        let (output, stdout, stderr) = crate::common::session::tests::session(json);
        let progress = Progress::new(output);
        for suffix in ["first", "second"] {
            let name = format!("cdn.example.com-{suffix}-{json}");
            let request = IssueRequest {
                name: CertificateName::new(&name).unwrap(),
                identifiers: vec![Identifier::Dns(
                    DnsIdentifier::new("cdn.example.com").unwrap(),
                )],
                account_name: "default".into(),
                profile: None,
                key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
                challenge: aster_acme::challenge::ChallengeKind::Dns01,
                solver_id: "manual_dns".into(),
                solver_config: serde_json::json!({}),
            };
            let session = store.create(&request, &allocation_account()).await.unwrap();
            let mut record = session.record().await.unwrap();
            record.renewal_of = Some(aster_acme::issuance::RenewalPredecessor {
                retained_validation: Vec::new(),
                operation_id: "p".repeat(43),
                certificate_id: None,
            });
            report_material(&context, &record, &progress).unwrap();
            progress.observe(&IssueEvent::CertificateSaved { name: record.name });
        }
        assert_eq!(stdout.text(), "");
        let text = stderr.text();
        if json {
            assert_eq!(text, "");
            continue;
        }
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 8);
        for (item, suffix) in ["first", "second"].into_iter().enumerate() {
            let name = format!("cdn.example.com-{suffix}-{json}");
            assert!(lines[item * 4].contains(&format!("Renewing {name} with ecdsa-p256")));
            assert!(
                lines[item * 4 + 1]
                    .contains("Using CA: https://ca.example/directory (account default)")
            );
            assert!(lines[item * 4 + 2].contains("Certificate key:"));
            assert!(
                lines[item * 4 + 3].contains(&format!("Certificate {name} verified and saved"))
            );
        }
    }
}

#[tokio::test]
async fn automatic_allocation_retries_only_name_collisions_while_explicit_names_refuse_reuse() {
    let temp = tempfile::tempdir().unwrap();
    let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
    let account = allocation_account();
    let request = IssueRequest {
        challenge: aster_acme::challenge::ChallengeKind::Dns01,
        solver_id: "manual_dns".into(),
        solver_config: serde_json::Value::Object(serde_json::Map::default()),
        key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
        name: CertificateName::new("example.com-collision").unwrap(),
        identifiers: vec![Identifier::Dns(DnsIdentifier::new("example.com").unwrap())],
        profile: None,
        account_name: "default".into(),
    };
    let initial = store.create(&request, &account).await.unwrap();
    let initial_record = initial.record().await.unwrap();
    drop(initial);
    assert!(matches!(
        allocate_certificate(&store, request.clone(), &account, Naming::Explicit).await,
        Err(IssueError::NameAlreadyExists(_))
    ));
    let generated = allocate_certificate(&store, request, &account, Naming::Automatic)
        .await
        .unwrap();
    let actual = generated.record().await.unwrap();
    assert_ne!(actual.name, initial_record.name);
    assert!(actual.name.as_str().starts_with("example.com-"));
    assert_eq!(actual.name.as_str().len(), "example.com-".len() + 8);
    assert_eq!(store.query(IssueQuery::default()).await.unwrap().len(), 2);
}

#[cfg(unix)]
#[tokio::test]
async fn allocation_propagates_unsafe_storage_errors_without_creating_another_random_name() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
    let account = allocation_account();
    let request = IssueRequest {
        challenge: aster_acme::challenge::ChallengeKind::Dns01,
        solver_id: "manual_dns".into(),
        solver_config: serde_json::Value::Object(serde_json::Map::default()),
        key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
        name: CertificateName::new("example.com-existing").unwrap(),
        identifiers: vec![Identifier::Dns(DnsIdentifier::new("example.com").unwrap())],
        profile: None,
        account_name: "default".into(),
    };
    drop(store.create(&request, &account).await.unwrap());
    let config = temp.path().join("certs/example.com-existing/cert.toml");
    let before = std::fs::read(&config).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        allocate_certificate(&store, request, &account, Naming::Automatic).await,
        Err(IssueError::Store(_))
    ));
    assert_eq!(
        std::fs::read_dir(temp.path().join("certs"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(std::fs::read(config).unwrap(), before);
}
#[tokio::test]
async fn renew_not_due_uses_saved_definition_and_never_contacts_ca_or_creates_a_generation() {
    use rcgen::{CertificateParams, Issuer, KeyPair};
    let temp = tempfile::tempdir().unwrap();
    let ca = aster_acme_protocol::url::AcmeUrl::new("https://127.0.0.1:1/directory").unwrap();
    let accounts = aster_acme_cli_storage::account::CliAccountStore::open(
        temp.path(),
        "default",
        Duration::from_secs(1),
    )
    .unwrap();
    let signer = accounts
        .signer(
            &ca,
            "default",
            aster_acme::storage::account::KeyAccess::Create(None),
        )
        .await
        .unwrap();
    let thumb = signer.jwk().unwrap().thumbprint().unwrap();
    let mut account = accounts.load(&ca, &thumb).await.unwrap().unwrap();
    account.state = aster_acme_core::account::AccountRecordState::Registered;
    account.last_status = Some(aster_acme_core::protocol::AccountStatus::Valid);
    account.account_url =
        Some(aster_acme_protocol::url::AcmeUrl::new("https://127.0.0.1:1/account").unwrap());
    accounts.save(&account).await.unwrap();
    let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
    let request = IssueRequest {
        challenge: aster_acme::challenge::ChallengeKind::Dns01,
        solver_id: "manual_dns".into(),
        solver_config: serde_json::Value::Object(serde_json::Map::default()),
        name: CertificateName::new("web").unwrap(),
        identifiers: vec![Identifier::Dns(DnsIdentifier::new("example.com").unwrap())],
        profile: None,
        key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP384,
        account_name: "default".into(),
    };
    let session = store.create(&request, &account).await.unwrap();
    let mut record = session.record().await.unwrap();
    let generation = temp.path().join("certs/web").join(record.generation_name());
    let key_bytes = std::fs::read(generation.join("private-key.pk8")).unwrap();
    let key = KeyPair::try_from(key_bytes.as_slice()).unwrap();
    let issuer = Issuer::new(
        CertificateParams::new(Vec::<String>::new()).unwrap(),
        KeyPair::generate().unwrap(),
    );
    let mut params = CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(89);
    record.phase = aster_acme_core::workflow::IssuancePhase::Completed;
    let chain = params.signed_by(&key, &issuer).unwrap().pem();
    session.complete(&record, chain.as_bytes()).await.unwrap();
    drop(session);
    let journal = std::fs::read(generation.join("operation.toml")).unwrap();
    let definition = std::fs::read(temp.path().join("certs/web/cert.toml")).unwrap();
    let args = crate::commands::cert::args::RenewArgs {
        target: crate::commands::cert::args::CertificateNameArgs {
            name: Some("web".into()),
            named_name: None,
        },
        now: false,
        all: false,
        run: crate::commands::cert::args::RunArgs {
            max_polls: Some(30),
            poll_interval: None,
            yes: false,

            operation_timeout: Some(2),
            http: HttpArgs::default(),
            local: LocalArgs {
                data_dir: Some(temp.path().into()),
                json: true,
            },
        },
    };
    crate::commands::cert::renewal::execute(
        args,
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .unwrap();
    assert_eq!(store.query(IssueQuery::default()).await.unwrap().len(), 1);
    assert_eq!(
        std::fs::read(generation.join("operation.toml")).unwrap(),
        journal
    );
    assert_eq!(
        std::fs::read(temp.path().join("certs/web/cert.toml")).unwrap(),
        definition
    );
    assert_eq!(
        std::fs::read(generation.join("private-key.pk8")).unwrap(),
        key_bytes
    );
}

mod entrypoints;
