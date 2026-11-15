//! Parsed command entrypoints retain exact identities before a rejected transport.
use crate::commands::cert::execute;
use crate::commands::cert::report::CertificateReport;
use crate::common::context::CommandContext;
use aster_acme::storage::account::{AccountKeyStore, AccountStore, KeyAccess};
use aster_acme::storage::issuance::IssueStore;
use aster_acme::storage::query::IssueQuery;
use aster_acme_cli_storage::{account::CliAccountStore, issuance::CliIssueStore};
use clap::Parser;
use std::{path::Path, time::Duration};

fn command(root: &Path, args: &[&str]) -> crate::commands::cert::args::CertCommand {
    let mut words = vec!["aster-acme".to_owned(), "cert".into()];
    words.extend(args.iter().map(|arg| (*arg).to_owned()));
    words.extend([
        "--data-dir".into(),
        root.display().to_string(),
        "--json".into(),
    ]);
    let crate::app::Command::Cert { command } = crate::app::Args::parse_from(words).command else {
        panic!("expected certificate command");
    };
    command
}

async fn seed_account(root: &Path) {
    let store = CliAccountStore::open(root, "default", Duration::from_secs(1)).unwrap();
    // Production CLI rejects plain HTTP before contacting this loopback address.
    let directory = aster_acme_protocol::url::AcmeUrl::new("http://127.0.0.1:1/directory").unwrap();
    let signer = store
        .signer(&directory, "default", KeyAccess::Create(None))
        .await
        .unwrap();
    let thumbprint = signer.jwk().unwrap().thumbprint().unwrap();
    let mut record = store.load(&directory, &thumbprint).await.unwrap().unwrap();
    record.state = aster_acme_core::account::AccountRecordState::Registered;
    record.last_status = Some(aster_acme_core::protocol::AccountStatus::Valid);
    record.account_url =
        Some(aster_acme_protocol::url::AcmeUrl::new("http://127.0.0.1:1/account").unwrap());
    store.save(&record).await.unwrap();
}

#[tokio::test]
async fn issue_resume_and_show_entrypoints_preserve_fixed_material_on_transport_rejection() {
    let temp = tempfile::tempdir().unwrap();
    seed_account(temp.path()).await;
    let cli = CommandContext::new(true);
    let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
    assert!(
        execute::execute(
            command(
                temp.path(),
                &[
                    "issue",
                    "-n",
                    "web",
                    "-d",
                    "example.com",
                    "-c",
                    "manual_http"
                ]
            ),
            &cli
        )
        .await
        .is_err()
    );
    let record = store
        .query(IssueQuery::default())
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(record.name.as_str(), "web");
    assert!(!record.new_order_intent_saved);
    let generation = temp.path().join("certs/web").join(record.generation_name());
    let before = ["private-key.pk8", "request.der", "operation.toml"]
        .map(|file| std::fs::read(generation.join(file)).unwrap());
    assert!(
        execute::execute(
            command(
                temp.path(),
                &[
                    "issue",
                    "--resume",
                    "web",
                    "--operation",
                    &record.operation_id
                ]
            ),
            &cli
        )
        .await
        .is_err()
    );
    assert_eq!(store.query(IssueQuery::default()).await.unwrap().len(), 1);
    for (file, bytes) in ["private-key.pk8", "request.der", "operation.toml"]
        .into_iter()
        .zip(before)
    {
        assert_eq!(std::fs::read(generation.join(file)).unwrap(), bytes);
    }
    for extra in [
        vec!["show", "web"],
        vec!["show", "web", "--history"],
        vec!["show", "web", "--operation", &record.operation_id],
    ] {
        let CertificateReport::Show {
            record: shown,
            verified,
            ..
        } = execute::execute(command(temp.path(), &extra), &cli)
            .await
            .unwrap()
        else {
            panic!("expected show");
        };
        assert_eq!(shown.operation_id, record.operation_id);
        assert!(!verified);
    }
    assert!(
        execute::execute(command(temp.path(), &["show", "web", "--verify"]), &cli)
            .await
            .is_err()
    );
    for extra in [vec!["list"], vec!["list", "-n", "web", "--history"]] {
        let CertificateReport::List(records) = execute::execute(command(temp.path(), &extra), &cli)
            .await
            .unwrap()
        else {
            panic!("expected list");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].operation_id, record.operation_id);
    }
    assert!(
        execute::execute(
            command(temp.path(), &["issue", "--resume", "missing"]),
            &cli
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn automatic_issue_names_and_similar_recovery_do_not_allocate_duplicate_generations() {
    let temp = tempfile::tempdir().unwrap();
    seed_account(temp.path()).await;
    let cli = CommandContext::new(true);
    let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
    for extra in [vec![], vec!["--if-similar-order"], vec![]] {
        let mut args = vec!["issue", "-d", "example.com", "-c", "manual_http"];
        args.extend(extra);
        assert!(
            execute::execute(command(temp.path(), &args), &cli)
                .await
                .is_err()
        );
        let records = store.query(IssueQuery::default()).await.unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].name.as_str().starts_with("example.com-"));
    }
    let record = store
        .query(IssueQuery::default())
        .await
        .unwrap()
        .pop()
        .unwrap();
    // Terminal records stay inspectable but cannot be selected for resume.
    let session = store
        .open(&record.name, &record.operation_id)
        .await
        .unwrap();
    let mut rejected = session.record().await.unwrap();
    rejected.creation_failure = Some(aster_acme::issuance::RequestFailure {
        status: 400,
        problem: None,
        retry_at: None,
    });
    session.save(&rejected).await.unwrap();
    drop(session);
    assert!(
        execute::execute(
            command(
                temp.path(),
                &[
                    "issue",
                    "--resume",
                    record.name.as_str(),
                    "--operation",
                    &record.operation_id
                ]
            ),
            &cli
        )
        .await
        .is_err()
    );
}
