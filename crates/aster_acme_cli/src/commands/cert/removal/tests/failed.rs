//! CLI confirmation and offline failed cleanup exercise actual storage effects.
use crate::commands::cert::{
    args::{CertificateNameArgs, SavedTargetArgs},
    removal::{RemovalFilter, execute},
    report::CertificateReport,
};
use crate::common::{args::LocalArgs, context::CommandContext};
use aster_acme::{
    issuance::{CertificateName, IssueRequest, RequestFailure},
    storage::{
        account::{AccountKeyStore, KeyAccess},
        issuance::IssueStore,
        query::IssueQuery,
    },
};
use aster_acme_cli_storage::{account::CliAccountStore, issuance::CliIssueStore};
use aster_acme_protocol::url::AcmeUrl;
use std::time::Duration;

#[tokio::test]
async fn failed_cli_requires_confirmation_then_deletes_only_evidenced_failure_offline() {
    let temp = tempfile::tempdir().unwrap();
    let directory = AcmeUrl::new("https://127.0.0.1:1/directory").unwrap();
    let accounts = CliAccountStore::open(temp.path(), "default", Duration::from_secs(1)).unwrap();
    accounts
        .signer(&directory, "default", KeyAccess::Create(None))
        .await
        .unwrap();
    let mut account = accounts.metadata().await.unwrap().unwrap();
    account.state = aster_acme_core::account::AccountRecordState::Registered;
    account.last_status = Some(aster_acme_core::protocol::AccountStatus::Valid);
    account.account_url = Some(AcmeUrl::new("https://127.0.0.1:1/account/1").unwrap());
    let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
    let session = store
        .create(
            &IssueRequest {
                name: CertificateName::new("failed.example.com").unwrap(),
                identifiers: vec![
                    aster_acme::identifier::DnsIdentifier::new("example.com").unwrap(),
                ],
                account_name: "default".into(),
                key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
                challenge: aster_acme::challenge::ChallengeKind::Dns01,
                solver_id: "manual_dns".into(),
                solver_config: serde_json::json!({}),
            },
            &account,
        )
        .await
        .unwrap();
    let mut saved = session.record().await.unwrap();
    saved.new_order_intent_saved = true;
    saved.creation_failure = Some(RequestFailure {
        status: 400,
        problem: None,
        retry_at: None,
    });
    session.save(&saved).await.unwrap();
    drop(session);
    let target = || SavedTargetArgs {
        identity: CertificateNameArgs {
            name: Some(saved.name.as_str().into()),
            named_name: None,
        },
        operation: None,
    };
    let local = || LocalArgs {
        data_dir: Some(temp.path().into()),
        json: true,
    };
    assert!(
        execute(
            target(),
            RemovalFilter::Failed,
            false,
            local(),
            &CommandContext::new(true)
        )
        .await
        .is_err()
    );
    assert_eq!(store.query(IssueQuery::default()).await.unwrap().len(), 1);
    let report = execute(
        target(),
        RemovalFilter::Failed,
        true,
        local(),
        &CommandContext::new(true),
    )
    .await
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(
        &crate::commands::cert::render::render(
            &report,
            crate::common::session::Format::plain(true),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(json["scope"], "failed");
    assert_eq!(json["generations"], 1);
    assert_eq!(json["ca_request_performed"], false);
    assert!(matches!(
        report,
        CertificateReport::Removed {
            in_use_removed: false,
            ..
        }
    ));
    assert_eq!(store.query(IssueQuery::default()).await.unwrap().len(), 0);
}
