//! Account query pushdown and metadata-only behavior.
use crate::{account::CliAccountStore, inventory::query_accounts};
use aster_acme::storage::{
    account::{AccountKeyStore, AccountStore, KeyAccess},
    query::AccountQuery,
};
use aster_acme_core::{account::AccountRecordState, protocol::AccountStatus};
use aster_acme_protocol::url::AcmeUrl;
use std::time::Duration;

#[tokio::test]
async fn account_queries_filter_before_return_and_name_lookup_ignores_unrelated_corruption() {
    let (temp, ca) = seed().await;
    assert_eq!(
        query_accounts(temp.path().into(), AccountQuery::default())
            .await
            .unwrap()
            .len(),
        2
    );
    let active = query_accounts(
        temp.path().into(),
        AccountQuery {
            usable: Some(true),
            directory: Some(ca.clone()),
            ..AccountQuery::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].name, "active");
    assert_eq!(
        query_accounts(
            temp.path().into(),
            AccountQuery {
                state: Some(AccountRecordState::RegistrationPending),
                usable: Some(true),
                ..AccountQuery::default()
            }
        )
        .await
        .unwrap()
        .len(),
        0
    );
    std::fs::write(temp.path().join("accounts/pending/account.toml"), "corrupt").unwrap();
    assert_eq!(
        query_accounts(
            temp.path().into(),
            AccountQuery {
                name: Some("active".into()),
                ..AccountQuery::default()
            }
        )
        .await
        .unwrap()
        .len(),
        1
    );
    assert!(
        query_accounts(temp.path().into(), AccountQuery::default())
            .await
            .is_err()
    );
    assert_eq!(
        query_accounts(
            temp.path().into(),
            AccountQuery {
                name: Some("missing".into()),
                ..AccountQuery::default()
            }
        )
        .await
        .unwrap()
        .len(),
        0
    );
    assert!(
        query_accounts(
            temp.path().into(),
            AccountQuery {
                name: Some("../escape".into()),
                ..AccountQuery::default()
            }
        )
        .await
        .is_err()
    );
}

async fn seed() -> (tempfile::TempDir, AcmeUrl) {
    let temp = tempfile::tempdir().unwrap();
    let ca = AcmeUrl::new("https://ca.example/directory").unwrap();
    for name in ["active", "pending"] {
        let store = CliAccountStore::open(temp.path(), name, Duration::from_secs(1)).unwrap();
        let signer = store
            .signer(&ca, name, KeyAccess::Create(None))
            .await
            .unwrap();
        let thumb = signer.jwk().unwrap().thumbprint().unwrap();
        let mut record = store.load(&ca, &thumb).await.unwrap().unwrap();
        if name == "active" {
            record.state = AccountRecordState::Registered;
            record.last_status = Some(AccountStatus::Valid);
            record.account_url = Some(AcmeUrl::new("https://ca.example/account/1").unwrap());
            store.save(&record).await.unwrap();
        }
        drop(signer);
        std::fs::remove_file(
            temp.path()
                .join("accounts")
                .join(name)
                .join("account-key.pk8"),
        )
        .unwrap();
    }
    (temp, ca)
}

#[tokio::test]
async fn operation_filter_keeps_reconcilable_rotation_but_excludes_other_mutations() {
    use aster_acme_core::account::{AccountOperation, KeyRotation, KeyRotationPhase};
    let (temp, ca) = seed().await;
    let path = temp.path().join("accounts/active/account.toml");
    let mut record = crate::account::read_record(&path).unwrap().unwrap();
    record.key_rotation = Some(KeyRotation {
        new_thumbprint: "n".repeat(43),
        phase: KeyRotationPhase::Pending,
    });
    let store = CliAccountStore::open(temp.path(), "active", Duration::from_secs(1)).unwrap();
    store.save(&record).await.unwrap();
    for (operation, expected) in [
        (AccountOperation::RotateKey, 1),
        (AccountOperation::Update, 0),
        (AccountOperation::Deactivate, 0),
    ] {
        let result = query_accounts(
            temp.path().into(),
            AccountQuery {
                directory: Some(ca.clone()),
                operation: Some(operation),
                ..AccountQuery::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(result.len(), expected);
    }
}
