//! Local-only certificate removal: resolve a name, validate under lease, confirm and delete.
use super::{args::SavedTargetArgs, selection};
use crate::{
    commands::account::args::AccountArgs,
    common::{args::LocalArgs, context::CliSettings, error::CliResult, terminal},
};
use aster_acme::issuance::IssueStore;
use aster_acme_cli_storage::issuance::{
    CliIssueStore,
    removal::{CertificateRemoval, RemovalScope},
};
use std::time::Duration;

/// CLI selection mode; an exact request is resolved before acquiring its deletion lease.
pub(super) enum RemovalFilter {
    Request,
    History,
    Revoked,
    All,
}

pub(super) async fn execute(
    target: SavedTargetArgs,
    filter: RemovalFilter,
    yes: bool,
    local: LocalArgs,
    cli: &crate::common::context::CommandContext,
) -> CliResult<super::report::CertificateReport> {
    let settings = CliSettings::load(&AccountArgs {
        data_dir: local.data_dir.clone(),
        json: local.json,
        ..AccountArgs::default()
    })
    .await?;
    let store = CliIssueStore::new(settings.data_dir, Duration::from_secs(5));
    let records = store.list().await?;
    let name = selection::certificate_name(
        &records,
        target
            .identity
            .name
            .as_deref()
            .or(target.identity.named_name.as_deref()),
        target.operation.as_deref(),
        &cli.output,
    )?;
    let scope = match filter {
        RemovalFilter::All => RemovalScope::All,
        RemovalFilter::History => RemovalScope::History,
        RemovalFilter::Revoked => RemovalScope::Revoked,
        RemovalFilter::Request => RemovalScope::Operation(
            selection::choose(
                records,
                &name,
                target.operation.as_deref(),
                selection::RequestSelection::Any,
                &cli.output,
            )?
            .operation_id,
        ),
    };
    let removal = store.prepare_removal(&name, scope.clone()).await?;
    let ids = removal
        .records()
        .iter()
        .map(|record| record.operation_id.clone())
        .collect::<Vec<_>>();
    let in_use_removed = removal.removes_in_use();
    if !ids.is_empty() || matches!(scope, RemovalScope::All) {
        terminal::confirm_action(
            &confirmation_details(&removal),
            "Remove this local material?",
            yes,
            &cli.output,
        )?;
    }
    removal.remove().await?;
    Ok(super::report::CertificateReport::Removed {
        name: name.as_str().into(),
        scope,
        ids,
        in_use_removed,
    })
}

fn confirmation_details(removal: &CertificateRemoval) -> String {
    use crate::common::time::timestamp;
    let (heading, scope) = match removal.scope() {
        RemovalScope::Revoked => (
            "Remove locally confirmed revoked certificates",
            "Only versions with a saved CA revocation confirmation will be deleted. Unconfirmed requests are retained.",
        ),
        RemovalScope::Operation(_) => (
            "Remove local certificate request",
            "Only the selected request and its artifacts will be deleted.",
        ),
        RemovalScope::History => (
            "Remove historical certificate versions",
            "Only issued non-selected versions will be deleted. InUse and unfinished requests are retained.",
        ),
        RemovalScope::All => (
            "Remove all local certificate requests",
            "All requests, issued versions and private keys under this name will be deleted.",
        ),
    };
    let mut lines = vec![
        heading.to_owned(),
        format!("  Name: {}", removal.name().as_str()),
        format!("  Requests: {}", removal.generations()),
        format!("  Directory: {}", removal.directory().display()),
    ];
    if let RemovalScope::Operation(_) = removal.scope() {
        for record in removal.records() {
            lines.push(format!("  Request: {}", record.operation_id));
            lines.push(format!(
                "  Requested: {}",
                timestamp(Some(record.created_at))
            ));
            lines.push(format!(
                "  Domains: {}",
                record
                    .identifiers
                    .iter()
                    .map(aster_acme::identifier::DnsIdentifier::value)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    lines.extend([String::new(), scope.into()]);
    if removal.removes_in_use() {
        lines.push("In-use selection will be cleared; no old version will be selected automatically. Deployments using the in_use certificate paths will lose access to these files.".into());
    }
    lines.extend([
        "This does not revoke certificates at the CA or remove deployed copies or DNS records."
            .into(),
        "Without a backup, deleted private keys cannot be recovered.".into(),
        "Files not managed by AsterACME will be kept.".into(),
    ]);
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_acme::{
        account::{AccountKeyStore, AccountStore},
        issuance::{CertificateName, IssueRequest},
    };
    use aster_acme_cli_storage::CliAccountStore;
    use aster_acme_core::{account::AccountRecordState, protocol::AccountStatus};
    use aster_acme_protocol::url::AcmeUrl;

    #[tokio::test]
    async fn local_removal_requires_confirmation_preserves_cancelled_files_and_needs_no_account() {
        let temp = tempfile::tempdir().unwrap();
        let directory = AcmeUrl::new("https://127.0.0.1:1/directory").unwrap();
        let accounts =
            CliAccountStore::open(temp.path(), "default", Duration::from_secs(1)).unwrap();
        let signer = accounts.signer(&directory, "default", true).await.unwrap();
        let thumb = signer.jwk().unwrap().thumbprint().unwrap();
        let mut account = accounts.load(&directory, &thumb).await.unwrap().unwrap();
        account.state = AccountRecordState::Registered;
        account.last_status = Some(AccountStatus::Valid);
        account.account_url = Some(AcmeUrl::new("https://127.0.0.1:1/account").unwrap());
        let store = CliIssueStore::new(temp.path().into(), Duration::from_secs(1));
        let name = CertificateName::new("example.com").unwrap();
        let session = store
            .create(
                &IssueRequest {
                    key_algorithm:
                        aster_acme::issuance::key_algorithm::CertificateKeyAlgorithm::EcdsaP256,
                    name: name.clone(),
                    identifiers: vec![
                        aster_acme::identifier::DnsIdentifier::new("example.com").unwrap(),
                    ],
                    account_name: "default".into(),
                },
                &account,
            )
            .await
            .unwrap();
        let record = session.record().await.unwrap();
        let key = temp
            .path()
            .join("certs/example.com")
            .join(record.generation_name())
            .join("private-key.pk8");
        let before = std::fs::read(&key).unwrap();
        drop(session);
        // Local certificate removal must also work after its account was removed.
        accounts.remove().await.unwrap();
        let target = || SavedTargetArgs {
            identity: super::super::args::CertificateNameArgs {
                name: Some("example.com".into()),
                named_name: None,
            },
            operation: None,
        };
        let local = || LocalArgs {
            data_dir: Some(temp.path().into()),
            json: true,
        };
        let error = execute(
            target(),
            RemovalFilter::Request,
            false,
            local(),
            &crate::common::context::CommandContext::new(true),
        )
        .await
        .err()
        .unwrap();
        assert!(error.to_string().contains("use --yes"));
        assert_eq!(std::fs::read(&key).unwrap(), before);
        assert_eq!(store.list().await.unwrap().len(), 1);
        execute(
            target(),
            RemovalFilter::Request,
            true,
            local(),
            &crate::common::context::CommandContext::new(true),
        )
        .await
        .unwrap();
        assert!(!key.exists());
        assert_eq!(store.list().await.unwrap().len(), 0);
        assert!(
            execute(
                target(),
                RemovalFilter::Request,
                true,
                local(),
                &crate::common::context::CommandContext::new(true)
            )
            .await
            .is_err()
        );
        assert!(!temp.path().join("accounts/default/account.toml").exists());
    }
}
