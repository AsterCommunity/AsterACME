//! Local revocation preparation owns confirmation, credentials and the execution leases.
use crate::{
    commands::cert::{args::RevokeArgs, execute::options},
    common::{
        context::{CliContext, CliSettings, CommandContext, http_options},
        error::CliResult,
        terminal,
    },
};
use aster_acme::{
    account::AccountRecord,
    issuance::{IssueError, IssueRecord},
    revocation::{RevocationSigningMethod, authority::RevocationAuthority},
    solver::ExecutionContext,
    storage::{
        account::{AccountKeyStore, AccountLease, AccountStore, KeyAccess},
        revocation::RevocationSession,
    },
    transport::{AcmeClient, TransportOptions},
};
use aster_acme_cli_storage::issuance::{CliIssueStore, revocation::ManagedRevocationSession};
use aster_acme_core::revocation::RevocationState;
use std::sync::Arc;

struct IssuingAccount {
    context: CliContext,
    record: Arc<AccountRecord>,
    signer: Arc<dyn aster_acme::crypto::JwsSigner>,
    _lease: Arc<dyn AccountLease>,
}

pub(super) enum Prepared {
    Confirmed(Box<IssueRecord>),
    Submit(Box<PreparedRevocation>),
}

/// Owns the key and leases across discovery and the submission checkpoint.
pub(super) struct PreparedRevocation {
    pub(super) session: ManagedRevocationSession,
    pub(super) transport: TransportOptions,
    pub(super) directory: aster_acme_protocol::url::AcmeUrl,
    authority: RevocationAuthority,
    _account: Option<IssuingAccount>,
    reason: Option<aster_acme_protocol::revocation::RevocationReason>,
}

impl PreparedRevocation {
    pub(super) async fn submit(
        mut self: Box<Self>,
        client: Arc<AcmeClient>,
        execution: &ExecutionContext,
    ) -> CliResult<IssueRecord> {
        aster_acme::revocation::RevocationService::new(client, self.authority)
            .revoke(&mut self.session, self.reason, execution)
            .await?;
        Ok(self.session.certificate_record().await?)
    }
}

pub(super) async fn prepare(
    store: &CliIssueStore,
    settings: &CliSettings,
    selected: &IssueRecord,
    args: &RevokeArgs,
    cli: &CommandContext,
    execution: &ExecutionContext,
) -> CliResult<Prepared> {
    execution
        .check()
        .map_err(|_| IssueError::RevocationInterrupted)?;
    // Account -> certificate for account mode. Certificate-key mode never accesses accounts.
    let account = match args.sign_with {
        RevocationSigningMethod::Account => Some(load_account(settings, selected, args).await?),
        RevocationSigningMethod::CertificateKey => None,
    };
    let session = store
        .open_revocation(&selected.name, &selected.operation_id)
        .await?;
    let record = session.certificate_record().await?;
    let target = session.target().await?;
    let (fingerprint, reason) = record.revocation.check_request(&target, args.reason)?;
    if record.revocation.state == RevocationState::Confirmed {
        return Ok(Prepared::Confirmed(Box::new(record)));
    }
    let (authority, transport) = match account.as_ref() {
        Some(account) => (
            RevocationAuthority::Account {
                account: account.record.clone(),
                signer: account.signer.clone(),
            },
            account
                .context
                .transport_options(&options(&args.local, &args.http, None))?,
        ),
        None => (
            RevocationAuthority::CertificateKey {
                signer: session.certificate_signer().await?,
            },
            http_options(&settings.config, &args.http, None)?,
        ),
    };
    let signing_method = authority.authorize(&target)?.observation.method();
    terminal::confirm_action(
        &format!(
            "Permanently revoke certificate\n  Name: {}\n  Request: {}\n  Domains: {}\n  CA: {}\n  Reason: {}\n  Sign with: {}\n  Certificate SHA-256: {}\n\nThis cannot be undone. Local certificate files will be retained.\nA deployed copy must be replaced separately.",
            record.name.as_str(),
            record.operation_id,
            record
                .identifiers
                .iter()
                .map(aster_acme::identifier::DnsIdentifier::value)
                .collect::<Vec<_>>()
                .join(", "),
            target.directory.as_str(),
            reason.map_or_else(|| "not specified".into(), |reason| reason.to_string()),
            signing_method.name(),
            fingerprint
        ),
        "Revoke this certificate?",
        args.yes,
        &cli.output,
    )?;
    execution
        .check()
        .map_err(|_| IssueError::RevocationInterrupted)?;
    Ok(Prepared::Submit(Box::new(PreparedRevocation {
        session,
        authority,
        transport,
        directory: target.directory,
        _account: account,
        reason,
    })))
}

async fn load_account(
    settings: &CliSettings,
    selected: &IssueRecord,
    args: &RevokeArgs,
) -> CliResult<IssuingAccount> {
    let context = settings
        .clone()
        .account(&options(
            &args.local,
            &args.http,
            Some(selected.account_name.clone()),
        ))
        .await?;
    context.require_account().await?;
    let signer = context
        .store
        .signer(&context.directory, &context.name, KeyAccess::Existing)
        .await?;
    let thumbprint = signer.jwk()?.thumbprint()?;
    let lease = context
        .store
        .lock_account(&context.directory, &thumbprint)
        .await?;
    let record = context
        .store
        .load(&context.directory, &thumbprint)
        .await?
        .ok_or("Account metadata missing.")?;
    if record.account_id != selected.account_id
        || record.account_url.as_ref() != Some(&selected.account_url)
        || record.directory_url != selected.directory
    {
        return Err("Revocation account does not match the selected certificate.".into());
    }
    Ok(IssuingAccount {
        context,
        record: Arc::new(record),
        signer,
        _lease: lease,
    })
}
