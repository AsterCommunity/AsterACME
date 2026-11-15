//! Account registration operations.

use crate::account::{
    AccountError, AccountRecord, AccountService, AccountTimes, AcmeAccount, RegistrationOptions,
    validate_contacts,
};
use crate::storage::account::AccountLease;
use crate::{crypto::JwsSigner, transport::json_payload};
use aster_acme_core::account::{AccountAction, AccountOperation, AccountRecordState};
use aster_acme_protocol::url::AcmeUrl;
use aster_acme_protocol::{
    account::{AccountObject, FindAccountRequest, NewAccountRequest},
    problem::ProblemKind,
};
use std::sync::Arc;

impl AccountService {
    /// Register an account, reuse a registered identity, or recover a pending registration.
    ///
    /// A pending intent always first uses `onlyReturnExisting=true` and the same supplied
    /// signer. If the account does not exist, registration resumes with the pending intent.
    /// The account record is persisted before the first `newAccount` request. A timeout may
    /// leave the server mutation uncertain; this method deliberately keeps that intent.
    ///
    /// # Errors
    /// Reports invalid contacts, consent/EAB requirements, storage, crypto, or ACME failures.
    pub async fn register_or_recover(
        &self,
        signer: &dyn JwsSigner,
        options: RegistrationOptions,
    ) -> Result<AcmeAccount, AccountError> {
        let directory = self.client.directory_url().clone();
        let jwk = signer.jwk()?;
        let thumbprint = jwk.thumbprint()?;
        let lease = self.store.lock_account(&directory, &thumbprint).await?;
        let mut record = self
            .load_or_prepare(
                &directory,
                &thumbprint,
                &options,
                signer.algorithm(),
                &lease,
            )
            .await?;
        match record
            .action(AccountOperation::Register)
            .map_err(AccountError::from)?
        {
            AccountAction::Inspect => {
                let account_url = record
                    .account_url
                    .clone()
                    .ok_or(AccountError::InvalidResponse)?;
                let response = self
                    .client
                    .signed(&account_url, signer, Some(&account_url), b"")
                    .await?;
                if response.status != reqwest::StatusCode::OK {
                    return Err(AccountError::InvalidResponse);
                }
                let account: AccountObject = serde_json::from_slice(&response.body)
                    .map_err(|_| AccountError::InvalidResponse)?;
                record.observe(&account, self.clock.now());
                self.store.save(&record, &lease).await?;
                return Ok(AcmeAccount {
                    key_algorithm: signer.algorithm(),
                    times: record.times,
                    account_id: record.account_id,
                    directory_url: directory,
                    account_url,
                    status: account.status,
                    contacts: account.contact.unwrap_or_default(),
                    recovered: false,
                });
            }
            AccountAction::LookupExisting => {}
            AccountAction::SendDeactivation
            | AccountAction::AlreadyDeactivated
            | AccountAction::Select
            | AccountAction::Update
            | AccountAction::SendKeyChange
            | AccountAction::ReconcileKeyChange
            | AccountAction::FinalizeKeyChange => return Err(AccountError::InvalidResponse),
        }

        let mut recovered = false;
        let response = match self.new_account(signer, &record, &options, true).await {
            Ok(response) => {
                recovered = true;
                response
            }
            Err(AccountError::Transport(error))
                if error.is_problem(&ProblemKind::AccountDoesNotExist) =>
            {
                self.new_account(signer, &record, &options, false).await?
            }
            Err(error) => return Err(error),
        };
        let account_url = self.client.account_location(&response)?;
        if !matches!(
            response.status,
            reqwest::StatusCode::OK | reqwest::StatusCode::CREATED
        ) {
            return Err(AccountError::InvalidResponse);
        }
        let account: AccountObject =
            serde_json::from_slice(&response.body).map_err(|_| AccountError::InvalidResponse)?;
        record.account_url = Some(account_url.clone());
        record.observe(&account, self.clock.now());
        record.state = AccountRecordState::Registered;
        self.store.save(&record, &lease).await?;
        Ok(AcmeAccount {
            key_algorithm: signer.algorithm(),
            times: record.times,
            account_id: record.account_id,
            directory_url: directory,
            account_url,
            status: account.status,
            contacts: account.contact.unwrap_or_default(),
            recovered,
        })
    }

    /// Look up an existing account by key without ever creating one, then persist its identity.
    ///
    /// # Errors
    /// Missing remote account, unavailable storage or invalid server responses are errors.
    pub async fn recover(&self, signer: &dyn JwsSigner) -> Result<AcmeAccount, AccountError> {
        let directory = self.client.directory_url().clone();
        let thumbprint = signer.jwk()?.thumbprint()?;
        let lease = self.store.lock_account(&directory, &thumbprint).await?;
        let previous = self.store.load(&directory, &thumbprint).await?;
        let mut record = previous.unwrap_or_else(|| AccountRecord {
            key_algorithm: signer.algorithm(),
            user_agent: None,
            times: AccountTimes::default(),
            account_id: AccountRecord::stable_id(&directory, &thumbprint),
            directory_url: directory.clone(),
            key_thumbprint: thumbprint.clone(),
            account_url: None,
            contacts: Vec::new(),
            server_contacts: None,
            last_status: None,
            deactivation: crate::account::DeactivationState::NotRequested,
            key_rotation: None,
            accepted_terms_url: None,
            state: AccountRecordState::RegistrationPending,
        });
        record
            .action(AccountOperation::Inspect)
            .map_err(AccountError::from)?;
        if record.directory_url != directory
            || record.key_thumbprint != thumbprint
            || record.key_algorithm != signer.algorithm()
        {
            return Err(AccountError::IdentityMismatch);
        }
        let response = self
            .new_account(signer, &record, &RegistrationOptions::default(), true)
            .await?;
        if response.status != reqwest::StatusCode::OK {
            return Err(AccountError::InvalidResponse);
        }
        let account_url = self.client.account_location(&response)?;
        let account: AccountObject =
            serde_json::from_slice(&response.body).map_err(|_| AccountError::InvalidResponse)?;
        record.account_url = Some(account_url.clone());
        record.observe(&account, self.clock.now());
        record.state = AccountRecordState::Registered;
        self.store.save(&record, &lease).await?;
        Ok(AcmeAccount {
            key_algorithm: signer.algorithm(),
            times: record.times,
            account_id: record.account_id,
            directory_url: directory,
            account_url,
            status: account.status,
            contacts: account.contact.unwrap_or_default(),
            recovered: true,
        })
    }

    pub(super) async fn load_or_prepare(
        &self,
        directory: &AcmeUrl,
        thumbprint: &str,
        options: &RegistrationOptions,
        key_algorithm: crate::crypto::key_algorithm::KeyAlgorithm,
        lease: &Arc<dyn AccountLease>,
    ) -> Result<AccountRecord, AccountError> {
        if let Some(mut record) = self.store.load(directory, thumbprint).await? {
            if &record.directory_url != directory
                || record.key_thumbprint != thumbprint
                || record.key_algorithm != key_algorithm
            {
                return Err(AccountError::IdentityMismatch);
            }
            record
                .action(AccountOperation::Register)
                .map_err(AccountError::from)?;
            validate_contacts(&options.contacts)?;
            let accepted_terms = match &self.client.directory().meta.terms_of_service {
                // Consent is recorded as the discovered URL, not a reusable boolean:
                // a changed document requires another explicit acceptance by the caller.
                Some(current) if record.accepted_terms_url.as_ref() == Some(current) => {
                    Some(current.clone())
                }
                Some(current) if options.terms_accepted => Some(current.clone()),
                Some(current) => return Err(AccountError::TermsRequired(current.clone())),
                None => None,
            };
            let mut changed = false;
            if !options.contacts.is_empty() && record.contacts != options.contacts {
                record.contacts.clone_from(&options.contacts);
                changed = true;
            }
            if let Some(accepted_terms) = accepted_terms
                && record.accepted_terms_url.as_ref() != Some(&accepted_terms)
            {
                record.accepted_terms_url = Some(accepted_terms);
                changed = true;
            }
            if changed {
                self.store.save(&record, lease).await?;
            }
            return Ok(record);
        }
        validate_contacts(&options.contacts)?;
        match &self.client.directory().meta.terms_of_service {
            Some(required) if !options.terms_accepted => {
                return Err(AccountError::TermsRequired(required.clone()));
            }
            Some(_) | None => {}
        }
        if self.client.directory().meta.external_account_required
            && options.external_account.is_none()
        {
            return Err(AccountError::ExternalAccountRequired);
        }
        let record = AccountRecord {
            key_algorithm,
            user_agent: None,
            times: AccountTimes::default(),
            account_id: AccountRecord::stable_id(directory, thumbprint),
            directory_url: directory.clone(),
            key_thumbprint: thumbprint.to_owned(),
            account_url: None,
            contacts: options.contacts.clone(),
            server_contacts: None,
            last_status: None,
            deactivation: crate::account::DeactivationState::NotRequested,
            key_rotation: None,
            accepted_terms_url: self.client.directory().meta.terms_of_service.clone(),
            state: AccountRecordState::RegistrationPending,
        };
        self.store.save(&record, lease).await?;
        Ok(record)
    }

    pub(super) async fn new_account(
        &self,
        signer: &dyn JwsSigner,
        record: &AccountRecord,
        options: &RegistrationOptions,
        only_return_existing: bool,
    ) -> Result<crate::transport::AcmeResponse, AccountError> {
        if !only_return_existing {
            match (
                &self.client.directory().meta.terms_of_service,
                &record.accepted_terms_url,
            ) {
                (Some(required), Some(accepted)) if required == accepted => {}
                (Some(required), _) => return Err(AccountError::TermsRequired(required.clone())),
                (None, _) => {}
            }
            if self.client.directory().meta.external_account_required
                && options.external_account.is_none()
            {
                return Err(AccountError::ExternalAccountRequired);
            }
        }
        let binding = match (&options.external_account, only_return_existing) {
            (Some(eab), false) => {
                Some(eab.bind(&signer.jwk()?, self.client.directory().new_account.as_str())?)
            }
            (Some(_), true) | (None, _) => None,
        };
        let body = if only_return_existing {
            json_payload(&FindAccountRequest {
                only_return_existing: true,
            })?
        } else {
            json_payload(&NewAccountRequest {
                contact: (!record.contacts.is_empty()).then_some(record.contacts.as_slice()),
                terms_of_service_agreed: record.accepted_terms_url.as_ref().map(|_| true),
                external_account_binding: binding.as_ref(),
            })?
        };
        let response = self
            .client
            .signed(&self.client.directory().new_account, signer, None, &body)
            .await?;
        if only_return_existing && response.status != reqwest::StatusCode::OK {
            return Err(AccountError::InvalidResponse);
        }
        if response.status == reqwest::StatusCode::CREATED
            && let Some(expected) = &binding
        {
            let account: AccountObject = serde_json::from_slice(&response.body)
                .map_err(|_| AccountError::InvalidResponse)?;
            if account.external_account_binding.as_ref() != Some(expected) {
                return Err(AccountError::ExternalAccountNotConfirmed);
            }
        }
        Ok(response)
    }
}
