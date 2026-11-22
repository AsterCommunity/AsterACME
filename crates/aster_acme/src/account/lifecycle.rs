//! Account lifecycle operations.

use crate::account::{
    AccountError, AccountService, AcmeAccount, ContactUpdateError, validate_contacts,
};
use crate::{crypto::JwsSigner, transport::json_payload};
use aster_acme_core::{
    account::{AccountAction, AccountOperation, DeactivationState},
    protocol::AccountStatus,
};
use aster_acme_protocol::account::{AccountObject, AccountStatusRequest, AccountUpdateRequest};

impl AccountService {
    /// Replace the complete account contact list under [RFC 8555 §7.3.2](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.2).
    /// An empty list clears remote contacts. Local intent is saved before HTTP and
    /// remains distinct from the last CA response if the update fails.
    ///
    /// # Errors
    /// Distinguishes no submission, explicit rejection, an unconfirmed remote
    /// result, and CA acceptance followed by failed local observation persistence.
    pub async fn update_contacts(
        &self,
        signer: &dyn JwsSigner,
        contacts: Vec<String>,
    ) -> Result<AcmeAccount, ContactUpdateError> {
        let directory = self.client.directory_url();
        let (mut record, account_url, payload, lease) = async {
            validate_contacts(&contacts)?;
            let thumbprint = signer.jwk()?.thumbprint()?;
            let lease = self.store.lock_account(directory, &thumbprint).await?;
            let mut record = self
                .store
                .load(directory, &thumbprint)
                .await?
                .ok_or(AccountError::AccountDoesNotExist)?;
            if record.directory_url != *directory
                || record.key_thumbprint != thumbprint
                || record.key_algorithm != signer.algorithm()
            {
                return Err(AccountError::IdentityMismatch);
            }
            record
                .action(AccountOperation::Update)
                .map_err(AccountError::from)?;
            let account_url = record
                .account_url
                .clone()
                .ok_or(AccountError::AccountDoesNotExist)?;
            record.contacts.clone_from(&contacts);
            self.store.save(&record, &lease).await?;
            let payload = json_payload(&AccountUpdateRequest { contact: &contacts })?;
            Ok::<_, AccountError>((record, account_url, payload, lease))
        }
        .await
        .map_err(|error| ContactUpdateError::NotSubmitted(Box::new(error)))?;
        let submitted = std::sync::atomic::AtomicBool::new(false);
        let response = self
            .client
            .signed_observed(
                &account_url,
                signer,
                Some(&account_url),
                &payload,
                &submitted,
                || std::future::ready(Ok(())),
            )
            .await
            .map_err(|error| {
                if matches!(
                    error,
                    crate::transport::TransportError::RetryPreparation { .. }
                ) && error.is_definitive_rejection()
                {
                    ContactUpdateError::Rejected(Box::new(error.into()))
                } else if !submitted.load(std::sync::atomic::Ordering::SeqCst) {
                    ContactUpdateError::NotSubmitted(Box::new(error.into()))
                } else if error.is_definitive_rejection() {
                    ContactUpdateError::Rejected(Box::new(error.into()))
                } else {
                    ContactUpdateError::Unconfirmed(Box::new(error.into()))
                }
            })?;
        if response.status != reqwest::StatusCode::OK {
            return Err(ContactUpdateError::Unconfirmed(Box::new(
                AccountError::InvalidResponse,
            )));
        }
        let account: AccountObject = serde_json::from_slice(&response.body).map_err(|_| {
            ContactUpdateError::Unconfirmed(Box::new(AccountError::InvalidResponse))
        })?;
        record.observe(&account, self.clock.now());
        self.store
            .save(&record, &lease)
            .await
            .map_err(ContactUpdateError::Persistence)?;
        Ok(AcmeAccount {
            key_algorithm: signer.algorithm(),
            times: record.times,
            account_id: record.account_id,
            directory_url: directory.clone(),
            account_url,
            status: account.status,
            contacts: account.contact.unwrap_or_default(),
            recovered: false,
        })
    }

    /// Refresh a known account via authenticated POST-as-GET, recovering its URL if absent.
    ///
    /// # Errors
    /// Reports storage, missing account, or network/protocol errors; never creates accounts.
    pub async fn inspect(&self, signer: &dyn JwsSigner) -> Result<AcmeAccount, AccountError> {
        let directory = self.client.directory_url();
        let thumbprint = signer.jwk()?.thumbprint()?;
        {
            let lease = self.store.lock_account(directory, &thumbprint).await?;
            if let Some(mut record) = self.store.load(directory, &thumbprint).await? {
                record
                    .action(AccountOperation::Inspect)
                    .map_err(AccountError::from)?;
                if record.directory_url != *directory
                    || record.key_thumbprint != thumbprint
                    || record.key_algorithm != signer.algorithm()
                {
                    return Err(AccountError::IdentityMismatch);
                }
                if let Some(account_url) = record.account_url.clone() {
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
                        directory_url: directory.clone(),
                        account_url,
                        status: account.status,
                        contacts: account.contact.unwrap_or_default(),
                        recovered: false,
                    });
                }
            }
        }
        self.recover(signer).await
    }

    /// Irreversibly deactivate an existing account ([RFC 8555 §7.3.6](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.6)).
    ///
    /// Persist intent before a signed POST containing only status=deactivated. Network
    /// errors and malformed responses retain pending state; repeated calls never replay
    /// an uncertain mutation. A confirmed local deactivation returns without HTTP.
    ///
    /// # Errors
    /// Reports missing/mismatched identity, uncertain intent, non-active status, storage,
    /// cryptography or CA failures. Only HTTP 200 with deactivated status confirms success.
    pub async fn deactivate(&self, signer: &dyn JwsSigner) -> Result<AcmeAccount, AccountError> {
        let directory = self.client.directory_url();
        let thumbprint = signer.jwk()?.thumbprint()?;
        let lease = self.store.lock_account(directory, &thumbprint).await?;
        let mut record = self
            .store
            .load(directory, &thumbprint)
            .await?
            .ok_or(AccountError::AccountDoesNotExist)?;
        if record.directory_url != *directory
            || record.key_thumbprint != thumbprint
            || record.key_algorithm != signer.algorithm()
        {
            return Err(AccountError::IdentityMismatch);
        }
        let account_url = record
            .account_url
            .clone()
            .ok_or(AccountError::AccountDoesNotExist)?;
        match record
            .action(AccountOperation::Deactivate)
            .map_err(AccountError::from)?
        {
            AccountAction::AlreadyDeactivated => {
                return Ok(AcmeAccount {
                    key_algorithm: signer.algorithm(),
                    times: record.times,
                    account_id: record.account_id,
                    directory_url: directory.clone(),
                    account_url,
                    status: AccountStatus::Deactivated,
                    contacts: record.server_contacts.unwrap_or_default(),
                    recovered: false,
                });
            }
            AccountAction::SendDeactivation => {}
            AccountAction::LookupExisting
            | AccountAction::Inspect
            | AccountAction::Select
            | AccountAction::Update
            | AccountAction::SendKeyChange
            | AccountAction::ReconcileKeyChange
            | AccountAction::FinalizeKeyChange => {
                return Err(AccountError::InvalidResponse);
            }
        }
        record.deactivation = DeactivationState::Pending;
        self.store.save(&record, &lease).await?;
        let response = self
            .client
            .signed(
                &account_url,
                signer,
                Some(&account_url),
                &json_payload(&AccountStatusRequest {
                    status: AccountStatus::Deactivated,
                })?,
            )
            .await?;
        if response.status != reqwest::StatusCode::OK {
            return Err(AccountError::InvalidResponse);
        }
        let account: AccountObject =
            serde_json::from_slice(&response.body).map_err(|_| AccountError::InvalidResponse)?;
        if account.status != AccountStatus::Deactivated {
            return Err(AccountError::InvalidResponse);
        }
        record.observe(&account, self.clock.now());
        self.store.save(&record, &lease).await?;
        Ok(AcmeAccount {
            key_algorithm: signer.algorithm(),
            times: record.times,
            account_id: record.account_id,
            directory_url: directory.clone(),
            account_url,
            status: account.status,
            contacts: account.contact.unwrap_or_default(),
            recovered: false,
        })
    }
}
