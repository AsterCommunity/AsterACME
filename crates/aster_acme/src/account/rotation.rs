//! Account rotation operations.

use crate::account::{AccountError, AccountRecord, AccountService};
use crate::storage::account::{AccountRotation, AccountRotationStore};
use crate::{
    crypto::JwsSigner,
    transport::{TransportError, json_payload},
};
use aster_acme_core::account::{AccountAction, AccountOperation, KeyRotation, KeyRotationPhase};
use aster_acme_protocol::account::AccountObject;
use std::sync::Arc;

impl AccountService {
    /// Finish the local part of a key rotation already confirmed by the CA.
    /// This recovery path needs no directory discovery or remote request.
    ///
    /// # Errors
    /// Rejects a stale account snapshot, missing confirmation or a mismatched staged key.
    pub async fn finalize_confirmed_rotation(
        keys: &dyn AccountRotationStore,
        directory: &aster_acme_protocol::url::AcmeUrl,
        expected: &AccountRecord,
        algorithm: Option<crate::crypto::key_algorithm::KeyAlgorithm>,
    ) -> Result<AccountRecord, AccountError> {
        let session: Arc<dyn AccountRotation> = Arc::from(keys.rotation(directory).await?);
        let record = session.record();
        if record != *expected
            || record.directory_url != *directory
            || !record
                .key_rotation
                .as_ref()
                .is_some_and(|rotation| rotation.phase == KeyRotationPhase::Confirmed)
        {
            return Err(AccountError::IdentityMismatch);
        }
        let staged = session.stage(algorithm).await?;
        let rotation = record
            .key_rotation
            .as_ref()
            .ok_or(AccountError::IdentityMismatch)?;
        let thumbprint = staged.jwk()?.thumbprint()?;
        if thumbprint != rotation.new_thumbprint
            || thumbprint == record.key_thumbprint
            || algorithm.is_some_and(|choice| choice != staged.algorithm())
        {
            return Err(AccountError::IdentityMismatch);
        }
        session.commit(&record).await?;
        Ok(Self::committed_rotation(record, &staged, thumbprint))
    }

    fn committed_rotation(
        mut record: AccountRecord,
        staged: &Arc<dyn JwsSigner>,
        thumbprint: String,
    ) -> AccountRecord {
        record.key_algorithm = staged.algorithm();
        record.key_thumbprint = thumbprint;
        record.key_rotation = None;
        record
    }

    /// Rotate a durable account key under [RFC 8555 §7.3.5.](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5.)
    /// The inner JWS uses the new key/algorithm, while the outer JWS uses the current
    /// account key/algorithm ([RFC 8555 §7.3.5](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5)); they need not be the same algorithm.
    /// A previous pending request is reconciled using the new key and original account
    /// URL; failure never authorizes another keyChange POST. No private key enters metadata.
    ///
    /// # Errors
    /// Reports unsupported CA endpoints, inactive accounts, persistence failures, or
    /// uncertain remote outcomes. Rerunning finishes a confirmed interrupted local commit.
    pub async fn rotate_key(
        &self,
        keys: &dyn AccountRotationStore,
        algorithm: Option<crate::crypto::key_algorithm::KeyAlgorithm>,
        expected: Option<&AccountRecord>,
    ) -> Result<AccountRecord, AccountError> {
        let session: Arc<dyn AccountRotation> =
            Arc::from(keys.rotation(self.client.directory_url()).await?);
        if expected.is_some_and(|expected| {
            let actual = session.record();
            actual.account_id != expected.account_id
                || actual.directory_url != expected.directory_url
                || actual.account_url != expected.account_url
                || actual.key_thumbprint != expected.key_thumbprint
                || actual.key_rotation != expected.key_rotation
        }) {
            return Err(AccountError::IdentityMismatch);
        }
        let mut record = session.record();
        let action = record
            .action(AccountOperation::RotateKey)
            .map_err(AccountError::from)?;
        if matches!(action, AccountAction::SendKeyChange)
            && self.client.directory().key_change.is_none()
        {
            return Err(AccountError::KeyChangeUnavailable);
        }
        let account_url = record
            .account_url
            .clone()
            .ok_or(AccountError::AccountDoesNotExist)?;
        let old = session.old_signer();
        if record.directory_url != *self.client.directory_url()
            || old.jwk()?.thumbprint()? != record.key_thumbprint
            || old.algorithm() != record.key_algorithm
        {
            return Err(AccountError::IdentityMismatch);
        }
        let new = session.stage(algorithm).await?;
        let new_thumbprint = new.jwk()?.thumbprint()?;
        if new_thumbprint == record.key_thumbprint
            || record
                .key_rotation
                .as_ref()
                .is_some_and(|rotation| rotation.new_thumbprint != new_thumbprint)
        {
            return Err(AccountError::IdentityMismatch);
        }
        match action {
            AccountAction::SendKeyChange => {
                record = self
                    .submit_key_change(session.clone(), record, old.clone(), new.clone())
                    .await?;
            }
            AccountAction::ReconcileKeyChange => {
                let response = self
                    .client
                    .signed(&account_url, new.as_ref(), Some(&account_url), b"")
                    .await
                    .map_err(|_| AccountError::KeyRotationUncertain)?;
                if response.status != reqwest::StatusCode::OK {
                    return Err(AccountError::KeyRotationUncertain);
                }
                let account: AccountObject = serde_json::from_slice(&response.body)
                    .map_err(|_| AccountError::KeyRotationUncertain)?;
                record.observe(&account, self.clock.now());
            }
            AccountAction::FinalizeKeyChange => {}
            AccountAction::LookupExisting
            | AccountAction::Inspect
            | AccountAction::SendDeactivation
            | AccountAction::AlreadyDeactivated
            | AccountAction::Select
            | AccountAction::Update => {
                return Err(AccountError::InvalidResponse);
            }
        }
        record.key_rotation = Some(KeyRotation {
            new_thumbprint: new_thumbprint.clone(),
            phase: KeyRotationPhase::Confirmed,
        });
        session.save(&record).await?;
        session.commit(&record).await?;
        Ok(Self::committed_rotation(record, &new, new_thumbprint))
    }

    pub(super) async fn submit_key_change(
        &self,
        session: Arc<dyn AccountRotation>,
        mut record: AccountRecord,
        old: Arc<dyn JwsSigner>,
        new: Arc<dyn JwsSigner>,
    ) -> Result<AccountRecord, AccountError> {
        let cancelled = tokio_util::sync::CancellationToken::new();
        let _cancel_on_drop = cancelled.clone().drop_guard();
        let service = Self {
            client: self.client.clone(),
            store: self.store.clone(),
            clock: self.clock.clone(),
        };
        // Pending persistence and HTTP submission share one owned task.
        // Dropping the caller must not release the lease between those
        // operations. Before Pending, cancellation prevents submission;
        // afterwards the worker classifies the result without replaying.
        tokio::spawn(async move {
            service
                .send_key_change(
                    session.as_ref(),
                    &mut record,
                    old.as_ref(),
                    new.as_ref(),
                    &cancelled,
                )
                .await?;
            Ok::<_, AccountError>(record)
        })
        .await
        .map_err(|_| AccountError::KeyRotationUncertain)?
    }

    // The mutation owns durable intent; the caller owns reconciliation and commit.
    pub(super) async fn send_key_change(
        &self,
        session: &dyn AccountRotation,
        record: &mut AccountRecord,
        old: &dyn JwsSigner,
        new: &dyn JwsSigner,
        cancelled: &tokio_util::sync::CancellationToken,
    ) -> Result<(), AccountError> {
        let account_url = record
            .account_url
            .clone()
            .ok_or(AccountError::AccountDoesNotExist)?;
        let endpoint = self
            .client
            .directory()
            .key_change
            .as_ref()
            .ok_or(AccountError::KeyChangeUnavailable)?;
        let inner =
            crate::crypto::sign_key_change(new, &old.jwk()?, &account_url, endpoint.as_str())?;
        let new_thumbprint = new.jwk()?.thumbprint()?;
        record.key_rotation = Some(KeyRotation {
            new_thumbprint: new_thumbprint.clone(),
            phase: KeyRotationPhase::Prepared,
        });
        session.save(record).await?;
        let payload = json_payload(&inner)?;
        let submitted = std::sync::atomic::AtomicBool::new(false);
        let response = self
            .client
            .signed_observed(
                endpoint,
                old,
                Some(&account_url),
                &payload,
                &submitted,
                || async {
                    if cancelled.is_cancelled() {
                        return Err("key rotation cancelled before submission".into());
                    }
                    record.key_rotation = Some(KeyRotation {
                        new_thumbprint: new_thumbprint.clone(),
                        phase: KeyRotationPhase::Pending,
                    });
                    session
                        .save(record)
                        .await
                        .map_err(|error| error.to_string())
                },
            )
            .await;
        let response = match response {
            Ok(response) => response,
            Err(
                error @ TransportError::Problem {
                    status: 400 | 409, ..
                },
            ) => {
                // A definitive protocol rejection is distinct from an unknown
                // timeout/5xx result. A later explicit invocation may start over.
                record.key_rotation = None;
                session.save(record).await?;
                return Err(error.into());
            }
            Err(error) => {
                if !submitted.load(std::sync::atomic::Ordering::SeqCst) {
                    record.key_rotation = Some(KeyRotation {
                        new_thumbprint: new_thumbprint.clone(),
                        phase: KeyRotationPhase::Prepared,
                    });
                    session.save(record).await?;
                }
                return Err(error.into());
            }
        };
        if response.status != reqwest::StatusCode::OK {
            return Err(AccountError::InvalidResponse);
        }
        record.times.last_used_at = Some(self.clock.now().to_offset(time::UtcOffset::UTC));
        // RFC 8555 §7.3.5: HTTP 200 confirms rollover. Persist this even if
        // the caller disappeared; recovery can finish the local key swap only.
        record.key_rotation = Some(KeyRotation {
            new_thumbprint,
            phase: KeyRotationPhase::Confirmed,
        });
        session.save(record).await?;
        Ok(())
    }
}
