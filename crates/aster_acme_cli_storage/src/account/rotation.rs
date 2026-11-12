//! Durable rollover journal, with a lease retained by every blocking write.
use crate::account::{
    AccountKey, AccountRecord, AccountSigner, AcmeUrl, Arc, CliAccountStore, FileLease,
    MAX_KEY_FILE, Path, PathBuf, StorageError, async_trait, atomic_write, fs, read_private,
    read_record, store_error, verify_identity, write_record,
};
use aster_acme::storage::account::{AccountRotation, AccountRotationStore, AccountStoreError};
use aster_acme_core::account::{AccountOperation, KeyRotationPhase};

struct Rotation {
    slot: PathBuf,
    lease: Arc<FileLease>,
    record: AccountRecord,
    old: Arc<dyn AccountSigner>,
}

impl Rotation {
    fn validate(&self, record: &AccountRecord) -> Result<(), AccountStoreError> {
        if record.directory_url != self.record.directory_url
            || record.key_thumbprint != self.record.key_thumbprint
            || record.account_id != self.record.account_id
            || record.account_url != self.record.account_url
            || record.key_algorithm != self.record.key_algorithm
        {
            return Err(store_error(
                "rotation cannot change the existing account identity",
            ));
        }
        if let Some(rotation) = &record.key_rotation
            && (rotation.new_thumbprint.len() != 43
                || rotation.new_thumbprint == record.key_thumbprint)
        {
            return Err(store_error("invalid proposed rotation identity"));
        }
        Ok(())
    }
}

fn load_key(path: &Path) -> Result<Arc<dyn AccountSigner>, AccountStoreError> {
    let bytes =
        zeroize::Zeroizing::new(read_private(path, MAX_KEY_FILE).map_err(|_| {
            store_error("rotation key is missing or unsafe; retain all account files")
        })?);
    Ok(Arc::new(
        AccountKey::from_pkcs8(&bytes).map_err(|_| store_error("rotation key is corrupt"))?,
    ))
}

fn thumbprint(key: &dyn AccountSigner) -> Result<String, AccountStoreError> {
    key.jwk()
        .and_then(|key| key.thumbprint())
        .map_err(|_| store_error("cannot identify rotation key"))
}

#[async_trait]
impl AccountRotationStore for CliAccountStore {
    async fn rotation(
        &self,
        directory: &AcmeUrl,
    ) -> Result<Box<dyn AccountRotation>, AccountStoreError> {
        let slot = self.account_slot();
        let lease = Arc::new(
            self.acquire(self.lock_path()?)
                .await
                .map_err(|error| store_error(&error.to_string()))?,
        );
        let directory = directory.clone();
        tokio::task::spawn_blocking(move || {
            let record = read_record(&slot.join("account.toml"))?
                .ok_or_else(|| store_error("account record is missing"))?;
            if record.directory_url != directory {
                return Err(store_error("account is bound to another CA"));
            }
            record
                .action(AccountOperation::RotateKey)
                .map_err(|_| store_error("account is not eligible for key rotation"))?;
            cleanup(&slot, &record)?;
            let backup = slot.join("account-key.previous.pk8");
            let old = match read_private(&backup, MAX_KEY_FILE) {
                Ok(_) => load_key(&backup)?,
                Err(StorageError::NotFound) => load_key(&slot.join("account-key.pk8"))?,
                Err(_) => return Err(store_error("rotation backup is unsafe")),
            };
            verify_identity(&record, &directory, &thumbprint(old.as_ref())?)?;
            if old.algorithm() != record.key_algorithm {
                return Err(store_error("account key algorithm does not match metadata"));
            }
            Ok(Box::new(Rotation {
                slot,
                lease,
                record,
                old,
            }) as Box<dyn AccountRotation>)
        })
        .await
        .map_err(|_| store_error("rotation worker failed"))?
    }
}

/// Completed metadata and primary key must agree before any obsolete keys are removed.
pub(super) fn cleanup(slot: &Path, record: &AccountRecord) -> Result<(), AccountStoreError> {
    if record.key_rotation.is_some() {
        return Ok(());
    }
    let primary = load_key(&slot.join("account-key.pk8"))?;
    if primary.algorithm() != record.key_algorithm {
        return Err(store_error("account key algorithm does not match metadata"));
    }
    verify_identity(
        record,
        &record.directory_url,
        &thumbprint(primary.as_ref())?,
    )?;
    let mut paths = Vec::new();
    for name in ["account-key.previous.pk8", "account-key.next.pk8"] {
        let path = slot.join(name);
        match read_private(&path, MAX_KEY_FILE) {
            Ok(_) => paths.push(path),
            Err(StorageError::NotFound) => {}
            Err(_) => return Err(store_error("rotation cleanup file is unsafe")),
        }
    }
    for path in paths {
        fs::remove_file(path).map_err(|_| store_error("completed rotation cleanup failed"))?;
    }
    crate::state_file::sync_directory(slot).map_err(|_| store_error("cannot sync rotation cleanup"))
}

#[async_trait]
impl AccountRotation for Rotation {
    fn record(&self) -> AccountRecord {
        self.record.clone()
    }
    fn old_signer(&self) -> Arc<dyn AccountSigner> {
        self.old.clone()
    }

    async fn stage(
        &self,
        algorithm: Option<aster_acme::crypto::key_algorithm::KeyAlgorithm>,
    ) -> Result<Arc<dyn AccountSigner>, AccountStoreError> {
        let slot = self.slot.clone();
        let lease = self.lease.clone();
        let pending = self.record.key_rotation.is_some();
        let fallback = self.old.algorithm();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let path = slot.join("account-key.next.pk8");
            match read_private(&path, MAX_KEY_FILE) {
                Ok(_) => {
                    // The on-disk proposal is authoritative after a restart: changing
                    // its algorithm would silently change the remote rotation intent.
                    let key = load_key(&path)?;
                    if algorithm.is_some_and(|choice| choice != key.algorithm()) {
                        return Err(store_error(
                            "requested algorithm differs from the staged rotation key",
                        ));
                    }
                    Ok(key)
                }
                Err(StorageError::NotFound) if !pending => {
                    let key = AccountKey::generate(algorithm.unwrap_or(fallback))
                        .map_err(|_| store_error("cannot generate rotation key"))?;
                    atomic_write(
                        &path,
                        &key.to_pkcs8()
                            .map_err(|_| store_error("cannot encode rotation key"))?,
                    )
                    .map_err(|_| store_error("cannot stage rotation key"))?;
                    Ok(Arc::new(key) as Arc<dyn AccountSigner>)
                }
                Err(_) => Err(store_error("staged rotation key is missing or unsafe")),
            }
        })
        .await
        .map_err(|_| store_error("rotation staging worker failed"))?
    }

    async fn save(&self, record: &AccountRecord) -> Result<(), AccountStoreError> {
        self.validate(record)?;
        let slot = self.slot.clone();
        let lease = self.lease.clone();
        let record = record.clone();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            write_record(&slot.join("account.toml"), &record)
        })
        .await
        .map_err(|_| store_error("rotation journal worker failed"))?
    }

    async fn commit(&self, record: &AccountRecord) -> Result<(), AccountStoreError> {
        self.validate(record)?;
        let slot = self.slot.clone();
        let lease = self.lease.clone();
        let mut record = record.clone();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let rotation = record
                .key_rotation
                .as_ref()
                .filter(|rotation| rotation.phase == KeyRotationPhase::Confirmed)
                .ok_or_else(|| store_error("key rotation is not confirmed"))?;
            let next = slot.join("account-key.next.pk8");
            let bytes = zeroize::Zeroizing::new(
                read_private(&next, MAX_KEY_FILE)
                    .map_err(|_| store_error("cannot read staged rotation key"))?,
            );
            let new =
                AccountKey::from_pkcs8(&bytes).map_err(|_| store_error("invalid staged key"))?;
            let new_thumbprint = thumbprint(&new)?;
            if new_thumbprint != rotation.new_thumbprint {
                return Err(store_error("staged key does not match rotation journal"));
            }
            let primary = slot.join("account-key.pk8");
            let backup = slot.join("account-key.previous.pk8");
            match read_private(&backup, MAX_KEY_FILE) {
                Ok(_) => verify_identity(
                    &record,
                    &record.directory_url,
                    &thumbprint(load_key(&backup)?.as_ref())?,
                )?,
                Err(StorageError::NotFound) => {
                    let old = zeroize::Zeroizing::new(
                        read_private(&primary, MAX_KEY_FILE)
                            .map_err(|_| store_error("cannot back up account key"))?,
                    );
                    atomic_write(&backup, &old)
                        .map_err(|_| store_error("cannot persist old key backup"))?;
                }
                Err(_) => return Err(store_error("rotation backup is unsafe")),
            }
            atomic_write(&primary, &bytes)
                .map_err(|_| store_error("cannot install rotated key"))?;
            // Switch algorithm metadata together with the confirmed primary key,
            // never while the old key still authorizes ordinary ACME requests.
            record.key_algorithm = new.algorithm();
            record.key_thumbprint = new_thumbprint;
            record.key_rotation = None;
            write_record(&slot.join("account.toml"), &record)?;
            // Keep completed key files until the next locked open. Cleanup is separate
            // from commit so a failed unlink cannot make a completed CA mutation fail.
            Ok(())
        })
        .await
        .map_err(|_| store_error("rotation commit worker failed"))?
    }
}

#[cfg(test)]
mod tests;
