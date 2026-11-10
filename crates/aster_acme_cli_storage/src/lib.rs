//! Private local account metadata, process locks and PKCS#8 key files for the CLI.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::unreachable,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo
    )
)]
use aster_acme_protocol::url::AcmeUrl;

use aster_acme::{
    account::{AccountKeyStore, AccountLease, AccountRecord, AccountStore, AccountStoreError},
    crypto::{AccountKey, AccountSigner, CryptoError},
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod issuance;
mod removal;
mod rotation;
pub mod toml_file;
use toml_file::{FileLease, atomic_write, ensure_real_dir, private_dir, read_private};

const MAX_ACCOUNT_FILE: u64 = 256 * 1024;
const MAX_KEY_FILE: u64 = 64 * 1024;

/// Public local metadata used by interactive account selection; never includes key bytes.
#[derive(Debug, Clone)]
pub struct LocalAccount {
    /// Outstanding key rollover, retained until durable local commit.
    pub key_rotation: Option<aster_acme_core::account::KeyRotation>,
    /// Local observation timestamps; enumeration never updates them.
    pub times: aster_acme::account::AccountTimes,
    /// Local unique account name.
    pub name: String,
    /// CA bound to this account.
    pub directory: AcmeUrl,
    /// Whether local metadata permits active use; enumeration never verifies current CA validity.
    pub usable: bool,
    /// Persisted local stage, independent of the latest observed remote status.
    pub state: aster_acme_core::account::AccountRecordState,
    /// Last CA response, never verified by enumeration.
    pub last_status: Option<aster_acme_core::protocol::AccountStatus>,
    /// Outstanding or confirmed deactivation state.
    pub deactivation: aster_acme_core::account::DeactivationState,
}

/// Enumerate bounded local account metadata without creating keys or accessing a CA.
///
/// # Errors
/// Rejects unsafe paths, corrupt records, I/O failures, or more than 1024 entries.
pub async fn accounts(root: PathBuf) -> Result<Vec<LocalAccount>, AccountStoreError> {
    tokio::task::spawn_blocking(move || {
        let path = root.join("accounts");
        if !path
            .try_exists()
            .map_err(|_| store_error("cannot inspect accounts directory"))?
        {
            return Ok(Vec::new());
        }
        ensure_real_dir(&path)?;
        let mut accounts = Vec::new();
        for (index, entry) in fs::read_dir(path)
            .map_err(|_| store_error("cannot list accounts"))?
            .enumerate()
        {
            if index >= 1024 {
                return Err(store_error("account listing exceeds 1024 entries"));
            }
            let entry = entry.map_err(|_| store_error("cannot read account entry"))?;
            if !entry
                .file_type()
                .map_err(|_| store_error("cannot inspect account entry"))?
                .is_dir()
            {
                continue;
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| store_error("invalid account name"))?;
            if !valid_account_name(&name) {
                continue;
            }
            ensure_real_dir(&entry.path())?;
            if let Some(record) = read_record(&entry.path().join("account.toml"))? {
                let usable = record.is_usable();
                accounts.push(LocalAccount {
                    key_rotation: record.key_rotation,
                    times: record.times,
                    name,
                    directory: record.directory_url,
                    state: record.state,
                    last_status: record.last_status,
                    deactivation: record.deactivation,
                    usable,
                });
            }
        }
        accounts.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(accounts)
    })
    .await
    .map_err(|_| store_error("account listing worker failed"))?
}

/// Local file store with directory-scoped identities and process locks.
#[derive(Debug, Clone)]
pub struct CliAccountStore {
    root: Arc<PathBuf>,
    name: Arc<str>,
    lock_timeout: Duration,
}

impl CliAccountStore {
    /// Open or create the store. Unix directories are forced to mode `0700`.
    ///
    /// # Errors
    /// Rejects symlinks, non-directories, zero/oversized lock timeouts and I/O failures.
    pub fn open(
        root: impl Into<PathBuf>,
        name: &str,
        lock_timeout: Duration,
    ) -> Result<Self, AccountStoreError> {
        if !valid_account_name(name) {
            return Err(store_error("invalid account name"));
        }
        if lock_timeout.is_zero() || lock_timeout > Duration::from_secs(300) {
            return Err(store_error("invalid lock timeout"));
        }
        let root = root.into();
        fs::create_dir_all(&root).map_err(|_| store_error("cannot create data directory"))?;
        ensure_real_dir(&root)?;
        private_dir(&root)?;
        let accounts = root.join("accounts");
        fs::create_dir_all(&accounts)
            .map_err(|_| store_error("cannot create account directory"))?;
        ensure_real_dir(&accounts)?;
        private_dir(&accounts)?;
        Ok(Self {
            root: Arc::new(root),
            name: Arc::from(name),
            lock_timeout,
        })
    }

    /// Read this name's metadata without loading its key or contacting the CA.
    ///
    /// # Errors
    /// Rejects corrupt, unsafe, or unsupported account records.
    pub async fn metadata(&self) -> Result<Option<AccountRecord>, AccountStoreError> {
        let path = self.account_slot().join("account.toml");
        tokio::task::spawn_blocking(move || read_record(&path))
            .await
            .map_err(|_| store_error("account storage worker failed"))?
    }

    fn account_slot(&self) -> PathBuf {
        self.root.join("accounts").join(self.name.as_ref())
    }

    async fn acquire(&self, path: PathBuf) -> Result<FileLease, StorageError> {
        let timeout = self.lock_timeout;
        tokio::task::spawn_blocking(move || toml_file::lock(&path, timeout))
            .await
            .map_err(|_| StorageError::Io)?
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::TimedOut => StorageError::LockTimeout,
                _ => StorageError::Io,
            })
    }
}

/// Failure opening or protecting local account files.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Lock remained held through the configured deadline.
    #[error("account storage lock timed out")]
    LockTimeout,
    /// Key file does not exist.
    #[error("account key not found")]
    NotFound,
    /// File exceeded its configured maximum.
    #[error("account storage file exceeds its size limit")]
    TooLarge,
    /// File/directory was a symlink, wrong kind, or insecurely permissioned.
    #[error("account storage path is unsafe")]
    InsecurePath,
    /// Filesystem operation failed; details may contain local paths and are intentionally hidden.
    #[error("account storage I/O failed")]
    Io,
    /// Cryptographic key encoding failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredAccount {
    version: u32,
    account: AccountRecord,
}

#[async_trait]
impl AccountStore for CliAccountStore {
    async fn lock_account(
        &self,
        _directory: &AcmeUrl,
        _thumbprint: &str,
    ) -> Result<Box<dyn AccountLease>, AccountStoreError> {
        Ok(Box::new(
            self.acquire(self.account_slot().join("account.lock"))
                .await
                .map_err(|error| store_error(&error.to_string()))?,
        ))
    }

    async fn load(
        &self,
        directory: &AcmeUrl,
        thumbprint: &str,
    ) -> Result<Option<AccountRecord>, AccountStoreError> {
        let path = self.account_slot().join("account.toml");
        let directory = directory.clone();
        let thumbprint = thumbprint.to_owned();
        tokio::task::spawn_blocking(move || {
            let record = read_record(&path)?;
            if let Some(record) = &record {
                verify_identity(record, &directory, &thumbprint)?;
            }
            Ok(record)
        })
        .await
        .map_err(|_| store_error("account storage worker failed"))?
    }

    async fn save(&self, record: &AccountRecord) -> Result<(), AccountStoreError> {
        if record.account_id.len() != 43
            || record.key_thumbprint.len() != 43
            || record.contacts.len() > 32
        {
            return Err(store_error("invalid account metadata"));
        }
        let path = self.account_slot().join("account.toml");
        let record = record.clone();
        tokio::task::spawn_blocking(move || {
            if let Some(previous) = read_record(&path)? {
                verify_identity(&previous, &record.directory_url, &record.key_thumbprint)?;
            }
            write_record(&path, &record)
        })
        .await
        .map_err(|_| store_error("account storage worker failed"))?
    }
}

#[async_trait]
impl AccountKeyStore for CliAccountStore {
    async fn signer(
        &self,
        directory: &AcmeUrl,
        name: &str,
        create: bool,
    ) -> Result<Arc<dyn AccountSigner>, AccountStoreError> {
        if name != self.name.as_ref() {
            return Err(store_error(
                "account name does not match the selected store",
            ));
        }
        let slot = self.account_slot();
        let lease = self
            .acquire(slot.join("account.lock"))
            .await
            .map_err(|error| store_error(&error.to_string()))?;
        let directory = directory.clone();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let metadata = slot.join("account.toml");
            let previous = read_record(&metadata)?;
            if let Some(record) = &previous
                && record.directory_url != directory {
                return Err(store_error("account name is already bound to another CA; choose a different --name"));
            }
            let path = slot.join("account-key.pk8");
            match read_private(&path, MAX_KEY_FILE) {
                Ok(bytes) => {
                    let key = AccountKey::from_pkcs8(&zeroize::Zeroizing::new(bytes)).map_err(|_| store_error("account key is corrupt"))?;
                    let thumbprint = key.jwk().and_then(|jwk| jwk.thumbprint()).map_err(|_| store_error("cannot identify account key"))?;
                    let record = previous.ok_or_else(|| store_error("account key exists without its identity record; refusing to guess its CA"))?;
                    verify_identity(&record, &directory, &thumbprint)?;
                    rotation::cleanup(&slot, &record)?;
                    Ok(Arc::new(key) as Arc<dyn AccountSigner>)
                }
                Err(StorageError::NotFound) if create && previous.is_none() => {
                    let key = AccountKey::generate().map_err(|_| store_error("cannot generate account key"))?;
                    let thumbprint = key.jwk().and_then(|jwk| jwk.thumbprint()).map_err(|_| store_error("cannot identify account key"))?;
                    let record = AccountRecord {
            user_agent: None, times: aster_acme::account::AccountTimes::default(),                        account_id: local_account_id(&directory, &thumbprint), directory_url: directory,
                        key_thumbprint: thumbprint, account_url: None, contacts: Vec::new(),
                        server_contacts: None,
last_status: None,
deactivation: aster_acme_core::account::DeactivationState::NotRequested, key_rotation: None, accepted_terms_url: None,
                        state: aster_acme_core::account::AccountRecordState::RegistrationPending,
                    };
                    // The record replaces a separate initialization marker. A crash after
                    // this write leaves a missing-key error, never a silently new identity.
                    write_record(&metadata, &record)?;
                    atomic_write(&path, &key.to_pkcs8().map_err(|_| store_error("cannot encode account key"))?)
                        .map_err(|_| store_error("cannot persist account key"))?;
                    Ok(Arc::new(key) as Arc<dyn AccountSigner>)
                }
                Err(StorageError::NotFound) if previous.is_some() => Err(store_error("account key is missing from an initialized account; refusing to replace it")),
                Err(error) => Err(store_error(&error.to_string())),
            }
        }).await.map_err(|_| store_error("account key worker failed"))?
    }
}

fn verify_identity(
    record: &AccountRecord,
    directory: &AcmeUrl,
    thumbprint: &str,
) -> Result<(), AccountStoreError> {
    if record.directory_url != *directory || record.key_thumbprint != thumbprint {
        return Err(store_error(
            "account metadata does not match the selected CA and key",
        ));
    }
    Ok(())
}

fn read_record(path: &Path) -> Result<Option<AccountRecord>, AccountStoreError> {
    match read_private(path, MAX_ACCOUNT_FILE) {
        Ok(bytes) => {
            let stored: StoredAccount = toml::from_str(
                std::str::from_utf8(&bytes)
                    .map_err(|_| store_error("account metadata is not UTF-8"))?,
            )
            .map_err(|_| store_error("account metadata is corrupt"))?;
            if stored.version != 1 {
                return Err(store_error("unsupported account metadata version"));
            }
            Ok(Some(stored.account))
        }
        Err(StorageError::NotFound) => Ok(None),
        Err(error) => Err(store_error(&error.to_string())),
    }
}

fn write_record(path: &Path, record: &AccountRecord) -> Result<(), AccountStoreError> {
    let body = toml::to_string_pretty(&StoredAccount {
        version: 1,
        account: record.clone(),
    })
    .map_err(|_| store_error("cannot encode account metadata"))?;
    let text = format!("# Managed by aster-acme. DO NOT EDIT this file.\n{body}");
    if text.len() > 256 * 1024 {
        return Err(store_error("account metadata exceeds size limit"));
    }
    toml_file::write_text(path, &text, 256 * 1024)
        .map_err(|_| store_error("cannot persist account metadata"))
}

fn local_account_id(directory: &AcmeUrl, thumbprint: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest as _, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(
        format!("{}\0{thumbprint}", directory.as_str()).as_bytes(),
    ))
}

fn store_error(message: &str) -> AccountStoreError {
    AccountStoreError {
        message: message.to_owned(),
    }
}

/// Account names are 1–64 ASCII letters, digits, hyphens or underscores.
/// Shared by the file adapter and CLI prompts so path validation has one owner.
#[must_use]
pub fn valid_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

#[cfg(test)]
mod tests;
