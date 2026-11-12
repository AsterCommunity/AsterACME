//! Local account catalog queries: metadata snapshots only, without private keys.
use crate::{
    account::{read_record, store_error, valid_account_name},
    toml_file::ensure_real_dir,
};
use aster_acme::storage::{account::AccountStoreError, query::AccountQuery};
use aster_acme_protocol::url::AcmeUrl;
use std::{fs, path::PathBuf};

/// Public local metadata used by interactive account selection; never includes key bytes.
#[derive(Debug, Clone)]
pub struct LocalAccount {
    /// Saved signing key choice; enumeration does not load private keys.
    pub key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm,
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

/// Query bounded local metadata without loading keys or contacting a CA.
///
/// # Errors
/// Rejects invalid filters, unsafe matching paths, corrupt records and oversized catalogs.
pub async fn query_accounts(
    root: PathBuf,
    query: AccountQuery,
) -> Result<Vec<LocalAccount>, AccountStoreError> {
    if query
        .name
        .as_deref()
        .is_some_and(|name| !valid_account_name(name))
    {
        return Err(store_error("invalid account name filter"));
    }
    tokio::task::spawn_blocking(move || {
        let path = root.join("accounts");
        if !path
            .try_exists()
            .map_err(|_| store_error("cannot inspect accounts directory"))?
        {
            return Ok(Vec::new());
        }
        ensure_real_dir(&path)?;
        let paths = if let Some(name) = &query.name {
            vec![path.join(name)]
        } else {
            let mut paths = Vec::new();
            for (index, entry) in fs::read_dir(path)
                .map_err(|_| store_error("cannot list accounts"))?
                .enumerate()
            {
                if index >= 1024 {
                    return Err(store_error("account listing exceeds 1024 entries"));
                }
                let entry = entry.map_err(|_| store_error("cannot read account entry"))?;
                if entry
                    .file_type()
                    .map_err(|_| store_error("cannot inspect account entry"))?
                    .is_dir()
                {
                    paths.push(entry.path());
                }
            }
            paths
        };
        let mut accounts = Vec::new();
        for path in paths {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| store_error("invalid account name"))?;
            if !valid_account_name(name) {
                continue;
            }
            if !path
                .try_exists()
                .map_err(|_| store_error("cannot inspect account directory"))?
            {
                continue;
            }
            ensure_real_dir(&path)?;
            if let Some(record) = read_record(&path.join("account.toml"))? {
                if !query.matches(name, &record) {
                    continue;
                }
                accounts.push(LocalAccount::from_record(name.to_owned(), record));
            }
        }
        accounts.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(accounts)
    })
    .await
    .map_err(|_| store_error("account query worker failed"))?
}

impl LocalAccount {
    /// Convert an authoritative local observation without re-enumerating the account catalog.
    #[must_use]
    pub fn from_record(name: String, record: aster_acme::account::AccountRecord) -> Self {
        let usable = record.is_usable();
        Self {
            key_algorithm: record.key_algorithm,
            key_rotation: record.key_rotation,
            times: record.times,
            name,
            directory: record.directory_url,
            state: record.state,
            last_status: record.last_status,
            deactivation: record.deactivation,
            usable,
        }
    }
}

#[cfg(test)]
mod tests;
