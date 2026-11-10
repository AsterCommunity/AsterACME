//! Local account deletion, serialized with protocol operations and isolated before cleanup.
use super::{
    AccountStoreError, CliAccountStore, MAX_ACCOUNT_FILE, ensure_real_dir, private_dir,
    read_private, store_error,
};
use std::{fs, path::Path};

impl CliAccountStore {
    /// Remove this named account's local files only, without loading the private key.
    ///
    /// The account lock serializes against registration and remote operations. Rename
    /// removes the whole account from the visible inventory before unlinking known files.
    /// A cleanup error leaves the hidden directory for manual inspection; it is never
    /// reused as an account. Unknown files and unsafe links are rejected before mutation.
    ///
    /// # Errors
    /// Reports missing identity, unsafe/unknown files, lock timeout, cleanup or sync failures.
    pub async fn remove(&self) -> Result<(), AccountStoreError> {
        let slot = self.account_slot();
        ensure_real_dir(&slot)?;
        let lease = self
            .acquire(slot.join("account.lock"))
            .await
            .map_err(|error| store_error(&error.to_string()))?;
        let name = self.name.clone();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let parent = slot.parent().ok_or_else(|| store_error("account directory has no parent"))?;
            ensure_real_dir(&slot)?;
            private_dir(&slot)?;
            let hidden = parent.join(format!(".{name}.removing"));
            match fs::symlink_metadata(&hidden) {
                Ok(_) => return Err(store_error("previous account cleanup requires inspection before removal")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(store_error("cannot inspect deletion directory")),
            }
            let mut files = Vec::new();
            for entry in fs::read_dir(&slot).map_err(|_| store_error("cannot inspect account directory"))? {
                let entry = entry.map_err(|_| store_error("cannot inspect account file"))?;
                let filename = entry.file_name();
                if !matches!(filename.to_str(), Some("account.toml" | "account-key.pk8" | "account.lock" | "account-key.next.pk8" | "account-key.previous.pk8")) {
                    return Err(store_error("account directory contains unknown files; refusing removal"));
                }
                // Enforce the same no-follow/owner/single-link policy even for corrupt
                // keys. Removal does not require key decoding or a successful CA request.
                let _bytes = zeroize::Zeroizing::new(read_private(&entry.path(), MAX_ACCOUNT_FILE).map_err(|_| store_error("account file is unsafe; refusing removal"))?);
                files.push(filename);
            }
            fs::rename(&slot, &hidden).map_err(|_| store_error("cannot isolate account for removal"))?;
            sync_directory(parent)?;
            for filename in files {
                fs::remove_file(hidden.join(filename)).map_err(|_| store_error("account removed from inventory but cleanup failed; inspect hidden .removing directory"))?;
            }
            fs::remove_dir(&hidden).map_err(|_| store_error("account cleanup incomplete; inspect hidden .removing directory"))?;
            sync_directory(parent)
        }).await.map_err(|_| store_error("account removal worker failed"))?
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), AccountStoreError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| store_error("cannot sync account directory after removal"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), AccountStoreError> {
    Err(store_error(
        "private account removal currently requires Unix",
    ))
}
