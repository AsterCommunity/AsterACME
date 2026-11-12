//! Local account deletion, serialized with protocol operations and isolated before cleanup.
use crate::account::{
    CliAccountStore, MAX_ACCOUNT_FILE, ensure_real_dir, private_dir, read_private, store_error,
};
use aster_acme::storage::account::AccountStoreError;
use std::{fs, path::Path};

impl CliAccountStore {
    /// Remove this named account's local files only, without loading the private key.
    ///
    /// The account lock serializes against registration and remote operations. Rename
    /// removes the whole account from the visible inventory before unlinking known files.
    /// A cleanup error leaves the hidden directory for manual inspection; it is never
    /// reused as an account. Extra user files are retained in their original directory;
    /// only known managed files are inspected and removed.
    ///
    /// # Errors
    /// Reports missing identity, unsafe managed files, lock timeout, cleanup or sync failures.
    pub async fn remove(
        &self,
        expected: &aster_acme::account::AccountRecord,
    ) -> Result<(), AccountStoreError> {
        let expected = expected.clone();
        let slot = self.account_slot();
        ensure_real_dir(&slot)?;
        let lease = self
            .acquire(self.lock_path()?)
            .await
            .map_err(|error| store_error(&error.to_string()))?;
        let name = self.name.clone();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let actual = crate::account::read_record(&slot.join("account.toml"))?.ok_or_else(|| store_error("account identity disappeared before removal"))?;
            if actual.account_id != expected.account_id || actual.directory_url != expected.directory_url || actual.key_thumbprint != expected.key_thumbprint {
                return Err(store_error("account identity changed after confirmation; select and confirm again"));
            }
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
            let mut has_user_entries=false;
            for entry in fs::read_dir(&slot).map_err(|_| store_error("cannot inspect account directory"))? {
                let entry = entry.map_err(|_| store_error("cannot inspect account file"))?;
                let filename = entry.file_name();
                if !matches!(filename.to_str(), Some("account.toml" | "account-key.pk8" | "account.lock" | "account-key.next.pk8" | "account-key.previous.pk8")) {
                    has_user_entries=true;
                    continue;
                }
                // Enforce the same no-follow/owner/single-link policy even for corrupt
                // keys. Removal does not require key decoding or a successful CA request.
                let _bytes = zeroize::Zeroizing::new(read_private(&entry.path(), MAX_ACCOUNT_FILE).map_err(|_| store_error("account file is unsafe; refusing removal"))?);
                files.push(filename);
            }
            if has_user_entries {
                // Retain the same lock inode while removing metadata first. New opens
                // cannot confuse a leftover user directory with an initialized account.
                let metadata=slot.join("account.toml");
                if files.iter().any(|name|name=="account.toml") {
                    fs::remove_file(&metadata).map_err(|_|store_error("cannot remove account metadata"))?;
                    sync_directory(&slot)?;
                }
                for filename in files {
                    if filename=="account.toml" {continue;}
                    fs::remove_file(slot.join(filename)).map_err(|_|store_error("account metadata removed but managed key cleanup failed"))?;
                }
                return sync_directory(&slot);
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

fn sync_directory(path: &Path) -> Result<(), AccountStoreError> {
    crate::state_file::sync_directory(path)
        .map_err(|_| store_error("cannot sync account directory after removal"))
}
