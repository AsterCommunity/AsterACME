//! Durable provider binding/checkpoints and per-remote-RRset process leases.
use aster_acme_dns::{
    DnsRecord, ProviderError, ProviderErrorCode, ProviderExecution, SideEffect,
    operation::{PublicationSession, PublicationStore, RecoveryState},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct ProviderPublicationStore {
    root: PathBuf,
}
impl ProviderPublicationStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    backend: String,
    binding: String,
    record: DnsRecord,
    state: Option<RecoveryState>,
}

struct Session {
    path: PathBuf,
    journal: Journal,
    // Blocking writes clone these leases: dropping an awaiting future cannot unlock them.
    leases: Arc<(crate::toml_file::FileLease, crate::toml_file::FileLease)>,
}

#[async_trait]
impl PublicationStore for ProviderPublicationStore {
    async fn open(
        &self,
        backend: &str,
        binding: &str,
        record: &DnsRecord,
        execution: &ProviderExecution,
    ) -> Result<Box<dyn PublicationSession>, ProviderError> {
        let root = self.root.clone();
        let backend = backend.to_owned();
        let binding = binding.to_owned();
        let record = record.clone();
        let execution = execution.clone();
        tokio::task::spawn_blocking(move || {
            if !aster_acme_dns::backend::valid_backend_id(&backend)
                || record.publication_id.is_empty()
                || record.publication_id.len() > 128
            {
                return Err(storage_error());
            }
            let publication = digest(&record.publication_id)?;
            // One backend and owner share a lock even across pinned and discovered scopes.
            let mutation = digest(&(
                backend.as_str(),
                record.name.trim_end_matches('.').to_ascii_lowercase(),
                "TXT",
            ))?;
            let own_lock = crate::toml_file::object_lock(
                &root,
                crate::toml_file::ObjectKind::Provider,
                &format!("publication-{publication}"),
            )
            .map_err(|_| storage_error())?;
            let remote_lock = crate::toml_file::object_lock(
                &root,
                crate::toml_file::ObjectKind::Provider,
                &format!("rrset-{mutation}"),
            )
            .map_err(|_| storage_error())?;
            let own_lease = lease(&own_lock, &execution)?;
            let remote_lease = lease(&remote_lock, &execution)?;
            let directory = root.join("providers").join(".publications");
            crate::toml_file::durable_private_dir(&directory).map_err(|_| storage_error())?;
            let path = directory.join(format!("{publication}.json"));
            let journal = match crate::state_file::read_private(&path, 64 * 1024) {
                Ok(bytes) => {
                    let journal: Journal =
                        serde_json::from_slice(&bytes).map_err(|_| storage_error())?;
                    if journal.state.as_ref().is_some_and(|state| {
                        state.version == 0
                            || serde_json::to_vec(&state.data)
                                .map_or(true, |data| data.len() > 32768)
                    }) {
                        return Err(storage_error());
                    }
                    if journal.version != 1
                        || journal.backend != backend
                        || journal.binding != binding
                        || journal.record != record
                    {
                        return Err(ProviderError {
                            code: ProviderErrorCode::RecordConflict,
                            message:
                                "saved DNS publication backend, remote scope or record changed"
                                    .into(),
                            side_effect: SideEffect::Unknown,
                            retry_after_seconds: None,
                            provider_code: None,
                        });
                    }
                    journal
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let journal = Journal {
                        version: 1,
                        backend,
                        binding,
                        record,
                        state: None,
                    };
                    write(&path, &journal)?;
                    journal
                }
                Err(_) => return Err(storage_error()),
            };
            Ok(Box::new(Session {
                path,
                journal,
                leases: Arc::new((own_lease, remote_lease)),
            }) as Box<dyn PublicationSession>)
        })
        .await
        .map_err(|_| storage_error())?
    }
}

#[async_trait]
impl PublicationSession for Session {
    fn state(&self) -> Option<RecoveryState> {
        self.journal.state.clone()
    }
    async fn save(&mut self, state: RecoveryState) -> Result<(), ProviderError> {
        if state.version == 0
            || serde_json::to_vec(&state.data).map_or(true, |data| data.len() > 32768)
        {
            return Err(storage_error());
        }
        let mut journal = self.journal.clone();
        journal.state = Some(state);
        let updated = journal.clone();
        let path = self.path.clone();
        let leases = self.leases.clone();
        tokio::task::spawn_blocking(move || {
            let _leases = leases;
            write(&path, &journal)
        })
        .await
        .map_err(|_| storage_error())??;
        self.journal = updated;
        Ok(())
    }
}

fn write(path: &std::path::Path, journal: &Journal) -> Result<(), ProviderError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| storage_error())?;
    if bytes.len() > 64 * 1024 {
        return Err(storage_error());
    }
    let (directory, name) = crate::state_file::location(path).map_err(|_| storage_error())?;
    directory
        .atomic_write(name, &bytes)
        .map_err(|_| storage_error())
}

fn lease(
    path: &std::path::Path,
    execution: &ProviderExecution,
) -> Result<crate::toml_file::FileLease, ProviderError> {
    let file: File = crate::toml_file::open_lock(path).map_err(|_| storage_error())?;
    loop {
        if execution.cancellation.is_cancelled() || Instant::now() >= execution.deadline {
            return Err(storage_error());
        }
        match file.try_lock() {
            Ok(()) => return Ok(crate::toml_file::FileLease(file)),
            Err(std::fs::TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
            Err(std::fs::TryLockError::Error(_)) => return Err(storage_error()),
        }
    }
}

fn digest(value: &impl Serialize) -> Result<String, ProviderError> {
    let bytes = serde_json::to_vec(value).map_err(|_| storage_error())?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        Sha256::digest(bytes),
    ))
}

fn storage_error() -> ProviderError {
    ProviderError {
        code: ProviderErrorCode::InternalError,
        message: "DNS publication checkpoint or mutation lease unavailable".into(),
        side_effect: SideEffect::Unknown,
        retry_after_seconds: None,
        provider_code: None,
    }
}

#[cfg(test)]
mod tests;
