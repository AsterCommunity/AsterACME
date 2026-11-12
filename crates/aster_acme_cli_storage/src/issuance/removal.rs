//! Scoped local certificate removal under the same lease used by issuance and revocation.
use crate::issuance::{
    CertificateName, CliIssueStore, IssueError, IssueRecord, failure, publication,
    read_generations, selection, write_selection,
};
use crate::toml_file::{FileLease, ensure_real_dir, private_dir, read_private};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Explicit deletion scope; names group independent requests, not one CA order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovalScope {
    /// One exact local request and its artifacts.
    Operation(String),
    /// Completed historical versions only; retain `in_use` and unfinished requests.
    History,
    /// Versions whose revocation was confirmed by a saved CA response, including `in_use`.
    Revoked,
    /// All requests and artifacts under this local name.
    All,
}

/// Prepared removal retains the execution lease through confirmation and blocking cleanup.
pub struct CertificateRemoval {
    name: CertificateName,
    slot: PathBuf,
    records: Vec<IssueRecord>,
    files: Vec<PathBuf>,
    links: Vec<PathBuf>,
    remove_catalog: bool,
    remove_in_use: bool,
    scope: RemovalScope,
    lease: Arc<FileLease>,
}

impl CliIssueStore {
    /// Validate the selected scope before confirmation, without decoding private keys.
    ///
    /// # Errors
    /// Rejects missing identity, unsafe managed paths, invalid `in_use`, interrupted cleanup or contention.
    pub async fn prepare_removal(
        &self,
        name: &CertificateName,
        scope: RemovalScope,
    ) -> Result<CertificateRemoval, IssueError> {
        let slot = self.slot(name);
        ensure_real_dir(&slot)?;
        let lease = self.lease(name).await?;
        let name = name.clone();
        tokio::task::spawn_blocking(move || {
            ensure_real_dir(&slot)?;
            ensure_idle(&slot)?;
            let config = selection(&slot)?;
            if config.cert.name != name {
                return Err(failure("certificate removal identity mismatch"));
            }
            let inventory = read_generations(&slot, &name)?;
            let records = select_records(&slot, &inventory, config.cert.in_use.as_deref(), &scope)?;
            let remove_catalog = matches!(scope, RemovalScope::All)
                || (!records.is_empty() && records.len() == inventory.len());
            let links = managed_links(&slot, &inventory, &records)?;
            let remove_in_use = config
                .cert
                .in_use
                .as_ref()
                .is_some_and(|id| records.iter().any(|r| &r.operation_id == id))
                || links
                    .iter()
                    .any(|path| path.file_name().is_some_and(|name| name == "in_use"));
            validate_file(&slot.join("cert.toml"))?;
            let files = artifact_paths(&slot, &records)?;
            Ok(CertificateRemoval {
                name,
                slot,
                records,
                files,
                links,
                remove_catalog,
                remove_in_use,
                scope,
                lease,
            })
        })
        .await
        .map_err(|_| failure("certificate removal preparation worker failed"))?
    }
}

impl CertificateRemoval {
    /// Selected local certificate group name.
    #[must_use]
    pub fn name(&self) -> &CertificateName {
        &self.name
    }

    /// Original directory; extra content and the original lock inode remain here.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.slot
    }

    /// Exact deletion scope, independently of how many requests currently match it.
    #[must_use]
    pub fn scope(&self) -> &RemovalScope {
        &self.scope
    }

    /// Selected requests, suitable for confirmation; no private material is exposed.
    #[must_use]
    pub fn records(&self) -> &[IssueRecord] {
        &self.records
    }

    /// Number of requests which will be removed.
    #[must_use]
    pub fn generations(&self) -> usize {
        self.records.len()
    }

    /// Whether `in_use` will be cleared. Historical versions are never automatically promoted.
    #[must_use]
    pub fn removes_in_use(&self) -> bool {
        self.remove_in_use
    }

    /// Delete the prepared scope. No network, account mutation or DNS cleanup.
    ///
    /// # Errors
    /// Failed cleanup keeps `.removing` to prevent reusing partial material after restart.
    pub async fn remove(self) -> Result<(), IssueError> {
        tokio::task::spawn_blocking(move || {
            let _lease=self.lease;
            if self.records.is_empty() && !self.remove_catalog {return Ok(());}
            let marker=self.slot.join(".removing");
            fs::create_dir(&marker).map_err(|_|failure("cannot establish certificate removal marker"))?;
            private_dir(&marker)?;
            sync_directory(&self.slot)?;
            if self.remove_catalog {
                fs::remove_file(self.slot.join("cert.toml")).map_err(|_|failure("cannot remove certificate catalog; inspect .removing marker"))?;
            } else if self.remove_in_use {
                let mut config=selection(&self.slot)?;
                config.cert.in_use=None;
                write_selection(&self.slot,&config)?;
            }
            for link in self.links { publication::NATIVE.remove(&link)?; }
            for file in self.files {fs::remove_file(file).map_err(|_|failure("certificate cleanup incomplete; inspect .removing marker and retained directory"))?;}
            for record in self.records {
                let generation=self.slot.join(record.generation_name());
                match fs::remove_dir(&generation) {
                    Ok(()) => {},
                    Err(error) if error.kind()==std::io::ErrorKind::DirectoryNotEmpty => sync_directory(&generation)?,
                    Err(_) => return Err(failure("certificate generation cleanup incomplete; inspect .removing marker")),
                }
            }
            sync_directory(&self.slot)?;
            fs::remove_dir(marker).map_err(|_|failure("cannot finish certificate removal marker"))?;
            sync_directory(&self.slot)?;
            if self.remove_catalog {
                match fs::remove_dir(&self.slot) {
                    Ok(()) => sync_directory(self.slot.parent().ok_or_else(|| failure("missing certificate parent"))?)?,
                    Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {},
                    Err(_) => return Err(failure("certificate files removed but empty directory cleanup failed")),
                }
            }
            Ok(())
        }).await.map_err(|_|failure("certificate removal worker failed"))?
    }
}

fn select_records(
    slot: &Path,
    records: &[IssueRecord],
    in_use: Option<&str>,
    scope: &RemovalScope,
) -> Result<Vec<IssueRecord>, IssueError> {
    match scope {
        RemovalScope::All => Ok(records.to_vec()),
        RemovalScope::Revoked => Ok(records
            .iter()
            .filter(|record| {
                matches!(
                    record.revocation.state,
                    aster_acme_core::revocation::RevocationState::Confirmed
                )
            })
            .cloned()
            .collect()),
        RemovalScope::Operation(id) => records
            .iter()
            .find(|r| &r.operation_id == id)
            .cloned()
            .map(|r| vec![r])
            .ok_or_else(|| failure("saved certificate request not found")),
        RemovalScope::History => {
            let in_use = in_use
                .and_then(|id| records.iter().find(|r| r.operation_id == id))
                .ok_or_else(|| {
                    failure("no in_use certificate is selected; use an exact request or --all")
                })?;
            if in_use.unfinished() || !publication::NATIVE.matches(slot, in_use)? {
                return Err(failure(
                    "in_use certificate selection is inconsistent; refusing history cleanup",
                ));
            }
            Ok(records
                .iter()
                .filter(|r| r.operation_id != in_use.operation_id && !r.unfinished())
                .cloned()
                .collect())
        }
    }
}

fn artifact_paths(slot: &Path, records: &[IssueRecord]) -> Result<Vec<PathBuf>, IssueError> {
    let mut files = Vec::new();
    for record in records {
        let generation = slot.join(record.generation_name());
        private_dir(&generation)?;
        for entry in fs::read_dir(&generation)
            .map_err(|_| failure("cannot inspect certificate generation"))?
        {
            let entry = entry.map_err(|_| failure("cannot inspect certificate artifact"))?;
            if matches!(
                entry.file_name().to_str(),
                Some(
                    "operation.toml"
                        | "private-key.pk8"
                        | "request.der"
                        | "material.sha256"
                        | "fullchain.pem"
                        | "cert.pem"
                        | "ca.pem"
                        | "private-key.pem"
                )
            ) {
                files.push(entry.path());
            }
        }
    }
    for file in &files {
        validate_file(file)?;
    }
    Ok(files)
}

pub(super) fn ensure_idle(slot: &Path) -> Result<(), IssueError> {
    match fs::symlink_metadata(slot.join(".removing")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(failure("previous certificate cleanup requires inspection")),
        Err(_) => Err(failure("cannot inspect certificate cleanup marker")),
    }
}

fn validate_file(path: &Path) -> Result<(), IssueError> {
    let _bytes = zeroize::Zeroizing::new(
        read_private(path, 1024 * 1024)
            .map_err(|_| failure("certificate artifact unsafe; refusing removal"))?,
    );
    Ok(())
}

fn managed_links(
    slot: &Path,
    inventory: &[IssueRecord],
    selected: &[IssueRecord],
) -> Result<Vec<PathBuf>, IssueError> {
    let mut links = Vec::new();
    for filename in std::iter::once("in_use".to_owned()).chain(
        inventory
            .iter()
            .map(|r| format!(".in_use-{}", r.operation_id)),
    ) {
        let path = slot.join(&filename);
        if let Some(target) = publication::NATIVE.target(&path)? {
            if !inventory.iter().any(|record| {
                target == record.generation_name()
                    && (filename == "in_use"
                        || filename == format!(".in_use-{}", record.operation_id))
            }) {
                return Err(failure(
                    "certificate view does not point to a managed generation",
                ));
            }
            if selected
                .iter()
                .any(|record| target == record.generation_name())
            {
                links.push(path);
            }
        }
    }
    Ok(links)
}

fn sync_directory(path: &Path) -> Result<(), IssueError> {
    crate::state_file::sync_directory(path)
        .map_err(|_| failure("cannot sync certificate directory after removal"))
}
