//! Deployment session: leased file operations, not business policy.
use crate::issuance::deployment::configuration::validate_binding;
use crate::issuance::deployment::{
    DeploymentArtifacts, DeploymentBinding, DeploymentSession, publication, targets, validate_id,
};
use crate::issuance::{
    CertificateName, CliIssueStore, IssueError, IssueRecord, failure, selection,
};
use crate::toml_file::read_private;
use aster_acme::{deployment::DeploymentIntent, issuance::certificate, storage::query::IssueQuery};
use std::{path::Path, sync::Arc};
use zeroize::Zeroizing;

impl CliIssueStore {
    /// Open the current `in_use` generation and hold its certificate lease through reload.
    ///
    /// # Errors
    /// Returns an error if the binding, selected generation or required certificate material
    /// is unavailable or unsafe.
    pub async fn open_deployment(
        &self,
        name: &CertificateName,
        id: &str,
    ) -> Result<DeploymentSession, IssueError> {
        validate_id(id)?;
        let id = id.to_owned();
        let config_lease = self.deployment_config_lease().await?;
        let root = self.root.clone();
        let slot = self.slot(name);
        let lease = self.lease(name).await?;
        let name = name.clone();
        tokio::task::spawn_blocking(move || {
            let _config_lease = config_lease;
            let config = selection(&slot)?;
            let definition = config
                .cert
                .deployments
                .iter()
                .find(|item| item.id == id)
                .cloned()
                .ok_or_else(|| failure("deployment ID not found"))?;
            validate_binding(&definition)?;
            targets::check_conflicts(&root, &name, &definition)?;
            let record = selected_record(&slot, &name)?;
            if !record.deployment_eligible() {
                return Err(failure(
                    "cannot deploy an unfinished or revoked certificate",
                ));
            }
            let generation = record.generation_name();
            let path = slot.join(&generation);
            let fullchain = read_private(&path.join("fullchain.pem"), 1024 * 1024)
                .map_err(|_| failure("fullchain unavailable"))?;
            let der = Zeroizing::new(
                read_private(&path.join("private-key.pk8"), 64 * 1024)
                    .map_err(|_| failure("certificate key unavailable"))?,
            );
            certificate::validate(&fullchain, &der, &record.identifiers)?;
            let artifacts = certificate::artifacts(&fullchain, &der)?;
            Ok(DeploymentSession {
                slot,
                name,
                definition,
                record,
                artifacts: Arc::new(DeploymentArtifacts {
                    generation,
                    fullchain,
                    certificate: artifacts.certificate.into_bytes(),
                    ca_chain: artifacts.ca_chain.into_bytes(),
                    private_key: Zeroizing::new(artifacts.private_key.as_bytes().to_vec()),
                }),
                lease,
            })
        })
        .await
        .map_err(|_| failure("deployment open worker failed"))?
    }
}

impl DeploymentSession {
    /// Revalidate automatic execution against the live binding and generation
    /// while this session owns the same lease used by renew/update/remove.
    #[must_use]
    pub fn admits(
        &self,
        intent: DeploymentIntent<'_, DeploymentBinding>,
        now: time::OffsetDateTime,
    ) -> bool {
        let matches = match intent {
            DeploymentIntent::Retry { snapshot, .. } => &self.definition == snapshot,
            DeploymentIntent::Explicit | DeploymentIntent::AfterIssuance { .. } => true,
        };
        self.definition
            .checkpoint()
            .admits(&self.artifacts.generation, intent, matches, now)
    }

    /// Binding snapshot this session was opened with, including its execution state.
    #[must_use]
    pub fn definition(&self) -> &DeploymentBinding {
        &self.definition
    }
    /// Certificate artifacts staged for this session's generation.
    #[must_use]
    pub fn artifacts(&self) -> &DeploymentArtifacts {
        &self.artifacts
    }

    /// Stage and sync every selected artifact before replacing any destination.
    /// Each replacement is atomic; a failure during commit can leave a partial set.
    /// The caller records Publishing before this operation and reloads only on success.
    /// The worker retains the certificate lease through completion after cancellation.
    ///
    /// # Errors
    /// Returns an error if a destination is unsafe or any staged file cannot be published.
    pub async fn publish(&self) -> Result<(), IssueError> {
        let target = self.definition.target.clone();
        let permissions = self.definition.permissions.clone();
        let lease = self.lease.clone();
        let artifacts = Arc::clone(&self.artifacts);
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            publication::PreparedPublication::prepare(&target, &artifacts, &permissions)?.commit()
        })
        .await
        .map_err(|_| failure("deployment file worker failed"))?
    }
}

pub(super) fn selected_record(
    slot: &Path,
    name: &CertificateName,
) -> Result<IssueRecord, IssueError> {
    let root = slot
        .parent()
        .ok_or_else(|| failure("certificate directory has no parent"))?;
    crate::issuance::query::read(
        root,
        &IssueQuery {
            name: Some(name.clone()),
            in_use: Some(true),
            ..IssueQuery::default()
        },
    )?
    .pop()
    .ok_or_else(|| failure("certificate has no selected generation"))
}
