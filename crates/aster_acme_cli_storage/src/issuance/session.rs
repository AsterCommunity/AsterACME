//! Locked generation reads, durable updates and certificate promotion.
use crate::issuance::{
    IssuancePhase, IssueError, IssueRecord, Session, atomic_write, certificate, check_material,
    failure, publication, read_journal, read_private, selection, write_journal, write_selection,
};
use aster_acme::storage::issuance::IssueSession;
use async_trait::async_trait;

#[async_trait]
impl IssueSession for Session {
    async fn record(&self) -> Result<IssueRecord, IssueError> {
        let permit = self.io.clone().lock_owned().await;
        let generation = self.generation.clone();
        let slot = self.slot.clone();
        let lease = self.lease.clone();
        let record = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lease = lease;
            let mut record = read_journal(&generation.join("operation.toml"))?;
            let config = selection(&slot)?;
            record.is_in_use = config.cert.in_use.as_deref() == Some(record.operation_id.as_str());
            record.deployment_count = Some(config.cert.deployments.len());
            Ok::<_, IssueError>(record)
        })
        .await
        .map_err(|_| failure("issuance snapshot worker failed"))??;
        self.verify_identity(&record)?;
        Ok(record)
    }

    async fn save(&self, record: &IssueRecord) -> Result<(), IssueError> {
        self.verify_identity(record)?;
        let record = record.clone();
        let generation = self.generation.clone();
        let lease = self.lease.clone();
        let permit = self.io.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lease = lease;
            write_journal(&generation.join("operation.toml"), &record)
        })
        .await
        .map_err(|_| failure("issuance journal worker failed"))?
    }

    async fn csr(&self) -> Result<Vec<u8>, IssueError> {
        let generation = self.generation.clone();
        let record = self.initial.clone();
        let lease = self.lease.clone();
        let permit = self.io.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lease = lease;
            check_material(&generation, &record)?;
            read_private(&generation.join("request.der"), 64 * 1024)
                .map_err(|_| failure("fixed CSR missing or unsafe"))
        })
        .await
        .map_err(|_| failure("CSR worker failed"))?
    }

    async fn certificate_der(&self) -> Result<Vec<u8>, IssueError> {
        let generation = self.generation.clone();
        let lease = self.lease.clone();
        let permit = self.io.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lease = lease;
            let chain = read_private(&generation.join("fullchain.pem"), 1024 * 1024)
                .map_err(|_| failure("issued certificate missing or unsafe"))?;
            certificate::leaf_der(&chain)
        })
        .await
        .map_err(|_| failure("certificate read worker failed"))?
    }

    async fn complete(
        &self,
        record: &IssueRecord,
        chain: &[u8],
    ) -> Result<IssueRecord, IssueError> {
        let mut record = record.clone();
        let chain = chain.to_vec();
        let generation = self.generation.clone();
        let slot = self.slot.clone();
        let lease = self.lease.clone();
        self.verify_identity(&record)?;
        let permit = self.io.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lease = lease;
            check_material(&generation, &record)?;
            let key = zeroize::Zeroizing::new(
                read_private(&generation.join("private-key.pk8"), 64 * 1024)
                    .map_err(|_| failure("missing certificate key"))?,
            );
            record.certificate_not_after =
                Some(certificate::validate(&chain, &key, &record.identifiers)?);
            // Establish a durable fallback before promotion; ARI network failures cannot
            // invalidate a successfully issued certificate or erase its renewal plan.
            if record.renewal.is_none() {
                record.renewal = Some(aster_acme::renewal::RenewalPlan::from_certificate(&chain)?);
            }
            if !matches!(record.phase, IssuancePhase::Completed) {
                return Err(failure("cannot promote incomplete issuance"));
            }
            let config = selection(&slot)?;
            if config.cert.in_use.as_deref()
                != record
                    .renewal_of
                    .as_ref()
                    .map(|previous| previous.operation_id.as_str())
                && config.cert.in_use.as_deref() != Some(record.operation_id.as_str())
            {
                return Err(failure(
                    "renewal predecessor is no longer in_use; refusing stale promotion",
                ));
            }
            let artifacts = certificate::artifacts(&chain, &key)?;
            for (name, bytes) in [
                ("fullchain.pem", chain.as_slice()),
                ("cert.pem", artifacts.certificate.as_bytes()),
                ("ca.pem", artifacts.ca_chain.as_bytes()),
                ("private-key.pem", artifacts.private_key.as_bytes()),
            ] {
                atomic_write(&generation.join(name), bytes)
                    .map_err(|_| failure("cannot persist certificate artifact set"))?;
            }
            // Keep the operation resumable until selection is durable. A crash after
            // selection only causes a safe re-download of the same issued artifact.
            record.phase = IssuancePhase::Downloading;
            write_journal(&generation.join("operation.toml"), &record)?;
            publication::NATIVE.publish(&slot, &record)?;
            let mut config = selection(&slot)?;
            config.cert.in_use = Some(record.operation_id.clone());
            if let Err(error) = write_selection(&slot, &config) {
                // The write may have replaced catalog state before a sync error;
                // recover according to what is actually persisted, not the attempted value.
                publication::recover_selection(&slot)?;
                return Err(error);
            }
            publication::NATIVE.recover(&slot, Some(&record.generation_name()))?;
            record.phase = IssuancePhase::Completed;
            record.is_in_use = true;
            write_journal(&generation.join("operation.toml"), &record)?;
            Ok(record)
        })
        .await
        .map_err(|_| failure("certificate completion worker failed"))?
    }
}
