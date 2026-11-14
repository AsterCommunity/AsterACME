//! Managed revocation leases load certificates without issuance/private-key prerequisites.
use crate::issuance::{
    CliIssueStore, OpenMode, Session, failure, read_journal, read_private, write_journal,
};
use aster_acme::{
    crypto::{JwsSigner, key::SoftwareSigningKey},
    issuance::{CertificateName, IssueError, IssueRecord, certificate},
    revocation::{RevocationIssuer, RevocationRecord, RevocationTarget},
    storage::{issuance::IssueSession, revocation::RevocationSession},
};
use aster_acme_core::{revocation::RevocationState, workflow::IssuancePhase};
use async_trait::async_trait;
use std::sync::Arc;

/// Owns one certificate lease; this handle is deliberately not cloneable.
pub struct ManagedRevocationSession {
    session: Session,
    target: RevocationTarget,
}

impl CliIssueStore {
    /// Open a completed target without requiring a CSR, certificate key or active account.
    /// # Errors
    /// Rejects invalid identity, unissued targets, unsafe files and lease contention.
    pub async fn open_revocation(
        &self,
        name: &CertificateName,
        operation_id: &str,
    ) -> Result<ManagedRevocationSession, IssueError> {
        let session = self
            .open_session(name, operation_id, OpenMode::Observation)
            .await?;
        if session.initial.phase != IssuancePhase::Completed {
            return Err(failure("only an issued certificate can be revoked"));
        }
        let target = read_target(&session).await?;
        target.fingerprint()?;
        Ok(ManagedRevocationSession { session, target })
    }
}

impl ManagedRevocationSession {
    /// Read current managed metadata under the same lease for confirmation and reports.
    /// # Errors
    /// Reports journal or immutable identity drift.
    pub async fn certificate_record(&self) -> Result<IssueRecord, IssueError> {
        self.session.record().await
    }

    /// Load the saved certificate key only for explicit certificate-key authorization.
    /// # Errors
    /// Rejects missing/unsafe keys, algorithm drift and unsupported PKCS#8 material.
    pub async fn certificate_signer(&self) -> Result<Arc<dyn JwsSigner>, IssueError> {
        let session = self.session.clone();
        let permit = session.io.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let bytes = zeroize::Zeroizing::new(
                read_private(&session.generation.join("private-key.pk8"), 64 * 1024)
                    .map_err(|_| failure("certificate signing key missing or unsafe"))?,
            );
            session.initial.key_algorithm.validate_key(&bytes)?;
            let signer: Arc<dyn JwsSigner> = Arc::new(SoftwareSigningKey::from_pkcs8(&bytes)?);
            Ok(signer)
        })
        .await
        .map_err(|_| failure("certificate signer worker failed"))?
    }
}

fn target(session: &Session, record: &IssueRecord) -> Result<RevocationTarget, IssueError> {
    session.verify_identity(record)?;
    if record.phase != IssuancePhase::Completed {
        return Err(failure("revocation target is not issued"));
    }
    let chain = read_private(&session.generation.join("fullchain.pem"), 1024 * 1024)
        .map_err(|_| failure("revocation certificate missing or unsafe"))?;
    Ok(RevocationTarget {
        directory: record.directory.clone(),
        certificate_der: certificate::leaf_der(&chain)?,
        issuer: Some(RevocationIssuer {
            account_id: record.account_id.clone(),
            account_url: record.account_url.clone(),
        }),
    })
}

async fn read_target(original: &Session) -> Result<RevocationTarget, IssueError> {
    let session = original.clone();
    let permit = session.io.clone().lock_owned().await;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let record = read_journal(&session.generation.join("operation.toml"))?;
        target(&session, &record)
    })
    .await
    .map_err(|_| failure("revocation target worker failed"))?
}

#[async_trait]
impl RevocationSession for ManagedRevocationSession {
    async fn target(&self) -> Result<RevocationTarget, IssueError> {
        Ok(self.target.clone())
    }

    async fn revocation(&self) -> Result<RevocationRecord, IssueError> {
        Ok(self.session.record().await?.revocation)
    }

    async fn save_revocation(&self, checkpoint: &RevocationRecord) -> Result<(), IssueError> {
        let session = self.session.clone();
        let checkpoint = checkpoint.clone();
        let expected_target = self.target.fingerprint()?;
        let permit = session.io.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let path = session.generation.join("operation.toml");
            let mut record = read_journal(&path)?;
            let target = target(&session, &record)?;
            if checkpoint.check_target(&target)? != expected_target {
                return Err(failure(
                    "revocation certificate changed after the session was opened",
                ));
            }
            if record.revocation.state == RevocationState::Confirmed
                && record.revocation != checkpoint
            {
                return Err(failure(
                    "confirmed revocation checkpoint cannot be replaced",
                ));
            }
            record.revocation = checkpoint;
            write_journal(&path, &record)
        })
        .await
        .map_err(|_| failure("revocation checkpoint worker failed"))?
    }
}
