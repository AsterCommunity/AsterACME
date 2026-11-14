//! RFC 8555 section 7.6 authorization, independent of revocation state transitions.
use crate::{
    account::AccountRecord,
    crypto::{JwsSigner, jwk::Jwk},
    issuance::IssueError,
    revocation::{RevocationSigner, RevocationTarget},
};
use aster_acme_protocol::url::AcmeUrl;
use std::sync::Arc;
use x509_parser::prelude::FromDer as _;

/// Explicit authority for one revocation invocation. No private key is serialized.
pub enum RevocationAuthority {
    /// The managed certificate's issuing account; the caller retains its account lease.
    Account {
        /// Shared immutable account observation, held independently of the signer.
        account: Arc<AccountRecord>,
        /// Signer matching the account's current public key.
        signer: Arc<dyn JwsSigner>,
    },
    /// A key matching the leaf certificate, without any ACME account dependency.
    CertificateKey {
        /// Software, hardware or application-owned JWS signer.
        signer: Arc<dyn JwsSigner>,
    },
}

/// Validated authority bound to one certificate target; contains no serialized private key.
pub struct RevocationAuthorization<'a> {
    pub(super) signer: &'a dyn JwsSigner,
    pub(super) kid: Option<&'a AcmeUrl>,
    /// Public identity that must be retained at the submission boundary.
    pub observation: RevocationSigner,
}

impl RevocationAuthority {
    /// Validate the selected authority before confirmation or remote mutation.
    /// # Errors
    /// Rejects inactive/mismatched accounts and certificate keys that do not match the leaf.
    pub fn authorize(
        &self,
        target: &RevocationTarget,
    ) -> Result<RevocationAuthorization<'_>, IssueError> {
        match self {
            Self::Account { account, signer } => {
                let thumbprint = signer.jwk()?.thumbprint()?;
                let url = account
                    .account_url
                    .as_ref()
                    .ok_or(IssueError::RevocationInput("revocation account has no kid"))?;
                if !account.is_usable()
                    || account.directory_url != target.directory
                    || account.key_thumbprint != thumbprint
                    || account.key_algorithm != signer.algorithm()
                    || target.issuer.as_ref().is_some_and(|issuer| {
                        issuer.account_id != account.account_id || issuer.account_url != *url
                    })
                {
                    return Err(IssueError::RevocationInput(
                        "revocation requires the matching active issuing account",
                    ));
                }
                Ok(RevocationAuthorization {
                    signer: signer.as_ref(),
                    kid: Some(url),
                    observation: RevocationSigner::Account {
                        account_id: account.account_id.clone(),
                        account_url: url.clone(),
                        key_thumbprint: thumbprint,
                    },
                })
            }
            Self::CertificateKey { signer } => {
                let (rest, certificate) =
                    x509_parser::certificate::X509Certificate::from_der(&target.certificate_der)
                        .map_err(|_| {
                            IssueError::RevocationInput("invalid revocation certificate DER")
                        })?;
                if !rest.is_empty() {
                    return Err(IssueError::RevocationInput(
                        "trailing revocation certificate DER",
                    ));
                }
                let public = Jwk::from_spki(certificate.public_key().raw)?;
                if signer.jwk()? != public {
                    return Err(IssueError::RevocationInput(
                        "revocation signing key does not match the certificate",
                    ));
                }
                Ok(RevocationAuthorization {
                    signer: signer.as_ref(),
                    kid: None,
                    observation: RevocationSigner::CertificateKey {
                        key_thumbprint: public.thumbprint()?,
                    },
                })
            }
        }
    }
}
