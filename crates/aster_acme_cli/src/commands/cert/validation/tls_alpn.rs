//! TLS-ALPN-01 responder for RFC 8737.
//!
//! The responder creates short-lived, self-signed challenge certificates with
//! one DNS SAN and the critical `id-pe-acmeIdentifier` extension. It selects a
//! certificate only when SNI and `acme-tls/1` are both present.
use crate::commands::cert::validation::{
    Arc, ChallengeKind, ChallengeSolver, IssueError, Progress, listener::Listener,
};
use crate::common::output::MessageKind;
use aster_acme::{
    issuance::ValidationRequirement,
    solver::{ChallengePublication, CleanupResult, ExecutionContext, ReadyResult, RestoreResult},
};
use async_trait::async_trait;
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, crypto::CryptoProvider, sign::CertifiedKey};
use std::{collections::BTreeMap, fmt, net::SocketAddr, sync::RwLock};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

const ALPN: &[u8] = b"acme-tls/1";

pub(super) struct TlsAlpn {
    address: SocketAddr,
    progress: Arc<Progress>,
    listener: Mutex<Option<Listener>>,
    resolver: Arc<SniResolver>,
}

impl TlsAlpn {
    pub(super) fn new(address: SocketAddr, progress: Arc<Progress>) -> Self {
        Self {
            address,
            progress,
            listener: Mutex::new(None),
            resolver: Arc::new(SniResolver::default()),
        }
    }

    async fn publish(
        &self,
        requirements: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<(), IssueError> {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        let mut listener = self.listener.lock().await;
        self.resolver.publish(requirements)?;
        if execution.check().is_err() {
            self.resolver.clear();
            return Err(IssueError::Interrupted);
        }
        if let Some(active) = listener.as_ref() {
            if active.is_finished() {
                return Err(IssueError::Publication(
                    "TLS-ALPN listener stopped unexpectedly".into(),
                ));
            }
            return Ok(());
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| IssueError::InvalidInput("cannot configure TLS protocol versions"))?
            .with_no_client_auth()
            .with_cert_resolver(self.resolver.clone());
        config.alpn_protocols = vec![ALPN.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let active = Listener::bind(self.address, execution, move |stream| {
            let acceptor = acceptor.clone();
            async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    // RFC 8737 carries no application data after the handshake.
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
                }
            }
        })
        .await;
        let active = match active {
            Ok(active) => active,
            Err(error) => {
                // A failed bind must not leave temporary private challenge keys resident.
                self.resolver.clear();
                return Err(error);
            }
        };
        self.progress.output.progress(
            MessageKind::Info,
            &format!(
                "TLS-ALPN-01 listener started at {}; public port 443 must reach this socket",
                active.address
            ),
        );
        tracing::debug!(listen_address = %active.address, "Forward public TLS port 443 with original SNI to this listener; only acme-tls/1 is accepted");
        *listener = Some(active);
        Ok(())
    }
}

#[async_trait]
impl ChallengeSolver for TlsAlpn {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::TlsAlpn01
    }
    async fn ready(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<ReadyResult, IssueError> {
        let requirements = publications
            .iter()
            .map(|publication| publication.requirement.clone())
            .collect::<Vec<_>>();
        self.publish(&requirements, execution).await?;
        Ok(ReadyResult {
            ready: true,
            ..ReadyResult::default()
        })
    }
    async fn restore(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<RestoreResult, IssueError> {
        let requirements = publications
            .iter()
            .map(|publication| publication.requirement.clone())
            .collect::<Vec<_>>();
        self.publish(&requirements, execution).await?;
        Ok(RestoreResult::default())
    }
    async fn cleanup(
        &self,
        publications: &[ChallengePublication],
        _: &ExecutionContext,
    ) -> Result<CleanupResult, IssueError> {
        self.shutdown().await;
        Ok(CleanupResult {
            completed: publications
                .iter()
                .map(|publication| publication.publication_id.clone())
                .collect(),
            failure: None,
            retry_at: None,
        })
    }
    async fn shutdown(&self) {
        let listener = self.listener.lock().await.take();
        if let Some(listener) = listener {
            let address = listener.address;
            listener.shutdown().await;
            self.progress.output.progress(
                MessageKind::Info,
                &format!("TLS-ALPN-01 listener stopped at {address}"),
            );
        }
        self.resolver.clear();
    }
}

struct Entry {
    digest: [u8; 32],
    certificate: Arc<CertifiedKey>,
}

#[derive(Default)]
struct SniResolver {
    certificates: RwLock<BTreeMap<String, Entry>>,
}

impl fmt::Debug for SniResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SniResolver")
            .finish_non_exhaustive()
    }
}

impl SniResolver {
    /// Validate and construct every new entry before changing the active table.
    /// Repeated publication keeps keys stable; conflicting digests never replace
    /// an active challenge and new SANs become visible to later handshakes.
    fn publish(&self, requirements: &[ValidationRequirement]) -> Result<(), IssueError> {
        let desired = validated_requirements(requirements)?;
        let mut entries = self
            .certificates
            .write()
            .map_err(|_| IssueError::Publication("TLS challenge table is unavailable".into()))?;
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let mut additions = BTreeMap::new();
        for (domain, digest) in desired {
            if let Some(entry) = entries.get(&domain) {
                if entry.digest != digest {
                    return Err(IssueError::InvalidInput(
                        "TLS-ALPN challenge digest changed",
                    ));
                }
            } else {
                additions.insert(
                    domain.clone(),
                    Entry {
                        digest,
                        certificate: certificate(&domain, &digest, &provider)?,
                    },
                );
            }
        }
        if entries.len() + additions.len() > 100 {
            return Err(IssueError::InvalidInput("too many TLS-ALPN domains"));
        }
        entries.extend(additions);
        Ok(())
    }

    fn clear(&self) {
        if let Ok(mut entries) = self.certificates.write() {
            entries.clear();
        }
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let has_alpn = hello
            .alpn()
            .is_some_and(|protocols| protocols.into_iter().any(|protocol| protocol == ALPN));
        if !has_alpn {
            return None;
        }
        let name = hello
            .server_name()?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        self.certificates
            .read()
            .ok()?
            .get(&name)
            .map(|entry| entry.certificate.clone())
    }
}

fn validated_requirements(
    requirements: &[ValidationRequirement],
) -> Result<BTreeMap<String, [u8; 32]>, IssueError> {
    if requirements.is_empty() || requirements.len() > 100 {
        return Err(IssueError::InvalidInput(
            "TLS-ALPN requires 1 to 100 challenge requirements",
        ));
    }
    let mut result = BTreeMap::new();
    for requirement in requirements {
        let ValidationRequirement::TlsAlpn01 { domain, digest } = requirement else {
            return Err(IssueError::InvalidInput(
                "TLS-ALPN received another validation method",
            ));
        };
        let identifier = aster_acme::identifier::DnsIdentifier::new(domain)?;
        if identifier.is_wildcard() {
            return Err(IssueError::InvalidInput(
                "TLS-ALPN does not support wildcard identifiers",
            ));
        }
        if result.insert(identifier.value(), *digest).is_some() {
            return Err(IssueError::InvalidInput("duplicate TLS-ALPN domain"));
        }
    }
    Ok(result)
}

fn certificate(
    domain: &str,
    digest: &[u8; 32],
    provider: &CryptoProvider,
) -> Result<Arc<CertifiedKey>, IssueError> {
    let mut params = CertificateParams::new(vec![domain.to_owned()])
        .map_err(|_| IssueError::InvalidInput("invalid TLS-ALPN DNS identifier"))?;
    params.distinguished_name = DistinguishedName::new();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(7);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(digest));
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|_| IssueError::InvalidInput("TLS-ALPN key generation failed"))?;
    let certificate = params
        .self_signed(&key)
        .map_err(|_| IssueError::InvalidInput("TLS-ALPN certificate generation failed"))?;
    let private_key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            key.serialize_der(),
        )))
        .map_err(|_| IssueError::InvalidInput("TLS-ALPN private key generation failed"))?;
    // CertifiedKey::from_der uses generic PKIX parsing, which rejects the
    // required critical ACME extension. The cert was self-signed by this exact
    // generated key, so package its public DER and signer directly.
    let certified = CertifiedKey::new(
        vec![CertificateDer::from(certificate.der().to_vec())],
        private_key,
    );
    Ok(Arc::new(certified))
}

impl fmt::Debug for TlsAlpn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsAlpn")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests;
