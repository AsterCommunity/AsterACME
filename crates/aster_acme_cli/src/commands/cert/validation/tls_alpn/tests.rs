//! Real TLS handshakes and RFC 8737 challenge certificate checks.
use super::super::tests::{execution, progress};
use super::*;
use std::time::{Duration, Instant};

#[tokio::test]
async fn generates_one_critical_challenge_certificate_per_dns_name() {
    let requirements = vec![ValidationRequirement::TlsAlpn01 {
        domain: "Example.COM".into(),
        digest: [7; 32],
    }];
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let desired = validated_requirements(&requirements).unwrap();
    let map = desired
        .iter()
        .map(|(name, digest)| (name.clone(), certificate(name, digest, &provider).unwrap()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(map.len(), 1);
    let key = map.get("example.com").unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(key.cert[0].as_ref()).unwrap();
    assert!(cert.verify_signature(None).is_ok());
    assert!(cert.subject().iter_attributes().next().is_none());
    let san = cert.subject_alternative_name().unwrap().unwrap();
    assert_eq!(san.value.general_names.len(), 1);
    let extension = cert
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        .unwrap();
    assert!(extension.critical);
    assert_eq!(extension.value, [&[0x04, 0x20][..], &[7; 32][..]].concat());
}

#[tokio::test]
async fn rejects_mixed_methods_duplicate_names_and_non_dns_identifiers() {
    let mut duplicate = vec![
        ValidationRequirement::TlsAlpn01 {
            domain: "example.com".into(),
            digest: [1; 32],
        },
        ValidationRequirement::TlsAlpn01 {
            domain: "example.com".into(),
            digest: [2; 32],
        },
    ];
    assert!(validated_requirements(&duplicate).is_err());
    duplicate.push(ValidationRequirement::Http01 {
        url: "http://example.com/".into(),
        path: "/".into(),
        content: "x".into(),
    });
    assert!(validated_requirements(&duplicate).is_err());
    assert!(
        validated_requirements(&[ValidationRequirement::TlsAlpn01 {
            domain: "*.example.com".into(),
            digest: [1; 32]
        }])
        .is_err()
    );
    assert!(
        validated_requirements(&[ValidationRequirement::TlsAlpn01 {
            domain: "127.0.0.1".into(),
            digest: [1; 32]
        }])
        .is_err()
    );
    let solver = TlsAlpn::new(([127, 0, 0, 1], 0).into(), progress());
    assert!(solver.ready(&[], &execution()).await.is_err());
}

#[test]
fn resolver_incrementally_adds_material_and_rejects_digest_replacement() {
    let resolver = SniResolver::default();
    let first = ValidationRequirement::TlsAlpn01 {
        domain: "one.example".into(),
        digest: [1; 32],
    };
    let second = ValidationRequirement::TlsAlpn01 {
        domain: "two.example".into(),
        digest: [2; 32],
    };
    resolver.publish(std::slice::from_ref(&first)).unwrap();
    let original = resolver
        .certificates
        .read()
        .unwrap()
        .get("one.example")
        .unwrap()
        .certificate
        .clone();
    resolver.publish(&[first.clone(), second]).unwrap();
    let entries = resolver.certificates.read().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(Arc::ptr_eq(
        &original,
        &entries.get("one.example").unwrap().certificate
    ));
    drop(entries);
    let changed = ValidationRequirement::TlsAlpn01 {
        domain: "one.example".into(),
        digest: [9; 32],
    };
    assert!(resolver.publish(&[first, changed]).is_err());
    let entries = resolver.certificates.read().unwrap();
    assert_eq!(entries.get("one.example").unwrap().digest, [1; 32]);
    assert_eq!(entries.get("two.example").unwrap().digest, [2; 32]);
    assert!(resolver.publish(&[]).is_err());
    let too_many = (0..101)
        .map(|index| ValidationRequirement::TlsAlpn01 {
            domain: format!("{index}.example"),
            digest: [u8::try_from(index).unwrap(); 32],
        })
        .collect::<Vec<_>>();
    assert!(resolver.publish(&too_many).is_err());
}

#[tokio::test]
async fn occupied_socket_cancelled_or_expired_runs_leave_no_listener_or_challenge_material() {
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    let requirement = ValidationRequirement::TlsAlpn01 {
        domain: "example.com".into(),
        digest: [3; 32],
    };
    let solver = TlsAlpn::new(address, progress());
    assert!(matches!(
        solver
            .ready(std::slice::from_ref(&requirement), &execution())
            .await,
        Err(IssueError::Publication(_))
    ));
    assert!(solver.listener.lock().await.is_none());
    assert!(solver.resolver.certificates.read().unwrap().is_empty());
    solver.shutdown().await;
    assert!(tokio::net::TcpStream::connect(address).await.is_ok());
    drop(occupied);
    let rebound = tokio::net::TcpListener::bind(address).await.unwrap();
    drop(rebound);

    let cancelled = execution();
    cancelled.cancellation.cancel();
    let solver = TlsAlpn::new(([127, 0, 0, 1], 0).into(), progress());
    assert!(matches!(
        solver
            .ready(std::slice::from_ref(&requirement), &cancelled)
            .await,
        Err(IssueError::Interrupted)
    ));
    assert!(solver.listener.lock().await.is_none());
    assert!(solver.resolver.certificates.read().unwrap().is_empty());
    let expired = ExecutionContext {
        deadline: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
        ..execution()
    };
    assert!(matches!(
        solver.restore(&[requirement], &expired).await,
        Err(IssueError::Interrupted)
    ));
    assert!(solver.listener.lock().await.is_none());
    assert!(solver.resolver.certificates.read().unwrap().is_empty());
    solver.shutdown().await;
}

#[tokio::test]
async fn cancelling_an_active_tls_handshake_closes_listener_and_idle_connection() {
    let requirement = ValidationRequirement::TlsAlpn01 {
        domain: "example.com".into(),
        digest: [5; 32],
    };
    let cancellation = tokio_util::sync::CancellationToken::new();
    let execution = ExecutionContext {
        cancellation: cancellation.clone(),
        deadline: Instant::now() + Duration::from_secs(30),
    };
    let solver = TlsAlpn::new(([127, 0, 0, 1], 0).into(), progress());
    solver
        .ready(std::slice::from_ref(&requirement), &execution)
        .await
        .unwrap();
    let address = solver.listener.lock().await.as_ref().unwrap().address;
    let mut idle = tokio::net::TcpStream::connect(address).await.unwrap();
    tokio::task::yield_now().await;
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if solver.listener.lock().await.as_ref().unwrap().is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    solver.shutdown().await;
    let rebound = tokio::net::TcpListener::bind(address).await.unwrap();
    drop(rebound);
    let mut bytes = [0; 1];
    let read = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut idle, &mut bytes),
    )
    .await
    .unwrap();
    assert!(match read {
        Ok(count) => count == 0,
        Err(_) => true,
    });
}

#[tokio::test]
async fn tls_handshake_requires_matching_sni_and_acme_alpn_and_serves_per_domain_certificates() {
    let requirements = vec![
        ValidationRequirement::TlsAlpn01 {
            domain: "first.example".into(),
            digest: [1; 32],
        },
        ValidationRequirement::TlsAlpn01 {
            domain: "second.example".into(),
            digest: [2; 32],
        },
    ];
    let solver = TlsAlpn::new(([127, 0, 0, 1], 0).into(), progress());
    solver.ready(&requirements, &execution()).await.unwrap();
    let address = solver.listener.lock().await.as_ref().unwrap().address;

    for (domain, digest) in [("first.example", [1; 32]), ("second.example", [2; 32])] {
        assert_valid_tls_alpn_certificate(address, domain, digest).await;
    }

    let first = requirements[0].clone();
    let third = ValidationRequirement::TlsAlpn01 {
        domain: "third.example".into(),
        digest: [3; 32],
    };
    solver
        .ready(&[first.clone(), third.clone()], &execution())
        .await
        .unwrap();
    assert_valid_tls_alpn_certificate(address, "third.example", [3; 32]).await;
    let changed = ValidationRequirement::TlsAlpn01 {
        domain: "first.example".into(),
        digest: [8; 32],
    };
    assert!(solver.ready(&[changed], &execution()).await.is_err());
    assert_valid_tls_alpn_certificate(address, "first.example", [1; 32]).await;

    assert_tls_client_rejected(address, "first.example", Some(b"http/1.1")).await;
    assert_tls_client_rejected(address, "unrequested.example", Some(ALPN)).await;
    assert_tls_client_rejected(address, "first.example", None).await;

    solver.shutdown().await;
    assert!(tokio::net::TcpListener::bind(address).await.is_ok());

    // A restarted invocation rebuilds ephemeral certificates from the same
    // persisted digest and binds the same saved socket without another CA ack.
    let resumed = TlsAlpn::new(address, progress());
    resumed.restore(&requirements, &execution()).await.unwrap();
    assert_valid_tls_alpn_certificate(address, "first.example", [1; 32]).await;
    resumed.cleanup(&requirements, &execution()).await.unwrap();
    assert!(tokio::net::TcpListener::bind(address).await.is_ok());
}

async fn assert_valid_tls_alpn_certificate(address: SocketAddr, domain: &str, digest: [u8; 32]) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let stream = tls_connect(address, domain, client_config(Some(ALPN), seen.clone()))
        .await
        .unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(ALPN));
    drop(stream);
    let der = seen.lock().unwrap().last().unwrap().clone();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    assert!(cert.verify_signature(None).is_ok());
    let san = cert.subject_alternative_name().unwrap().unwrap();
    assert_eq!(san.value.general_names.len(), 1);
    assert!(san.value.general_names.iter().any(|name| matches!(name, x509_parser::extensions::GeneralName::DNSName(value) if *value == domain)));
    let extension = cert
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        .unwrap();
    assert!(extension.critical);
    assert_eq!(extension.value, [&[0x04, 0x20][..], &digest[..]].concat());
}

async fn assert_tls_client_rejected(address: SocketAddr, domain: &str, alpn: Option<&[u8]>) {
    let config = client_config(alpn, Arc::new(std::sync::Mutex::new(Vec::new())));
    assert!(tls_connect(address, domain, config).await.is_err());
}

async fn tls_connect(
    address: SocketAddr,
    domain: &str,
    config: Arc<rustls::ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, std::io::Error> {
    let stream = tokio::net::TcpStream::connect(address).await?;
    let name = rustls::pki_types::ServerName::try_from(domain.to_owned())
        .map_err(std::io::Error::other)?;
    tokio_rustls::TlsConnector::from(config)
        .connect(name, stream)
        .await
        .map_err(std::io::Error::other)
}

pub(crate) async fn verify_challenge_certificate(
    address: SocketAddr,
    domain: &str,
    digest: [u8; 32],
) -> Result<(), String> {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let stream = tls_connect(address, domain, client_config(Some(ALPN), seen.clone()))
        .await
        .map_err(|error| error.to_string())?;
    if stream.get_ref().1.alpn_protocol() != Some(ALPN) {
        return Err("TLS listener selected the wrong ALPN".into());
    }
    drop(stream);
    let certificates = seen
        .lock()
        .map_err(|_| "captured certificate lock poisoned")?;
    let (_, cert) = x509_parser::parse_x509_certificate(
        certificates.last().ok_or("TLS peer sent no certificate")?,
    )
    .map_err(|error| error.to_string())?;
    cert.verify_signature(None)
        .map_err(|error| error.to_string())?;
    let names = cert
        .subject_alternative_name()
        .map_err(|error| error.to_string())?
        .ok_or("missing SAN")?;
    if names.value.general_names.len() != 1 || !names.value.general_names.iter().any(|name| matches!(name, x509_parser::extensions::GeneralName::DNSName(value) if *value == domain)) {
        return Err("challenge certificate SAN does not match SNI".into());
    }
    let extension = cert
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        .ok_or("missing acmeIdentifier")?;
    if !extension.critical || extension.value != [&[0x04, 0x20][..], &digest[..]].concat() {
        return Err("acmeIdentifier criticality or digest does not match".into());
    }
    Ok(())
}

fn client_config(
    alpn: Option<&[u8]>,
    seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(ChallengeVerifier {
        provider: provider.clone(),
        seen,
    });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    if let Some(alpn) = alpn {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    Arc::new(config)
}

#[derive(Debug)]
struct ChallengeVerifier {
    provider: Arc<CryptoProvider>,
    seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl rustls::client::danger::ServerCertVerifier for ChallengeVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.seen
            .lock()
            .map_err(|_| rustls::Error::General("test certificate capture lock poisoned".into()))?
            .push(cert.as_ref().to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // This test verifier intentionally bypasses PKIX parsing because the
        // RFC-mandated unknown critical extension is rejected by generic PKIX.
        // Tests independently inspect the exact self-signed challenge cert.
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
