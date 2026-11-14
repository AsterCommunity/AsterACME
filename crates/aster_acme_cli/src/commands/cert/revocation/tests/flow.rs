//! Real journals, absent accounts/CSR, and the production CLI preparation transaction.
use crate::{
    app::{Args, Command},
    commands::cert::{
        args::{CertCommand, RevokeArgs},
        revocation::{
            self,
            preparation::{self, Prepared},
        },
    },
    common::{
        context::{CliSettings, CommandContext},
        session::OutputSession,
    },
};
use aster_acme::{
    crypto::key_algorithm::KeyAlgorithm,
    identifier::DnsIdentifier,
    issuance::{CertificateName, IssueRecord, IssueRequest},
    solver::ExecutionContext,
    storage::{
        account::{AccountKeyStore, AccountStore, KeyAccess},
        issuance::IssueStore,
        revocation::RevocationSession,
    },
    transport::{HttpPool, TransportOptions},
};
use aster_acme_cli_storage::{account::CliAccountStore, issuance::CliIssueStore};
use aster_acme_core::{
    account::AccountRecordState, protocol::AccountStatus, revocation::RevocationState,
    workflow::IssuancePhase,
};
use aster_acme_protocol::{jws::FlattenedJws, url::AcmeUrl};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser as _;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct Fixture {
    temp: tempfile::TempDir,
    server: MockServer,
    store: CliIssueStore,
    record: IssueRecord,
    key: Vec<u8>,
    generation: PathBuf,
}
impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let server = MockServer::start().await;
        let directory = AcmeUrl::new(&format!("{}/directory", server.uri())).unwrap();
        let accounts =
            CliAccountStore::open(temp.path(), "issuer", Duration::from_secs(1)).unwrap();
        let signer = accounts
            .signer(&directory, "issuer", KeyAccess::Create(None))
            .await
            .unwrap();
        let mut account = accounts
            .load(&directory, &signer.jwk().unwrap().thumbprint().unwrap())
            .await
            .unwrap()
            .unwrap();
        account.state = AccountRecordState::Registered;
        account.last_status = Some(AccountStatus::Valid);
        account.account_url = Some(AcmeUrl::new(&format!("{}/account/1", server.uri())).unwrap());
        accounts.save(&account).await.unwrap();
        let store = CliIssueStore::new(temp.path().into(), Duration::from_millis(40));
        let request = IssueRequest {
            challenge: aster_acme::challenge::ChallengeKind::Http01,
            solver_id: "manual_http".into(),
            solver_config: serde_json::json!({}),
            name: CertificateName::new("web").unwrap(),
            identifiers: vec![DnsIdentifier::new("example.com").unwrap()],
            key_algorithm: KeyAlgorithm::EcdsaP256,
            account_name: "issuer".into(),
        };
        let session = store.create(&request, &account).await.unwrap();
        let mut record = session.record().await.unwrap();
        let generation = temp.path().join("certs/web").join(record.generation_name());
        let key = std::fs::read(generation.join("private-key.pk8")).unwrap();
        let leaf = certificate(&key, false);
        record.phase = IssuancePhase::Completed;
        let record = session.complete(&record, leaf.as_bytes()).await.unwrap();
        drop(session);
        Mock::given(method("GET")).and(path("/directory")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce":format!("{}/nonce",server.uri()),"newAccount":format!("{}/must-not-register",server.uri()),"revokeCert":format!("{}/revoke",server.uri())
        }))).mount(&server).await;
        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "fresh_nonce"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "revoked_nonce"))
            .mount(&server)
            .await;
        Self {
            temp,
            server,
            store,
            record,
            key,
            generation,
        }
    }
    fn settings(&self) -> CliSettings {
        CliSettings {
            config: crate::config::Config {
                default_account: Some("deliberately-missing".into()),
                ..crate::config::Config::default()
            },
            config_path: self.temp.path().join("config.toml"),
            data_dir: self.temp.path().into(),
        }
    }
    fn args(&self, mode: &str, yes: bool) -> RevokeArgs {
        let mut words = vec![
            "aster-acme",
            "cert",
            "revoke",
            "web",
            "--sign-with",
            mode,
            "--data-dir",
            self.temp.path().to_str().unwrap(),
            "--json",
        ];
        if yes {
            words.push("--yes");
        }
        let Command::Cert {
            command: CertCommand::Revoke(args),
        } = Args::try_parse_from(words).unwrap().command
        else {
            panic!("expected revoke");
        };
        args
    }
    fn cli() -> CommandContext {
        CommandContext {
            output: OutputSession::new(true),
            http: HttpPool::default(),
        }
    }
    fn execution() -> ExecutionContext {
        ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }
    async fn prepared(&self, mode: &str) -> preparation::PreparedRevocation {
        let prepared = preparation::prepare(
            &self.store,
            &self.settings(),
            &self.record,
            &self.args(mode, true),
            &Self::cli(),
            &Self::execution(),
        )
        .await
        .unwrap();
        let Prepared::Submit(prepared) = prepared else {
            panic!("expected submission");
        };
        *prepared
    }
    async fn submit(&self, mode: &str) -> IssueRecord {
        let prepared = Box::new(self.prepared(mode).await);
        let client = Arc::new(
            HttpPool::default()
                .discover(
                    self.record.directory.clone(),
                    TransportOptions {
                        allow_loopback_http: true,
                        ..TransportOptions::default()
                    },
                )
                .await
                .unwrap(),
        );
        prepared.submit(client, &Self::execution()).await.unwrap()
    }
    async fn posts(&self) -> Vec<wiremock::Request> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.method == "POST")
            .collect()
    }
}
fn certificate(key: &[u8], expired: bool) -> String {
    let key = rcgen::KeyPair::try_from(key).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(100);
    params.not_after = now + time::Duration::days(if expired { -1 } else { 89 });
    params.self_signed(&key).unwrap().pem()
}

#[tokio::test]
async fn certificate_key_mode_uses_saved_key_without_any_account_and_preserves_material() {
    let f = Fixture::new().await;
    std::fs::remove_dir_all(f.temp.path().join("accounts")).unwrap();
    let csr = std::fs::read(f.generation.join("request.der")).unwrap();
    let chain = std::fs::read(f.generation.join("fullchain.pem")).unwrap();
    let record = f.submit("certificate-key").await;
    assert_eq!(record.revocation.state, RevocationState::Confirmed);
    assert!(!f.temp.path().join("accounts").exists());
    assert_eq!(
        std::fs::read(f.generation.join("request.der")).unwrap(),
        csr
    );
    assert_eq!(
        std::fs::read(f.generation.join("private-key.pk8")).unwrap(),
        f.key
    );
    assert_eq!(
        std::fs::read(f.generation.join("fullchain.pem")).unwrap(),
        chain
    );
    let posts = f.posts().await;
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].url.path(), "/revoke");
    let jws: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.protected).unwrap()).unwrap();
    assert!(header.get("kid").is_none() && header.get("jwk").is_some());
    // Confirmed repeats need neither the removed account nor the now-removed certificate key.
    std::fs::remove_file(f.generation.join("private-key.pk8")).unwrap();
    revocation::execute(f.args("certificate-key", true), &Fixture::cli())
        .await
        .unwrap();
    revocation::execute(f.args("account", true), &Fixture::cli())
        .await
        .unwrap();
    assert_eq!(f.posts().await.len(), 1);
}

#[tokio::test]
async fn account_mode_needs_no_certificate_key_or_csr_and_can_revoke_expired_leaf() {
    let f = Fixture::new().await;
    std::fs::write(
        f.generation.join("fullchain.pem"),
        certificate(&f.key, true),
    )
    .unwrap();
    std::fs::remove_file(f.generation.join("private-key.pk8")).unwrap();
    std::fs::remove_file(f.generation.join("request.der")).unwrap();
    std::fs::remove_file(f.generation.join("material.sha256")).unwrap();
    let record = f.submit("account").await;
    assert_eq!(record.revocation.state, RevocationState::Confirmed);
    let posts = f.posts().await;
    assert_eq!(posts.len(), 1);
    let jws: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.protected).unwrap()).unwrap();
    assert!(header.get("jwk").is_none() && header.get("kid").is_some());
}

#[tokio::test]
async fn certificate_mode_needs_no_csr_and_accepts_expired_certificate() {
    let f = Fixture::new().await;
    std::fs::write(
        f.generation.join("fullchain.pem"),
        certificate(&f.key, true),
    )
    .unwrap();
    std::fs::remove_dir_all(f.temp.path().join("accounts")).unwrap();
    std::fs::remove_file(f.generation.join("request.der")).unwrap();
    std::fs::remove_file(f.generation.join("material.sha256")).unwrap();
    assert_eq!(
        f.submit("certificate-key").await.revocation.state,
        RevocationState::Confirmed
    );
}

#[tokio::test]
async fn missing_certificate_key_does_not_fall_back_to_an_account_and_confirmation_is_required() {
    let f = Fixture::new().await;
    let result = preparation::prepare(
        &f.store,
        &f.settings(),
        &f.record,
        &f.args("certificate-key", false),
        &Fixture::cli(),
        &Fixture::execution(),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(f.posts().await.len(), 0);
    std::fs::remove_file(f.generation.join("private-key.pk8")).unwrap();
    let result = preparation::prepare(
        &f.store,
        &f.settings(),
        &f.record,
        &f.args("certificate-key", true),
        &Fixture::cli(),
        &Fixture::execution(),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(f.posts().await.len(), 0);
    let session = f
        .store
        .open_revocation(&f.record.name, &f.record.operation_id)
        .await
        .unwrap();
    assert_eq!(
        session.revocation().await.unwrap().state,
        RevocationState::NotRequested
    );
}

#[tokio::test]
async fn lease_lives_through_preparation_and_replacement_after_confirmation_cannot_retarget_request()
 {
    let f = Fixture::new().await;
    let prepared = Box::new(f.prepared("certificate-key").await);
    assert!(
        f.store
            .open_revocation(&f.record.name, &f.record.operation_id)
            .await
            .is_err()
    );
    let other = rcgen::KeyPair::generate().unwrap();
    std::fs::write(
        f.generation.join("fullchain.pem"),
        certificate(&other.serialize_der(), false),
    )
    .unwrap();
    let client = Arc::new(
        HttpPool::default()
            .discover(
                f.record.directory.clone(),
                TransportOptions {
                    allow_loopback_http: true,
                    ..TransportOptions::default()
                },
            )
            .await
            .unwrap(),
    );
    assert!(
        prepared
            .submit(client, &Fixture::execution())
            .await
            .is_err()
    );
    assert_eq!(f.posts().await.len(), 0);
}

#[tokio::test]
async fn failed_target_key_binding_leaves_files_and_journal_untouched() {
    let f = Fixture::new().await;
    let other = rcgen::KeyPair::generate().unwrap();
    std::fs::write(f.generation.join("private-key.pk8"), other.serialize_der()).unwrap();
    let before = std::fs::read(f.generation.join("operation.toml")).unwrap();
    assert!(
        preparation::prepare(
            &f.store,
            &f.settings(),
            &f.record,
            &f.args("certificate-key", true),
            &Fixture::cli(),
            &Fixture::execution()
        )
        .await
        .is_err()
    );
    assert_eq!(f.posts().await.len(), 0);
    assert_eq!(
        std::fs::read(f.generation.join("operation.toml")).unwrap(),
        before
    );
}

#[tokio::test]
async fn pending_revocation_survives_reopen_keeps_reason_and_reports_actual_signer() {
    let f = Fixture::new().await;
    std::fs::remove_dir_all(f.temp.path().join("accounts")).unwrap();
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(ResponseTemplate::new(503).insert_header("Replay-Nonce", "uncertain_nonce"))
        .with_priority(2)
        .mount(&f.server)
        .await;
    let prepared = Box::new(f.prepared("certificate-key").await);
    let client = Arc::new(
        HttpPool::default()
            .discover(
                f.record.directory.clone(),
                TransportOptions {
                    allow_loopback_http: true,
                    ..TransportOptions::default()
                },
            )
            .await
            .unwrap(),
    );
    assert!(
        prepared
            .submit(client.clone(), &Fixture::execution())
            .await
            .is_err()
    );
    let session = f
        .store
        .open_revocation(&f.record.name, &f.record.operation_id)
        .await
        .unwrap();
    let pending = session.revocation().await.unwrap();
    assert_eq!(pending.state, RevocationState::Pending);
    drop(session);
    let mut changed = f.args("certificate-key", true);
    changed.reason = Some(aster_acme_protocol::revocation::RevocationReason::KeyCompromise);
    assert!(
        preparation::prepare(
            &f.store,
            &f.settings(),
            &f.record,
            &changed,
            &Fixture::cli(),
            &Fixture::execution()
        )
        .await
        .is_err()
    );
    assert_eq!(f.posts().await.len(), 1);
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("Replay-Nonce", "already_revoked_nonce")
                .set_body_json(
                    serde_json::json!({"type":"urn:ietf:params:acme:error:alreadyRevoked"}),
                ),
        )
        .with_priority(1)
        .mount(&f.server)
        .await;
    let prepared = Box::new(f.prepared("certificate-key").await);
    let record = prepared
        .submit(client, &Fixture::execution())
        .await
        .unwrap();
    assert_eq!(record.revocation.state, RevocationState::Confirmed);
    assert_eq!(record.revocation.requested_at, pending.requested_at);
    let text = crate::commands::cert::render::revoked(
        &record,
        crate::common::session::Format::plain(false),
    )
    .unwrap();
    assert!(text.contains("certificate-key"));
    let json: serde_json::Value = serde_json::from_str(
        &crate::commands::cert::render::revoked(
            &record,
            crate::common::session::Format::plain(true),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        json["operation"]["revocation"]["signer"]["method"],
        "certificate-key"
    );
    assert!(
        json["operation"]["revocation"]["certificate_sha256"]
            .as_str()
            .is_some()
    );
}

#[tokio::test]
async fn unsafe_or_corrupt_revocation_files_are_rejected_without_network_or_file_changes() {
    for object in ["fullchain.pem", "private-key.pk8"] {
        let f = Fixture::new().await;
        let checkpoint = std::fs::read(f.generation.join("operation.toml")).unwrap();
        std::fs::write(
            f.generation.join(object),
            b"not valid certificate or key material",
        )
        .unwrap();
        assert!(
            preparation::prepare(
                &f.store,
                &f.settings(),
                &f.record,
                &f.args("certificate-key", true),
                &Fixture::cli(),
                &Fixture::execution()
            )
            .await
            .is_err()
        );
        assert_eq!(f.posts().await.len(), 0);
        assert_eq!(
            std::fs::read(f.generation.join("operation.toml")).unwrap(),
            checkpoint
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn revocation_never_follows_key_or_certificate_symlinks() {
    for object in ["fullchain.pem", "private-key.pk8"] {
        let f = Fixture::new().await;
        let outside = f.temp.path().join("user-owned-copy");
        std::fs::copy(f.generation.join(object), &outside).unwrap();
        let before = std::fs::read(&outside).unwrap();
        std::fs::remove_file(f.generation.join(object)).unwrap();
        std::os::unix::fs::symlink(&outside, f.generation.join(object)).unwrap();
        assert!(
            preparation::prepare(
                &f.store,
                &f.settings(),
                &f.record,
                &f.args("certificate-key", true),
                &Fixture::cli(),
                &Fixture::execution()
            )
            .await
            .is_err()
        );
        assert_eq!(f.posts().await.len(), 0);
        assert_eq!(std::fs::read(&outside).unwrap(), before);
    }
}

#[tokio::test]
async fn explicit_reason_reaches_the_single_submission_transaction() {
    let f = Fixture::new().await;
    let mut args = f.args("certificate-key", true);
    args.reason = Some(aster_acme_protocol::revocation::RevocationReason::Superseded);
    let Prepared::Submit(prepared) = preparation::prepare(
        &f.store,
        &f.settings(),
        &f.record,
        &args,
        &Fixture::cli(),
        &Fixture::execution(),
    )
    .await
    .unwrap() else {
        panic!("expected submit");
    };
    let client = Arc::new(
        HttpPool::default()
            .discover(
                f.record.directory.clone(),
                TransportOptions {
                    allow_loopback_http: true,
                    ..TransportOptions::default()
                },
            )
            .await
            .unwrap(),
    );
    let record = prepared
        .submit(client, &Fixture::execution())
        .await
        .unwrap();
    assert_eq!(record.revocation.reason, args.reason);
    let posts = f.posts().await;
    let jws: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
    assert_eq!(payload["reason"], 4);
}
