//! Real account orchestration with explicit loopback transport and durable files.
use crate::commands::account::args::{AccountArgs, AccountCommand};
use crate::commands::account::execute::{Operation, remote};
use crate::commands::account::mutation::update_with_transport;
use crate::commands::account::render;
use crate::commands::account::report::AccountReport;
use crate::common::context::{CliSettings, CommandContext};
use aster_acme::account::AccountRecord;
use aster_acme::storage::account::AccountKeyStore;
use aster_acme::transport::TransportOptions;
use aster_acme_cli_storage::account::CliAccountStore;
use aster_acme_protocol::jws::FlattenedJws;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::Duration;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

struct Fixture {
    temp: tempfile::TempDir,
    server: MockServer,
}

impl Fixture {
    async fn new() -> Self {
        Self {
            temp: tempfile::tempdir().unwrap(),
            server: MockServer::start().await,
        }
    }

    async fn mount(&self, terms: Option<&str>, existing: bool) {
        self.server.reset().await;
        let mut directory = serde_json::json!({
            "newNonce": format!("{}/nonce", self.server.uri()),
            "newAccount": format!("{}/new-account", self.server.uri()),
            "keyChange": format!("{}/key-change", self.server.uri())
        });
        if let Some(terms) = terms {
            directory["meta"] = serde_json::json!({"termsOfService":terms});
        }
        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(ResponseTemplate::new(200).set_body_json(directory))
            .mount(&self.server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(204).insert_header("Replay-Nonce", "initial"))
            .mount(&self.server)
            .await;
        let location = format!("{}/identity", self.server.uri());
        let metadata = self.temp.path().join("accounts/work/account.toml");
        Mock::given(method("POST")).and(path("/new-account"))
            .respond_with(move |request: &wiremock::Request| {
                let jws: FlattenedJws = serde_json::from_slice(&request.body).unwrap();
                let payload: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
                if payload["onlyReturnExisting"] == true && !existing {
                    return ResponseTemplate::new(400).insert_header("Replay-Nonce", "lookup")
                        .set_body_json(serde_json::json!({"type":"urn:ietf:params:acme:error:accountDoesNotExist"}));
                }
                if payload["onlyReturnExisting"] != true {
                    let saved: toml::Value = toml::from_str(&std::fs::read_to_string(&metadata).unwrap()).unwrap();
                    assert_eq!(payload["termsOfServiceAgreed"].as_bool(), saved["account"].get("accepted_terms_url").map(|_| true));
                }
                ResponseTemplate::new(if existing { 200 } else { 201 })
                    .insert_header("Replay-Nonce", "registered").insert_header("Location", &location)
                    .set_body_json(serde_json::json!({"status":"valid"}))
            }).mount(&self.server).await;
        Mock::given(method("POST"))
            .and(path("/identity"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Replay-Nonce", "observed")
                    .set_body_json(serde_json::json!({"status":"valid"})),
            )
            .mount(&self.server)
            .await;
    }

    fn options(&self) -> AccountArgs {
        AccountArgs {
            name: Some("work".into()),
            data_dir: Some(self.temp.path().into()),
            ca_directory: Some(format!("{}/directory", self.server.uri())),
            json: true,
            yes: true,
            ..AccountArgs::default()
        }
    }

    async fn run(
        &self,
        options: AccountArgs,
        operation: Operation,
    ) -> crate::common::error::CliResult<AccountReport> {
        let context = CliSettings::load(&options).await?.account(&options).await?;
        let reused = context.store.metadata().await?.is_some();
        let signer = context
            .store
            .signer(&context.directory, "work", operation.key_access(None))
            .await?;
        // The command's production HTTP policy stays unchanged. Only this fixture
        // explicitly permits its loopback CA, through the same transport contract.
        remote(
            context,
            signer,
            options,
            operation,
            reused,
            TransportOptions {
                allow_loopback_http: true,
                ..TransportOptions::default()
            },
            &CommandContext::new(true),
        )
        .await
    }

    fn store(&self) -> CliAccountStore {
        CliAccountStore::open(self.temp.path(), "work", Duration::from_secs(1)).unwrap()
    }

    async fn context(&self) -> crate::common::context::CliContext {
        let options = self.options();
        CliSettings::load(&options)
            .await
            .unwrap()
            .account(&options)
            .await
            .unwrap()
    }

    fn network_args(&self) -> crate::commands::account::args::NetworkArgs {
        use crate::commands::account::args::{CaArgs, NameArgs, NetworkArgs};
        use crate::common::args::{HttpArgs, LocalArgs};
        NetworkArgs {
            identity: NameArgs {
                name: Some("work".into()),
                ..NameArgs::default()
            },
            ca: CaArgs {
                ca_directory: Some(format!("{}/directory", self.server.uri())),
                ..CaArgs::default()
            },
            http: HttpArgs::default(),
            local: LocalArgs {
                data_dir: Some(self.temp.path().into()),
                json: true,
            },
        }
    }

    fn update_args(
        &self,
        enable: bool,
        disable: bool,
    ) -> crate::commands::account::args::UpdateArgs {
        crate::commands::account::args::UpdateArgs {
            network: self.network_args(),
            auto_accept_new_terms: enable,
            clear_auto_accept_new_terms: disable,
            yes: true,
            ..Default::default()
        }
    }

    async fn record(&self) -> AccountRecord {
        self.store().metadata().await.unwrap().unwrap()
    }

    async fn posts(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count()
    }
}

#[tokio::test]
async fn first_acceptance_is_not_an_update_and_delegation_survives_restart_and_changed_terms() {
    let fixture = Fixture::new().await;
    fixture
        .mount(Some("https://ca.example/terms/one"), false)
        .await;
    let mut options = fixture.options();
    options.auto_accept_new_terms = true;
    options.contact = vec!["admin@example.com".into()];
    let first = fixture.run(options, Operation::Register).await.unwrap();
    assert_eq!(
        render::tests::json_value(&first)["auto_accepted_terms"],
        false
    );
    assert!(
        !render::render(&first, crate::common::session::Format::plain(false))
            .unwrap()
            .contains("updated CA terms")
    );
    assert!(fixture.record().await.auto_accept_terms_updates);
    assert_eq!(fixture.posts().await, 2);
    assert_eq!(
        crate::config::load(fixture.temp.path())
            .await
            .unwrap()
            .default_account
            .as_deref(),
        Some("default")
    );
    let key = std::fs::read(fixture.temp.path().join("accounts/work/account-key.pk8")).unwrap();
    fixture
        .mount(
            Some("https://different.example/terms/two?version=%41"),
            true,
        )
        .await;
    let update = fixture
        .run(fixture.options(), Operation::Register)
        .await
        .unwrap();
    assert_eq!(
        render::tests::json_value(&update)["auto_accepted_terms"],
        true
    );
    assert!(
        render::render(&update, crate::common::session::Format::plain(false))
            .unwrap()
            .contains("Automatically accepted the updated CA terms")
    );
    let record = fixture.record().await;
    assert_eq!(
        record.accepted_terms_url.as_ref().unwrap().as_str(),
        "https://different.example/terms/two?version=%41"
    );
    assert!(record.auto_accept_terms_updates);
    assert_eq!(record.contacts, ["mailto:admin@example.com"]);
    assert_eq!(
        std::fs::read(fixture.temp.path().join("accounts/work/account-key.pk8")).unwrap(),
        key
    );
    let unchanged = fixture
        .run(fixture.options(), Operation::Register)
        .await
        .unwrap();
    assert_eq!(
        render::tests::json_value(&unchanged)["auto_accepted_terms"],
        false
    );
    let shown = crate::commands::account::execute::execute(
        crate::commands::account::args::AccountCommand::Show {
            verify: false,
            profiles: false,
            options: crate::commands::account::args::NetworkArgs::from(fixture.options()),
        },
        &CommandContext::new(true),
    )
    .await
    .unwrap();
    let json = render::tests::json_value(&shown);
    assert_eq!(json["auto_accept_terms_updates"], true);
    assert_eq!(
        json["accepted_terms_url"],
        "https://different.example/terms/two?version=%41"
    );
    assert!(
        render::render(&shown, crate::common::session::Format::plain(false))
            .unwrap()
            .contains("enabled")
    );
}

#[tokio::test]
async fn unapproved_updates_fail_without_posts_or_metadata_changes_then_explicit_opt_in_persists() {
    let fixture = Fixture::new().await;
    fixture
        .mount(Some("https://ca.example/terms/one"), false)
        .await;
    let mut options = fixture.options();
    options.accept_terms = true;
    fixture.run(options, Operation::Register).await.unwrap();
    assert!(!fixture.record().await.auto_accept_terms_updates);
    fixture
        .mount(Some("https://ca.example/terms/two"), true)
        .await;
    let before = std::fs::read(fixture.temp.path().join("accounts/work/account.toml")).unwrap();
    let error = fixture
        .run(fixture.options(), Operation::Register)
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("https://ca.example/terms/two"));
    assert_eq!(fixture.posts().await, 0);
    assert_eq!(
        std::fs::read(fixture.temp.path().join("accounts/work/account.toml")).unwrap(),
        before
    );
    let mut options = fixture.options();
    options.auto_accept_new_terms = true;
    let report = fixture.run(options, Operation::Register).await.unwrap();
    assert_eq!(
        render::tests::json_value(&report)["auto_accepted_terms"],
        true
    );
    assert!(fixture.record().await.auto_accept_terms_updates);
}

#[tokio::test]
async fn no_terms_and_recovery_do_not_invent_an_update_or_grant_consent() {
    for opt_in in [false, true] {
        let fixture = Fixture::new().await;
        fixture.mount(None, false).await;
        let mut options = fixture.options();
        options.auto_accept_new_terms = opt_in;
        let report = fixture.run(options, Operation::Register).await.unwrap();
        assert_eq!(
            render::tests::json_value(&report)["auto_accepted_terms"],
            false
        );
        assert_eq!(fixture.record().await.auto_accept_terms_updates, opt_in);
        assert_eq!(fixture.record().await.accepted_terms_url, None);
        fixture
            .mount(Some("https://ca.example/new-terms"), true)
            .await;
        let recovered = fixture
            .run(fixture.options(), Operation::Recover)
            .await
            .unwrap();
        assert_eq!(
            render::tests::json_value(&recovered)["auto_accepted_terms"],
            false
        );
        assert_eq!(render::tests::json_value(&recovered)["recovered"], true);
        assert_eq!(fixture.record().await.auto_accept_terms_updates, opt_in);
        assert_eq!(fixture.record().await.accepted_terms_url, None);
    }
}

#[tokio::test]
async fn authorized_account_reports_first_terms_url_when_ca_adds_terms_later() {
    let fixture = Fixture::new().await;
    fixture.mount(None, false).await;
    let mut options = fixture.options();
    options.auto_accept_new_terms = true;
    let first = fixture.run(options, Operation::Register).await.unwrap();
    assert_eq!(
        render::tests::json_value(&first)["auto_accepted_terms"],
        false
    );
    assert!(fixture.record().await.auto_accept_terms_updates);
    assert_eq!(fixture.record().await.accepted_terms_url, None);

    fixture
        .mount(Some("https://ca.example/terms/first-published"), true)
        .await;
    let report = fixture
        .run(fixture.options(), Operation::Register)
        .await
        .unwrap();
    assert_eq!(
        render::tests::json_value(&report)["auto_accepted_terms"],
        true
    );
    assert!(
        render::render(&report, crate::common::session::Format::plain(false))
            .unwrap()
            .contains("Automatically accepted the updated CA terms")
    );
    assert_eq!(
        fixture.record().await.accepted_terms_url.unwrap().as_str(),
        "https://ca.example/terms/first-published"
    );
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "native PTY registration-consent fixture"]
async fn terminal_terms_consent_child() {
    let mode = std::env::var("ASTER_ACCOUNT_TERMS_TEST_MODE").unwrap();
    let fixture = Fixture::new().await;
    fixture
        .mount(Some("https://ca.example/terms/one"), false)
        .await;
    let mut options = fixture.options();
    options.json = false;
    options.contact = vec!["admin@example.com".into()];
    options.yes = mode == "yes";
    options.accept_terms = mode == "yes";
    let result = fixture.run(options, Operation::Register).await;
    if mode == "cancel" {
        assert!(
            result
                .err()
                .unwrap()
                .is::<crate::common::terminal::Canceled>()
        );
        assert_eq!(fixture.posts().await, 0);
        assert!(!fixture.record().await.auto_accept_terms_updates);
        assert_eq!(fixture.record().await.accepted_terms_url, None);
    } else {
        let report = result.unwrap();
        assert_eq!(
            render::tests::json_value(&report)["auto_accepted_terms"],
            false
        );
        assert_eq!(
            fixture.record().await.auto_accept_terms_updates,
            mode == "grant"
        );
    }
    println!("ACCOUNT_TERMS_DONE {mode}");
}

#[tokio::test]
async fn contact_updates_preserve_terms_delegation_without_reporting_automatic_acceptance() {
    let fixture = Fixture::new().await;
    fixture
        .mount(Some("https://ca.example/terms/one"), false)
        .await;
    let mut options = fixture.options();
    options.auto_accept_new_terms = true;
    fixture.run(options, Operation::Register).await.unwrap();
    fixture
        .mount(Some("https://ca.example/terms/two"), true)
        .await;
    let options = fixture.options();
    let context = CliSettings::load(&options)
        .await
        .unwrap()
        .account(&options)
        .await
        .unwrap();
    let signer = context
        .store
        .signer(
            &context.directory,
            "work",
            aster_acme::storage::account::KeyAccess::Existing,
        )
        .await
        .unwrap();
    let before = fixture.record().await;
    let contacts = vec!["mailto:new@example.com".to_owned()];
    let report = crate::commands::account::mutation::submit_contacts(
        &context,
        signer,
        contacts.clone(),
        TransportOptions {
            allow_loopback_http: true,
            ..TransportOptions::default()
        },
        &CommandContext::new(true),
    )
    .await
    .unwrap();
    let json = render::tests::json_value(&report);
    assert_eq!(json["action"], "update_contact");
    assert_eq!(json["auto_accepted_terms"], false);
    let after = fixture.record().await;
    assert!(after.auto_accept_terms_updates);
    assert_eq!(after.accepted_terms_url, before.accepted_terms_url);
    assert_eq!(after.contacts, contacts);
    let requests = fixture.server.received_requests().await.unwrap();
    let posts: Vec<_> = requests.iter().filter(|r| r.method == "POST").collect();
    assert_eq!(posts.len(), 1);
    let jws: FlattenedJws = serde_json::from_slice(&posts[0].body).unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jws.payload).unwrap()).unwrap();
    assert_eq!(
        payload,
        serde_json::json!({"contact":["mailto:new@example.com"]})
    );
}

/// Enabling the delegation must survive a later terms change without prompting
/// and must never send a CA account request while it is applied.
#[tokio::test]
async fn enabled_delegation_unblocks_ensure_after_a_terms_change() {
    let fixture = Fixture::new().await;
    fixture
        .mount(Some("https://ca.example/terms/one"), false)
        .await;
    let mut options = fixture.options();
    options.contact = vec!["admin@example.com".into()];
    options.accept_terms = true;
    fixture.run(options, Operation::Register).await.unwrap();
    assert!(!fixture.record().await.auto_accept_terms_updates);

    let context = fixture.context().await;
    let before = fixture.posts().await;
    let report = update_with_transport(
        fixture.update_args(true, false),
        &context,
        TransportOptions {
            allow_loopback_http: true,
            ..TransportOptions::default()
        },
        &CommandContext::new(true),
    )
    .await
    .unwrap();
    let json = render::tests::json_value(&report);
    assert_eq!(json["auto_accept_terms_updates"], true);
    assert_eq!(json["accepted_terms_url"], "https://ca.example/terms/one");
    assert_eq!(json["ca_account_update_sent"], false);
    assert_eq!(json["directory_checked"], true);
    assert_eq!(
        fixture.posts().await,
        before,
        "enabling sends no CA account POST"
    );
    assert!(fixture.record().await.auto_accept_terms_updates);

    fixture
        .mount(Some("https://ca.example/terms/two"), true)
        .await;
    let ensure = fixture
        .run(fixture.options(), Operation::Register)
        .await
        .unwrap();
    assert_eq!(
        render::tests::json_value(&ensure)["auto_accepted_terms"],
        true
    );
    let record = fixture.record().await;
    assert!(record.auto_accept_terms_updates);
    assert_eq!(
        record.accepted_terms_url.as_ref().unwrap().as_str(),
        "https://ca.example/terms/two"
    );

    let shown = crate::commands::account::execute::execute(
        AccountCommand::Show {
            verify: false,
            profiles: false,
            options: fixture.network_args(),
        },
        &CommandContext::new(true),
    )
    .await
    .unwrap();
    let json = render::tests::json_value(&shown);
    assert_eq!(json["auto_accept_terms_updates"], true);
    assert_eq!(json["accepted_terms_url"], "https://ca.example/terms/two");
    assert!(
        render::render(&shown, crate::common::session::Format::plain(false))
            .unwrap()
            .contains("enabled")
    );
}

/// After revoking the delegation a changed URL must block the unattended
/// ensure before any POST, while the last accepted URL stays recorded.
#[tokio::test]
async fn disabled_delegation_blocks_ensure_until_explicit_consent() {
    let fixture = Fixture::new().await;
    fixture
        .mount(Some("https://ca.example/terms/one"), false)
        .await;
    let mut options = fixture.options();
    options.accept_terms = true;
    fixture.run(options, Operation::Register).await.unwrap();
    let context = fixture.context().await;
    let transport = TransportOptions {
        allow_loopback_http: true,
        ..TransportOptions::default()
    };
    update_with_transport(
        fixture.update_args(true, false),
        &context,
        transport.clone(),
        &CommandContext::new(true),
    )
    .await
    .unwrap();
    update_with_transport(
        fixture.update_args(false, true),
        &context,
        transport,
        &CommandContext::new(true),
    )
    .await
    .unwrap();
    let record = fixture.record().await;
    assert!(!record.auto_accept_terms_updates);
    assert_eq!(
        record.accepted_terms_url.as_ref().unwrap().as_str(),
        "https://ca.example/terms/one"
    );

    fixture
        .mount(Some("https://ca.example/terms/two"), true)
        .await;
    let error = fixture
        .run(fixture.options(), Operation::Register)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("https://ca.example/terms/two"), "{error}");
    assert_eq!(fixture.posts().await, 0, "no POST before explicit consent");
    let record = fixture.record().await;
    assert!(!record.auto_accept_terms_updates);
    assert_eq!(
        record.accepted_terms_url.as_ref().unwrap().as_str(),
        "https://ca.example/terms/one"
    );
}
