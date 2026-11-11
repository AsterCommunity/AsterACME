//! Account command parsing, selection, offline inspection and network boundaries.
use super::args::AccountCommand;
use crate::app::{Args, Command};
use crate::common::args::{HttpArgs, LocalArgs};
use aster_acme::account::KeyAccess;
use aster_acme::crypto::key_algorithm::KeyAlgorithm;
use aster_acme_core::account::{AccountRecordState, DeactivationState};
use aster_acme_protocol::url::AcmeUrl;
use clap::Parser;

#[tokio::test]
async fn remove_requires_confirmation_clears_matching_default_and_never_connects() {
    use super::{args::RemoveArgs, execute, render};
    use aster_acme::account::AccountKeyStore;
    use aster_acme_cli_storage::CliAccountStore;
    use std::time::Duration;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ca = AcmeUrl::new(&format!(
        "https://{}/directory",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    crate::config::load(temp.path()).await.unwrap();
    crate::config::persist(
        temp.path().join("config.toml"),
        Some("personal".into()),
        None,
    )
    .await
    .unwrap();
    let store = CliAccountStore::open(temp.path(), "personal", Duration::from_secs(1)).unwrap();
    store
        .signer(&ca, "personal", KeyAccess::Create(None))
        .await
        .unwrap();
    let args = |yes| RemoveArgs {
        yes,
        target: super::args::LocalTargetArgs {
            identity: super::args::NameArgs {
                positional_name: Some("personal".into()),
                ..super::args::NameArgs::default()
            },
            local: LocalArgs {
                data_dir: Some(temp.path().into()),
                json: true,
            },
        },
    };
    let before = std::fs::read(temp.path().join("accounts/personal/account-key.pk8")).unwrap();
    assert!(
        execute::execute(
            AccountCommand::Remove(args(false)),
            &crate::common::context::CommandContext::new(true)
        )
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("--yes")
    );
    assert_eq!(
        std::fs::read(temp.path().join("accounts/personal/account-key.pk8")).unwrap(),
        before
    );
    let report = execute::execute(
        AccountCommand::Remove(args(true)),
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .unwrap();
    assert_eq!(render::tests::json_value(&report)["removed_locally"], true);
    assert_eq!(
        render::tests::json_value(&report)["ca_request_performed"],
        false
    );
    assert!(!temp.path().join("accounts/personal").exists());
    assert_eq!(
        crate::config::load(temp.path())
            .await
            .unwrap()
            .default_account,
        None
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[test]
fn list_http_options_require_explicit_verification() {
    for command in [
        vec!["aster-acme", "account", "list", "--timeout", "1"],
        vec!["aster-acme", "account", "list", "--user-agent", "client"],
    ] {
        assert!(Args::try_parse_from(command).is_err());
    }
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "account",
            "list",
            "--verify",
            "--timeout",
            "1",
            "--json"
        ])
        .is_ok()
    );
}

#[tokio::test]
async fn list_verification_continues_after_failures_and_returns_each_result() {
    use super::{args::ListArgs, execute, render};
    use aster_acme::account::AccountKeyStore;
    use aster_acme_cli_storage::CliAccountStore;
    use std::time::Duration;
    let temp = tempfile::tempdir().unwrap();
    let mut peers = Vec::new();
    for name in ["alpha", "zebra"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let directory = AcmeUrl::new(&format!(
            "https://{}/directory",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let store = CliAccountStore::open(temp.path(), name, Duration::from_secs(1)).unwrap();
        store
            .signer(&directory, name, KeyAccess::Create(None))
            .await
            .unwrap();
        peers.push(tokio::spawn(async move {
            let (stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .unwrap()
                .unwrap();
            drop(stream);
        }));
    }
    let report = execute::execute(
        AccountCommand::List(ListArgs {
            verify: true,
            http: HttpArgs {
                timeout: Some(1),
                ..HttpArgs::default()
            },
            local: LocalArgs {
                data_dir: Some(temp.path().into()),
                json: true,
            },
        }),
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .unwrap();
    for peer in peers {
        peer.await.unwrap();
    }
    assert!(report.has_failures());
    let value = render::tests::json_value(&report);
    assert_eq!(value["ca_query"]["refreshed"], 0);
    assert_eq!(value["verification"].as_array().unwrap().len(), 2);
    assert_eq!(value["verification"][0]["name"], "alpha");
    assert_eq!(value["verification"][1]["name"], "zebra");
    for result in value["verification"].as_array().unwrap() {
        assert!(result["error"].is_string());
    }
    assert!(
        render::render(&report, crate::common::session::Format::plain(false))
            .unwrap()
            .contains("verification failed")
    );
}

#[test]
fn all_single_account_commands_share_positional_and_named_targets() {
    use super::args::AccountArgs;
    for command in [
        "show",
        "switch",
        "register",
        "recover",
        "deactivate",
        "remove",
        "update-contact",
        "rotate-key",
    ] {
        for target in [vec!["work"], vec!["--name", "work"]] {
            let mut argv = vec!["aster-acme", "account", command];
            argv.extend(target);
            argv.push("--json");
            let parsed = Args::try_parse_from(argv).unwrap();
            let Command::Account { command } = parsed.command else {
                panic!("expected account");
            };
            let options: AccountArgs = match command {
                AccountCommand::Show { options, .. } | AccountCommand::Recover(options) => {
                    options.into()
                }
                AccountCommand::Switch(options) => options.into(),
                AccountCommand::Remove(options) => options.into(),
                AccountCommand::Register(options) => options.into(),
                AccountCommand::Deactivate(options) => options.into(),
                AccountCommand::UpdateContact(options) => options.network.into(),
                AccountCommand::RotateKey(options) => options.network.into(),
                AccountCommand::List(_) => panic!("list has no target"),
            };
            assert_eq!(options.name.as_deref(), Some("work"));
            assert!(options.json);
        }
        let conflict =
            Args::try_parse_from(["aster-acme", "account", command, "work", "--name", "other"]);
        assert!(matches!(
            conflict.err().unwrap().kind(),
            clap::error::ErrorKind::ArgumentConflict
        ));
        for invalid in ["", "../bad", "space name", &"x".repeat(65)] {
            assert!(Args::try_parse_from(["aster-acme", "account", command, invalid]).is_err());
            assert!(
                Args::try_parse_from(["aster-acme", "account", command, "--name", invalid])
                    .is_err()
            );
        }
    }
    assert!(Args::try_parse_from(["aster-acme", "account", "list", "work"]).is_err());
    assert!(Args::try_parse_from(["aster-acme", "account", "list", "--name", "work"]).is_err());
    assert!(Args::try_parse_from(["aster-acme", "version", "work"]).is_err());
    assert!(Args::try_parse_from(["aster-acme", "version", "--json"]).is_ok());
}

#[test]
fn list_and_deactivate_expose_only_their_own_arguments() {
    assert!(Args::try_parse_from(["aster-acme", "account", "list", "--json"]).is_ok());
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "account",
            "deactivate",
            "--name",
            "work",
            "--yes",
            "--json"
        ])
        .is_ok()
    );
    for flags in [
        vec!["--contact", "you@example.com"],
        vec!["--accept-terms"],
        vec!["--eab-kid", "id"],
        vec!["--verify"],
    ] {
        let mut command = vec!["aster-acme", "account", "deactivate"];
        command.extend(flags);
        assert!(Args::try_parse_from(command).is_err());
    }
    for flag in [
        "--name",
        "--ca",
        "--ca-directory",
        "--user-agent",
        "--timeout",
        "--yes",
        "--accept-terms",
    ] {
        assert!(Args::try_parse_from(["aster-acme", "account", "list", flag, "value"]).is_err());
    }
}

#[tokio::test]
async fn list_is_offline_sorted_marks_default_and_never_loads_keys() {
    use super::{execute, render};
    use aster_acme::account::{AccountKeyStore, AccountStore};
    use aster_acme_cli_storage::CliAccountStore;
    use std::time::Duration;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ca = AcmeUrl::new(&format!(
        "https://{}/directory",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    crate::config::load(temp.path()).await.unwrap();
    crate::config::persist(temp.path().join("config.toml"), Some("alpha".into()), None)
        .await
        .unwrap();
    for name in ["zebra", "alpha"] {
        let store = CliAccountStore::open(temp.path(), name, Duration::from_secs(1)).unwrap();
        let thumb = store
            .signer(&ca, name, KeyAccess::Create(None))
            .await
            .unwrap()
            .jwk()
            .unwrap()
            .thumbprint()
            .unwrap();
        if name == "alpha" {
            let mut record = store.load(&ca, &thumb).await.unwrap().unwrap();
            record.state = AccountRecordState::Registered;
            record.account_url = Some(AcmeUrl::new("https://ca.example/account/1").unwrap());
            store.save(&record).await.unwrap();
        }
        // Listing metadata remains useful even when a key needs restoration.
        std::fs::remove_file(temp.path().join(format!("accounts/{name}/account-key.pk8"))).unwrap();
    }
    let report = execute::execute(
        AccountCommand::List(
            LocalArgs {
                data_dir: Some(temp.path().into()),
                json: true,
            }
            .into(),
        ),
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .unwrap();
    let value = render::tests::json_value(&report);
    assert_eq!(value["ca_query"]["refreshed"], 0);
    assert_eq!(value["accounts"][0]["name"], "alpha");
    assert_eq!(value["accounts"][0]["is_default"], true);
    assert_eq!(value["accounts"][1]["local_state"], "registration_pending");
    assert!(
        render::render(&report, crate::common::session::Format::plain(false))
            .unwrap()
            .contains("* alpha")
    );
    assert!(
        !render::render(&report, crate::common::session::Format::plain(true))
            .unwrap()
            .contains('\x1b')
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn empty_list_is_actionable_and_stale_default_is_explicit() {
    use super::{execute, render};
    let temp = tempfile::tempdir().unwrap();
    let report = execute::execute(
        AccountCommand::List(
            LocalArgs {
                data_dir: Some(temp.path().into()),
                json: false,
            }
            .into(),
        ),
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .unwrap();
    assert_eq!(
        render::tests::json_value(&report)["accounts"],
        serde_json::json!([])
    );
    assert!(
        render::render(&report, crate::common::session::Format::plain(false))
            .unwrap()
            .contains("No local accounts")
    );
    assert!(!temp.path().join("accounts").exists());
}

#[tokio::test]
async fn deactivate_requires_confirmation_and_retains_identity_on_discovery_failure() {
    use super::{
        args::{AccountArgs, DeactivateArgs},
        execute,
    };
    use aster_acme::account::{AccountKeyStore, AccountStore};
    use aster_acme_cli_storage::CliAccountStore;
    use std::time::Duration;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ca = AcmeUrl::new(&format!(
        "https://{}/directory",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    crate::config::load(temp.path()).await.unwrap();
    let store = CliAccountStore::open(temp.path(), "default", Duration::from_secs(1)).unwrap();
    let thumb = store
        .signer(&ca, "default", KeyAccess::Create(None))
        .await
        .unwrap()
        .jwk()
        .unwrap()
        .thumbprint()
        .unwrap();
    let mut record = store.load(&ca, &thumb).await.unwrap().unwrap();
    record.state = AccountRecordState::Registered;
    record.account_url = Some(AcmeUrl::new("https://ca.example/account/1").unwrap());
    store.save(&record).await.unwrap();
    let paths = [
        temp.path().join("config.toml"),
        temp.path().join("accounts/default/account.toml"),
        temp.path().join("accounts/default/account-key.pk8"),
    ];
    let before = paths.each_ref().map(|path| std::fs::read(path).unwrap());
    let args = |yes| DeactivateArgs {
        yes,
        network: AccountArgs {
            data_dir: Some(temp.path().into()),
            name: Some("default".into()),
            json: true,
            timeout: Some(1),
            ..AccountArgs::default()
        }
        .into(),
    };
    let error = execute::execute(
        AccountCommand::Deactivate(args(false)),
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .err()
    .unwrap()
    .to_string();
    assert!(
        error.contains("cannot be undone")
            && error.contains("--yes")
            && error.contains("default")
            && error.contains("https://ca.example/account/1")
    );
    assert_eq!(
        paths.each_ref().map(|path| std::fs::read(path).unwrap()),
        before
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let peer = tokio::spawn(async move {
        let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        drop(stream);
    });
    assert!(
        execute::execute(
            AccountCommand::Deactivate(args(true)),
            &crate::common::context::CommandContext::new(true)
        )
        .await
        .is_err()
    );
    peer.await.unwrap();
    assert_eq!(
        store.load(&ca, &thumb).await.unwrap().unwrap().deactivation,
        DeactivationState::NotRequested
    );
    assert_eq!(std::fs::read(&paths[2]).unwrap(), before[2]);
}

#[tokio::test]
async fn confirmed_deactivation_is_local_and_cannot_be_switched_to_active_use() {
    use super::{
        args::{AccountArgs, DeactivateArgs},
        execute, render,
    };
    use aster_acme::account::{AccountKeyStore, AccountStore};
    use aster_acme_cli_storage::CliAccountStore;
    use std::time::Duration;
    let ca = AcmeUrl::new("https://unreachable.invalid/directory").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = CliAccountStore::open(temp.path(), "old", Duration::from_secs(1)).unwrap();
    let thumb = store
        .signer(&ca, "old", KeyAccess::Create(None))
        .await
        .unwrap()
        .jwk()
        .unwrap()
        .thumbprint()
        .unwrap();
    let mut record = store.load(&ca, &thumb).await.unwrap().unwrap();
    record.state = AccountRecordState::Registered;
    record.account_url = Some(AcmeUrl::new("https://unreachable.invalid/account/1").unwrap());
    record.last_status = Some(aster_acme_core::protocol::AccountStatus::Deactivated);
    record.deactivation = DeactivationState::Confirmed;
    store.save(&record).await.unwrap();
    let report = execute::execute(
        AccountCommand::Deactivate(DeactivateArgs {
            yes: false,
            network: AccountArgs {
                name: Some("old".into()),
                data_dir: Some(temp.path().into()),
                json: true,
                ..AccountArgs::default()
            }
            .into(),
        }),
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .unwrap();
    assert_eq!(render::tests::json_value(&report)["verified"], false);
    assert_eq!(render::tests::json_value(&report)["deactivated"], true);
    assert!(
        execute::execute(
            AccountCommand::Switch(super::args::LocalTargetArgs {
                identity: super::args::NameArgs {
                    positional_name: Some("old".into()),
                    ..super::args::NameArgs::default()
                },
                local: LocalArgs {
                    data_dir: Some(temp.path().into()),
                    json: true
                }
            }),
            &crate::common::context::CommandContext::new(true)
        )
        .await
        .is_err()
    );
    let listed = aster_acme_cli_storage::accounts(temp.path().into())
        .await
        .unwrap();
    assert!(!listed[0].usable);
    assert_eq!(
        listed[0].last_status,
        Some(aster_acme_core::protocol::AccountStatus::Deactivated)
    );
}

#[test]
fn command_specific_options_are_rejected_by_unrelated_commands() {
    for command in ["recover", "show", "switch"] {
        for arguments in [
            vec!["--accept-terms"],
            vec!["--yes"],
            vec!["--contact", "you@example.com"],
            vec!["--eab-kid", "id"],
            vec!["--eab-key-file", "key"],
        ] {
            let mut argv = vec!["aster-acme", "account", command];
            argv.extend(arguments);
            assert!(Args::try_parse_from(argv).is_err());
        }
    }
    for flag in [
        "--user-agent",
        "--timeout",
        "--name",
        "--ca",
        "--ca-directory",
    ] {
        assert!(
            Args::try_parse_from(["aster-acme", "account", "switch", "work", flag, "value"])
                .is_err()
        );
    }
    for flag in ["--user-agent", "--timeout"] {
        let value = if flag == "--timeout" {
            "10"
        } else {
            "client/1"
        };
        assert!(Args::try_parse_from(["aster-acme", "account", "show", flag, value]).is_err());
        assert!(
            Args::try_parse_from(["aster-acme", "account", "show", "--verify", flag, value])
                .is_ok()
        );
    }
    for old in ["--directory", "--server", "--ca-url", "--config"] {
        assert!(Args::try_parse_from(["aster-acme", "account", "register", old, "value"]).is_err());
    }
    for ca in ["letsencrypt", "zerossl", "google"] {
        assert!(Args::try_parse_from(["aster-acme", "account", "register", "--ca", ca]).is_ok());
        assert!(
            Args::try_parse_from([
                "aster-acme",
                "account",
                "register",
                "--ca",
                ca,
                "--ca-directory",
                "https://custom.example/directory"
            ])
            .is_err()
        );
    }
}

// Test fixtures use resolved input; rebuild only fields owned by each parser group.
impl From<super::args::AccountArgs> for LocalArgs {
    fn from(args: super::args::AccountArgs) -> Self {
        Self {
            data_dir: args.data_dir,
            json: args.json,
        }
    }
}

impl From<super::args::AccountArgs> for super::args::NetworkArgs {
    fn from(args: super::args::AccountArgs) -> Self {
        Self {
            identity: super::args::NameArgs {
                name: args.name,
                ..super::args::NameArgs::default()
            },
            ca: super::args::CaArgs {
                ca: None,
                ca_directory: args.ca_directory,
            },
            http: HttpArgs {
                user_agent: args.user_agent,
                timeout: args.timeout,
            },
            local: LocalArgs {
                data_dir: args.data_dir,
                json: args.json,
            },
        }
    }
}

impl From<super::args::AccountArgs> for super::args::RegisterArgs {
    fn from(mut args: super::args::AccountArgs) -> Self {
        let key_algorithm = args.key_algorithm;
        let (yes, accept_terms) = (args.yes, args.accept_terms);
        let contact = std::mem::take(&mut args.contact);
        let eab_kid = args.eab_kid.take();
        let eab_key_file = args.eab_key_file.take();
        let network = super::args::NetworkArgs::from(args);
        Self {
            identity: network.identity,
            key_algorithm,
            ca: network.ca,
            http: network.http,
            local: network.local,
            yes,
            accept_terms,
            contact,
            eab_kid,
            eab_key_file,
        }
    }
}

#[tokio::test]
async fn switch_without_a_name_in_automation_fails_without_selecting_the_default() {
    use super::{args::AccountArgs, execute};
    let temp = tempfile::tempdir().unwrap();
    let error = execute::execute(
        AccountCommand::Switch(super::args::LocalTargetArgs {
            identity: super::args::NameArgs {
                positional_name: None,
                ..super::args::NameArgs::default()
            },
            local: AccountArgs {
                data_dir: Some(temp.path().into()),
                json: true,
                ..AccountArgs::default()
            }
            .into(),
        }),
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .err()
    .unwrap();
    assert!(error.to_string().contains("switch <NAME>"));
    assert!(!temp.path().join("accounts").exists());
}

#[tokio::test]
async fn existing_registration_requires_confirmation_before_any_mutation_or_http() {
    use super::{args::AccountArgs, execute};
    use aster_acme::account::AccountKeyStore;
    use aster_acme_cli_storage::CliAccountStore;
    use std::time::Duration;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let directory = AcmeUrl::new(&format!(
        "https://{}/directory",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    crate::config::load(temp.path()).await.unwrap();
    let store = CliAccountStore::open(temp.path(), "default", Duration::from_secs(1)).unwrap();
    store
        .signer(&directory, "default", KeyAccess::Create(None))
        .await
        .unwrap();
    let config_path = temp.path().join("config.toml");
    let record_path = temp.path().join("accounts/default/account.toml");
    let key_path = temp.path().join("accounts/default/account-key.pk8");
    let before = [&config_path, &record_path, &key_path].map(|path| std::fs::read(path).unwrap());
    let options = || AccountArgs {
        data_dir: Some(temp.path().into()),
        contact: vec!["change@example.com".into()],
        accept_terms: true,
        json: true,
        timeout: Some(1),
        ..AccountArgs::default()
    };
    let error = execute::execute(
        AccountCommand::Register(options().into()),
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .err()
    .unwrap();
    assert!(error.to_string().contains("already exists"));
    assert!(error.to_string().contains("--yes"));
    assert_eq!(
        [&config_path, &record_path, &key_path].map(|path| std::fs::read(path).unwrap()),
        before
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let peer = tokio::spawn(async move {
        let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        drop(stream);
    });
    let mut confirmed = options();
    confirmed.yes = true;
    let error = execute::execute(
        AccountCommand::Register(confirmed.into()),
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .err()
    .unwrap();
    assert!(!error.to_string().contains("Reuse requires confirmation"));
    peer.await.unwrap();
    assert_eq!(std::fs::read(key_path).unwrap(), before[2]);
}

#[tokio::test]
async fn registration_saves_explicit_contact_before_discovery_failure() {
    use super::{args::AccountArgs, execute};
    use aster_acme::account::{AccountKeyStore, AccountStore};
    use aster_acme_cli_storage::CliAccountStore;
    use std::time::Duration;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let directory = AcmeUrl::new(&format!(
        "https://{}/directory",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let peer = tokio::spawn(async move {
        let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        drop(stream);
    });
    let temp = tempfile::tempdir().unwrap();
    assert!(
        execute::execute(
            AccountCommand::Register(
                AccountArgs {
                    data_dir: Some(temp.path().into()),
                    ca_directory: Some(directory.as_str().into()),
                    contact: vec!["you@example.com".into()],
                    accept_terms: true,
                    timeout: Some(1),
                    ..AccountArgs::default()
                }
                .into()
            ),
            &crate::common::context::CommandContext::new(true)
        )
        .await
        .is_err()
    );
    peer.await.unwrap();
    let config = crate::config::load(temp.path()).await.unwrap();
    assert_eq!(config.contact, ["you@example.com"]);
    let store = CliAccountStore::open(temp.path(), "default", Duration::from_secs(1)).unwrap();
    let thumb = store
        .signer(&directory, "default", KeyAccess::Existing)
        .await
        .unwrap()
        .jwk()
        .unwrap()
        .thumbprint()
        .unwrap();
    let record = store.load(&directory, &thumb).await.unwrap().unwrap();
    assert_eq!(record.contacts, ["mailto:you@example.com"]);
    assert_eq!(record.server_contacts, None);
    let config_text = std::fs::read_to_string(temp.path().join("config.toml")).unwrap();
    assert!(
        config_text
            .starts_with("# Managed by aster-acme. DO NOT EDIT version.\nversion = 1\n\n[config]")
    );
    let account_text =
        std::fs::read_to_string(temp.path().join("accounts/default/account.toml")).unwrap();
    assert!(
        account_text.starts_with(
            "# Managed by aster-acme. DO NOT EDIT this file.\nversion = 1\n\n[account]"
        )
    );
}

#[tokio::test]
async fn switch_edits_config_and_uses_the_named_accounts_ca_offline() {
    use super::{args::AccountArgs, execute, report::AccountReport};
    use aster_acme::account::{AccountKeyStore, AccountStore};
    use aster_acme_cli_storage::CliAccountStore;
    use std::time::Duration;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.toml");
    std::fs::write(
        &path,
        "# user config\nversion=1\n[config]\ndefault_account='default' # selected\n",
    )
    .unwrap();
    let ca = AcmeUrl::new("https://custom.invalid/directory").unwrap();
    let store = CliAccountStore::open(temp.path(), "work", Duration::from_secs(1)).unwrap();
    let thumb = store
        .signer(&ca, "work", KeyAccess::Create(None))
        .await
        .unwrap()
        .jwk()
        .unwrap()
        .thumbprint()
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    let options = || AccountArgs {
        data_dir: Some(temp.path().into()),
        ..AccountArgs::default()
    };
    assert!(
        execute::execute(
            AccountCommand::Switch(super::args::LocalTargetArgs {
                identity: super::args::NameArgs {
                    positional_name: Some("work".into()),
                    ..super::args::NameArgs::default()
                },
                local: options().into()
            }),
            &crate::common::context::CommandContext::new(true)
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let mut record = store.load(&ca, &thumb).await.unwrap().unwrap();
    record.state = AccountRecordState::Registered;
    record.account_url = Some(AcmeUrl::new("https://custom.invalid/account/1").unwrap());
    store.save(&record).await.unwrap();
    let result = execute::execute(
        AccountCommand::Switch(super::args::LocalTargetArgs {
            identity: super::args::NameArgs {
                positional_name: Some("work".into()),
                ..super::args::NameArgs::default()
            },
            local: options().into(),
        }),
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .unwrap();
    assert!(matches!(result, AccountReport::Switched { directory, .. } if directory == ca));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("# selected") && text.contains("# user config"));
    assert_eq!(
        crate::config::load(temp.path())
            .await
            .unwrap()
            .default_account
            .as_deref(),
        Some("work")
    );
    let result = execute::execute(
        AccountCommand::Show {
            verify: false,
            options: options().into(),
        },
        &crate::common::context::CommandContext::new(true),
    )
    .await
    .unwrap();
    assert!(
        matches!(result, AccountReport::Local(local) if local.name == "work" && local.directory == ca)
    );
    let mut wrong_ca = options();
    wrong_ca.ca_directory = Some("https://another.invalid/directory".into());
    assert!(
        execute::execute(
            AccountCommand::Show {
                verify: false,
                options: wrong_ca.into()
            },
            &crate::common::context::CommandContext::new(true)
        )
        .await
        .is_err()
    );
}

#[test]
fn registration_normalizes_cli_and_config_contacts_with_cli_precedence() {
    use super::{args::AccountArgs, execute::registration_options};
    let configured = vec!["config@example.com".into()];
    let options = registration_options(AccountArgs::default(), configured.clone()).unwrap();
    assert_eq!(options.contacts, ["mailto:config@example.com"]);
    let options = registration_options(
        AccountArgs {
            contact: vec!["cli@example.com".into(), "mailto:second@example.com".into()],
            ..AccountArgs::default()
        },
        configured,
    )
    .unwrap();
    assert_eq!(
        options.contacts,
        ["mailto:cli@example.com", "mailto:second@example.com"]
    );
    assert!(registration_options(AccountArgs::default(), vec!["invalid".into()]).is_err());
}

#[test]
fn verify_is_an_explicit_show_only_option() {
    let args = Args::try_parse_from(["aster-acme", "account", "show", "--verify"]).unwrap();
    assert!(matches!(
        args.command,
        Command::Account { command } if matches!(command, AccountCommand::Show { verify: true, .. })
    ));
    let args = Args::try_parse_from(["aster-acme", "account", "show"]).unwrap();
    assert!(matches!(
        args.command,
        Command::Account { command } if matches!(command, AccountCommand::Show { verify: false, .. })
    ));
    for command in ["register", "recover", "switch"] {
        assert!(Args::try_parse_from(["aster-acme", "account", command, "--verify"]).is_err());
    }
}

#[tokio::test]
async fn show_reads_all_local_stages_without_connecting_or_changing_metadata() {
    use super::{args::AccountArgs, execute, render, report::AccountReport};
    use aster_acme::account::{AccountKeyStore, AccountRecord, AccountStore};
    use aster_acme_cli_storage::CliAccountStore;
    use std::time::Duration;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let directory = AcmeUrl::new(&format!(
        "https://{}/directory",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = CliAccountStore::open(temp.path(), "work", Duration::from_secs(1)).unwrap();
    let signer = store
        .signer(&directory, "work", KeyAccess::Create(None))
        .await
        .unwrap();
    let thumbprint = signer.jwk().unwrap().thumbprint().unwrap();
    for (state, expected) in [
        (None, "registration_pending"),
        (
            Some(AccountRecordState::RegistrationPending),
            "registration_pending",
        ),
        (Some(AccountRecordState::Registered), "registered"),
    ] {
        if let Some(state) = state {
            let account_url = match state {
                AccountRecordState::Registered => {
                    Some(AcmeUrl::new("https://ca.example/account/1").unwrap())
                }
                AccountRecordState::RegistrationPending => None,
            };
            store
                .save(&AccountRecord {
                    key_algorithm: KeyAlgorithm::EcdsaP256,
                    user_agent: None,
                    times: aster_acme::account::AccountTimes::default(),
                    account_id: "a".repeat(43),
                    directory_url: directory.clone(),
                    key_thumbprint: thumbprint.clone(),
                    account_url,
                    contacts: vec!["mailto:you@example.com".into()],
                    server_contacts: None,
                    last_status: None,
                    deactivation: aster_acme_core::account::DeactivationState::NotRequested,
                    key_rotation: None,
                    accepted_terms_url: None,
                    state,
                })
                .await
                .unwrap();
        }
        let before = store.load(&directory, &thumbprint).await.unwrap();
        let report = execute::execute(
            AccountCommand::Show {
                verify: false,
                options: AccountArgs {
                    ca_directory: Some(directory.as_str().into()),
                    data_dir: Some(temp.path().into()),
                    name: Some("work".into()),
                    // Invalid HTTP-only settings must not interfere with local inspection.
                    user_agent: Some("bad\nheader".into()),
                    ..AccountArgs::default()
                }
                .into(),
            },
            &crate::common::context::CommandContext::new(true),
        )
        .await
        .unwrap();
        assert!(matches!(report, AccountReport::Local(_)));
        let value = render::tests::json_value(&report);
        assert_eq!(value["local_state"], expected);
        assert_eq!(value["ca_query"]["account_refreshed"], false);
        assert!(value.get("verified").is_none());
        assert!(value.get("source").is_none());
        assert!(value["status"].is_null());
        assert!(
            !render::render(&report, crate::common::session::Format::plain(true))
                .unwrap()
                .contains('\x1b')
        );
        assert!(
            render::render(&report, crate::common::session::Format::plain(false))
                .unwrap()
                .contains("not performed (local data only)")
        );
        assert_eq!(store.load(&directory, &thumbprint).await.unwrap(), before);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn show_verify_attempts_network_and_retains_local_data_on_failure() {
    use super::{args::AccountArgs, execute};
    use aster_acme::account::{AccountKeyStore, AccountStore};
    use aster_acme_cli_storage::CliAccountStore;
    use std::time::Duration;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let directory = AcmeUrl::new(&format!(
        "https://{}/directory",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = CliAccountStore::open(temp.path(), "default", Duration::from_secs(1)).unwrap();
    let jwk = store
        .signer(&directory, "default", KeyAccess::Create(None))
        .await
        .unwrap()
        .jwk()
        .unwrap();
    let connection = tokio::spawn(async move {
        let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        // Terminate the TLS handshake to exercise the network error path deterministically.
        drop(stream);
    });
    assert!(
        execute::execute(
            AccountCommand::Show {
                verify: true,
                options: AccountArgs {
                    ca_directory: Some(directory.as_str().into()),
                    data_dir: Some(temp.path().into()),
                    timeout: Some(1),
                    ..AccountArgs::default()
                }
                .into()
            },
            &crate::common::context::CommandContext::new(true)
        )
        .await
        .is_err()
    );
    connection.await.unwrap();
    assert_eq!(
        store
            .signer(&directory, "default", KeyAccess::Existing)
            .await
            .unwrap()
            .jwk()
            .unwrap(),
        jwk
    );
    assert!(
        store
            .load(&directory, &jwk.thumbprint().unwrap())
            .await
            .unwrap()
            .is_some()
    );
}

#[test]
fn parser_requires_commands_and_bounds_timeout_and_eab_pairs() {
    assert!(Args::try_parse_from(["aster-acme"]).is_err());
    for timeout in ["0", "301", "-1", "x"] {
        assert!(
            Args::try_parse_from(["aster-acme", "account", "register", "--timeout", timeout])
                .is_err()
        );
    }
    for timeout in ["1", "300"] {
        assert!(
            Args::try_parse_from(["aster-acme", "account", "register", "--timeout", timeout])
                .is_ok()
        );
    }
    assert!(
        Args::try_parse_from(["aster-acme", "account", "register", "--eab-kid", "id"]).is_err()
    );
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "account",
            "register",
            "--eab-key-file",
            "file"
        ])
        .is_err()
    );
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "account",
            "register",
            "--accept-terms",
            "--ca-directory",
            "https://custom.example/directory",
            "--user-agent",
            "my client"
        ])
        .is_ok()
    );
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "account",
            "switch",
            "work",
            "--data-dir",
            "data"
        ])
        .is_ok()
    );
    assert!(Args::try_parse_from(["aster-acme", "account", "switch"]).is_ok());
}

#[tokio::test]
async fn existing_account_commands_reject_missing_names_before_prompts_keys_or_http() {
    let temp = tempfile::tempdir().unwrap();
    crate::config::load(temp.path()).await.unwrap();
    for command in [
        "show",
        "recover",
        "switch",
        "deactivate",
        "remove",
        "update-contact",
        "rotate-key",
    ] {
        let parsed = Args::try_parse_from([
            "aster-acme",
            "account",
            command,
            "missing",
            "--data-dir",
            temp.path().to_str().unwrap(),
            "--json",
        ])
        .unwrap();
        let Command::Account { command } = parsed.command else {
            panic!("expected account");
        };
        let error =
            super::execute::execute(command, &crate::common::context::CommandContext::new(true))
                .await
                .err()
                .unwrap();
        assert!(
            error
                .to_string()
                .contains("No local account named 'missing'"),
            "{error}"
        );
        assert!(!error.to_string().contains("confirmation"));
        assert!(!temp.path().join("accounts/missing").exists());
    }
}
