//! Requested TTL options, durable updates and input boundaries.
use crate::{
    app::Args,
    commands::provider::{execute::execute, render::render, tests::command},
    common::{context::CommandContext, session::Format},
};
use clap::Parser;

#[tokio::test]
async fn ttl_options_persist_show_and_update_without_changing_other_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_str().unwrap();
    let executable = std::env::current_exe().unwrap();
    let executable = executable.to_str().unwrap();
    let report = execute(
        command(&[
            "add",
            "dns",
            "--exec",
            executable,
            "--ttl-seconds",
            "0",
            "--data-dir",
            root,
            "--json",
        ]),
        &CommandContext::new(true),
    )
    .await
    .unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&render(&report, Format::plain(true)).unwrap()).unwrap();
    assert_eq!(json["profiles"][0]["ttl_seconds"], 0);
    assert!(
        render(&report, Format::plain(false))
            .unwrap()
            .contains("Requested TTL (seconds):")
    );
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        temp.path().into(),
        std::time::Duration::from_secs(1),
    );
    store
        .edit("dns".into(), |profile| {
            profile.propagation_timeout = 17;
            profile.propagation_interval = 7;
            Ok(())
        })
        .await
        .unwrap();
    let before = store.get("dns".into()).await.unwrap();
    for ttl in ["0", "300", "2147483647"] {
        execute(
            command(&[
                "update",
                "dns",
                "--ttl-seconds",
                ttl,
                "--data-dir",
                root,
                "--json",
            ]),
            &CommandContext::new(true),
        )
        .await
        .unwrap();
        let mut expected = before.clone();
        expected.ttl_seconds = ttl.parse().unwrap();
        assert_eq!(store.get("dns".into()).await.unwrap(), expected);
    }
}

#[test]
fn ttl_flags_reject_invalid_values_and_are_scoped_to_add_update() {
    for action in ["add", "update"] {
        for ttl in ["-1", "2147483648", "4294967295", "NaN"] {
            assert!(
                Args::try_parse_from([
                    "aster-acme",
                    "provider",
                    action,
                    "dns",
                    "--ttl-seconds",
                    ttl
                ])
                .is_err()
            );
        }
        for ttl in ["0", "1", "120", "2147483647"] {
            assert!(
                Args::try_parse_from([
                    "aster-acme",
                    "provider",
                    action,
                    "dns",
                    "--ttl-seconds",
                    ttl
                ])
                .is_ok()
            );
        }
    }
    for action in ["show", "remove", "cleanup", "list", "backends"] {
        assert!(
            Args::try_parse_from(["aster-acme", "provider", action, "--ttl-seconds", "120"])
                .is_err()
        );
    }
}
