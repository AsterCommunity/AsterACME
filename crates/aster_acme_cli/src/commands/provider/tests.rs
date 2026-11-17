//! Provider command behavior and argument boundaries.
use crate::{
    app::{Args, Command},
    commands::provider::{
        execute::execute,
        render::render,
        report::{CleanupView, ProviderReport},
    },
    common::{context::CommandContext, session::Format},
};
use aster_acme::storage::issuance::IssueStore;
use clap::Parser;
fn command(words: &[&str]) -> crate::commands::provider::args::ProviderCommand {
    let args = Args::try_parse_from(
        ["aster-acme", "provider"]
            .into_iter()
            .chain(words.iter().copied()),
    )
    .unwrap();
    let Command::Provider { command } = args.command else {
        panic!("not provider command");
    };
    command
}

#[tokio::test]
async fn show_requires_explicit_targets_in_automation_and_empty_selection_is_actionable() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_str().unwrap();
    for action in ["show", "cleanup", "remove"] {
        let error = execute(
            command(&[action, "--data-dir", root, "--json"]),
            &CommandContext::new(true),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("provider {action} <NAME>"))
        );
    }
    let error = execute(
        command(&["remove", "--yes", "--json", "--data-dir", root]),
        &CommandContext::new(true),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("provider remove <NAME>"));
    for words in [
        vec!["add", "--json", "--data-dir", root],
        vec!["add", "new", "--json", "--data-dir", root],
    ] {
        assert!(
            execute(command(&words), &CommandContext::new(true))
                .await
                .unwrap_err()
                .to_string()
                .contains("provider add <NAME> with --backend <ID> or --exec <PATH>")
        );
    }
    for words in [
        vec!["update", "--json", "--data-dir", root],
        vec!["update", "prod", "--json", "--data-dir", root],
        vec!["update", "--clear-args", "--json", "--data-dir", root],
    ] {
        assert!(
            execute(command(&words), &CommandContext::new(true))
                .await
                .is_err()
        );
    }
    let error =
        crate::commands::provider::execute::select(temp.path(), &CommandContext::new(false).output)
            .await
            .unwrap_err();
    assert!(error.to_string().contains("provider add"));
    assert!(!temp.path().join("providers").exists());
    assert!(!temp.path().join("certs").exists());
    assert!(
        execute(
            command(&["show", "missing", "--data-dir", root, "--json"]),
            &CommandContext::new(true)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn interactive_update_commits_once_and_refuses_concurrent_profile_changes() {
    let temp = tempfile::tempdir().unwrap();
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        temp.path().into(),
        std::time::Duration::from_secs(1),
    );
    let original = aster_acme_cli_storage::provider::ProviderProfile::new(
        std::env::current_exe().unwrap(),
        vec!["old".into()],
        Vec::new(),
    )
    .unwrap();
    store.add("prod".into(), original.clone()).await.unwrap();
    let mut edited = original.clone();
    edited.args = vec!["edited".into()];
    let saved = crate::commands::provider::execute::save_interactive_edit(
        &store,
        "prod".into(),
        original.clone(),
        edited.clone(),
    )
    .await
    .unwrap();
    assert_eq!(saved, edited);
    let mut concurrent = edited.clone();
    concurrent
        .provider_custom
        .insert("token".into(), serde_json::json!("concurrent-secret"));
    store
        .update("prod".into(), concurrent.clone())
        .await
        .unwrap();
    let error = crate::commands::provider::execute::save_interactive_edit(
        &store,
        "prod".into(),
        edited,
        original,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("changed while editing"));
    assert!(!error.to_string().contains("concurrent-secret"));
    assert_eq!(store.get("prod".into()).await.unwrap(), concurrent);
}

fn untrusted_profile_view() -> crate::commands::provider::report::ProfileView {
    crate::commands::provider::report::ProfileView {
        ttl_seconds: 120,
        backend_id: aster_acme_dns::backend::ADPP_BACKEND_ID.into(),
        backend_config_version: 1,
        name: "safe-name".into(),
        profile_path: "path\nfile.toml".into(),
        executable: "bad\x1b[2J".into(),
        args: vec!["line\nnext".into()],
        allowed_zones: vec!["zone\r.example".into()],
        profile_version: 1,
        custom_values: "<redacted>".into(),
    }
}

#[test]
fn profile_and_cleanup_reports_escape_untrusted_fields_and_keep_machine_output_pure() {
    let mut report = ProviderReport {
        backends: Vec::new(),
        operation: "shown",
        profiles: vec![untrusted_profile_view()],
        removed: None,
        cleanup: Vec::new(),
        cancelled: false,
        incomplete: false,
    };
    for operation in ["shown", "listed"] {
        report.operation = operation;
        let text = render(&report, Format::plain(false)).unwrap();
        assert!(!text.contains('\x1b'));
        assert!(!text.contains('\r'));
        if operation == "shown" {
            assert!(text.contains("bad\\u{1b}[2J"));
        }
        assert!(text.contains("zone\\r.example"));
        let json = render(
            &report,
            Format {
                json: true,
                color: true,
            },
        )
        .unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
        assert!(!json.contains('\x1b'));
    }
    report.operation = "cleanup";
    report.cleanup = vec![CleanupView {
        certificate: "web\x1b[2J".into(),
        operation: "op".into(),
        completed: false,
        error: Some("failure\nnext".into()),
    }];
    let text = render(&report, Format::plain(false)).unwrap();
    assert!(!text.contains('\x1b'));
    assert_eq!(text.lines().count(), 1);
    assert!(text.contains("cleanup pending"));
    assert!(text.contains("failure\\nnext"));
    assert!(
        render(
            &report,
            Format {
                json: false,
                color: true
            }
        )
        .unwrap()
        .starts_with("\x1b[33m[WARN]")
    );
    report.cleanup[0].completed = true;
    report.cleanup[0].error = None;
    let complete = render(&report, Format::plain(false)).unwrap();
    assert!(complete.contains("cleanup complete"));
    assert!(!complete.contains("cleanup pending"));
    report.cleanup.clear();
    assert!(
        render(&report, Format::plain(false))
            .unwrap()
            .contains("No terminal DNS publication cleanup is pending")
    );
    report.incomplete = true;
    assert!(
        render(&report, Format::plain(false))
            .unwrap()
            .contains("deadline expired")
    );
    report.operation = "listed";
    report.profiles.clear();
    assert!(
        render(&report, Format::plain(false))
            .unwrap()
            .contains("No DNS provider profiles configured")
    );
    report.removed = Some("prod\nunsafe".into());
    report.operation = "removed";
    let removed = render(
        &report,
        Format {
            json: false,
            color: true,
        },
    )
    .unwrap();
    assert!(removed.contains("Removed provider profile prod\\nunsafe"));
}

#[test]
fn backend_and_unrecognized_operation_reports_keep_their_rendering_boundaries() {
    let descriptors = crate::commands::provider::runtime::registry()
        .unwrap()
        .descriptors();
    let report = ProviderReport {
        backends: descriptors.clone(),
        operation: "backends",
        profiles: Vec::new(),
        removed: None,
        cleanup: Vec::new(),
        cancelled: false,
        incomplete: false,
    };
    let output = render(&report, Format::plain(false)).unwrap();
    assert!(output.contains("BACKEND ID") && output.contains("CONFIGURATION"));
    for descriptor in descriptors {
        assert!(output.contains(descriptor.id));
        assert!(output.contains(descriptor.label));
        for field in descriptor.fields {
            assert!(output.contains(field.name));
        }
    }

    let mut report = report;
    report.operation = "future-operation";
    report.profiles.push(untrusted_profile_view());
    assert!(
        render(&report, Format::plain(false))
            .unwrap()
            .contains("DNS provider profiles:")
    );
}

#[tokio::test]
async fn list_is_a_sorted_table_and_show_exposes_the_profile_file_with_shared_styles() {
    let temp = tempfile::tempdir().unwrap();
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        temp.path().into(),
        std::time::Duration::from_secs(1),
    );
    for name in ["long-profile", "a"] {
        let mut profile = aster_acme_cli_storage::provider::ProviderProfile::new(
            std::env::current_exe().unwrap(),
            vec!["arg\\n".into()],
            Vec::new(),
        )
        .unwrap();
        profile
            .provider_custom
            .insert("token".into(), serde_json::json!("secret-sentinel"));
        store.add(name.into(), profile).await.unwrap();
    }
    let root = temp.path().to_str().unwrap();
    let report = execute(
        command(&["list", "--data-dir", root, "--json"]),
        &CommandContext::new(true),
    )
    .await
    .unwrap();
    let plain = render(&report, Format::plain(false)).unwrap();
    let lines = plain.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("NAME"));
    assert!(lines[1].starts_with("a "));
    assert!(lines[2].starts_with("long-profile "));
    assert_eq!(
        lines[0].find("EXECUTABLE"),
        lines[1].find(
            &std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .to_string()
        )
    );
    assert!(!plain.contains("Arguments:"));
    assert!(!plain.contains('\x1b'));
    assert!(
        render(
            &report,
            Format {
                json: false,
                color: true
            }
        )
        .unwrap()
        .contains("\x1b[1;36mNAME")
    );
    let report = execute(
        command(&["show", "a", "--data-dir", root, "--json"]),
        &CommandContext::new(true),
    )
    .await
    .unwrap();
    let plain = render(&report, Format::plain(false)).unwrap();
    let expected = store.path("a").unwrap();
    assert!(plain.contains(&expected.to_string_lossy().to_string()));
    assert!(plain.contains("Profile file:"));
    let colored = render(
        &report,
        Format {
            json: false,
            color: true,
        },
    )
    .unwrap();
    assert!(colored.contains("\x1b[36mProfile file:\x1b[0m"));
    assert!(colored.contains("\x1b[36mExecutable:\x1b[0m"));
    assert!(!colored.contains("secret-sentinel"));
    let json = render(
        &report,
        Format {
            json: true,
            color: true,
        },
    )
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["profiles"][0]["profile_path"],
        expected.to_string_lossy().as_ref()
    );
    assert!(!json.contains("secret-sentinel"));
    assert!(!json.contains('\x1b'));
    assert!(store.path("../escape").is_err());
}

#[test]
fn incomplete_cleanup_report_is_rendered_and_fails_the_command() {
    let report = ProviderReport {
        backends: Vec::new(),
        operation: "cleanup",
        profiles: Vec::new(),
        removed: None,
        cleanup: vec![CleanupView {
            certificate: "web".into(),
            operation: "operation-id".into(),
            completed: true,
            error: None,
        }],
        cancelled: false,
        incomplete: true,
    };
    assert!(report.has_failures());
    assert_eq!(
        crate::dispatch::CommandReport::Provider(report.clone()).exit_status(),
        crate::common::session::ExitStatus::Failed
    );
    assert!(
        render(&report, Format::plain(false))
            .unwrap()
            .contains("did not examine all matching requests")
    );
    let json: serde_json::Value =
        serde_json::from_str(&render(&report, Format::plain(true)).unwrap()).unwrap();
    assert_eq!(json["incomplete"], true);
}
#[tokio::test]
async fn cleanup_command_is_offline_and_reports_all_terminal_results() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_str().unwrap();
    let executable = std::env::current_exe().unwrap();
    let cli = CommandContext::new(true);
    execute(
        command(&[
            "add",
            "prod",
            "--exec",
            executable.to_str().unwrap(),
            "--allow-zone",
            "validation.net",
            "--data-dir",
            root,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    let report = execute(
        command(&["cleanup", "prod", "--data-dir", root, "--json"]),
        &cli,
    )
    .await
    .unwrap();
    assert_eq!(report.operation, "cleanup");
    assert!(report.cleanup.is_empty());
}

#[tokio::test]
async fn cleanup_filters_legacy_foreign_idle_and_nonterminal_requests() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_str().unwrap();
    let executable = std::env::current_exe().unwrap();
    let cli = CommandContext::new(true);
    execute(
        command(&[
            "add",
            "prod",
            "--exec",
            executable.to_str().unwrap(),
            "--data-dir",
            root,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    let account: aster_acme::account::AccountRecord = serde_json::from_value(serde_json::json!({
        "key_algorithm":"ecdsa-p256", "account_id":"test-account",
        "directory_url":"https://ca.example/directory",
        "account_url":"https://ca.example/account/1", "key_thumbprint":"test-thumbprint",
        "contacts":[], "server_contacts":null, "last_status":"valid",
        "deactivation":"not_requested", "key_rotation":null, "accepted_terms_url":null,
        "state":"registered"
    }))
    .unwrap();
    let issues = aster_acme_cli_storage::issuance::CliIssueStore::new(
        temp.path().into(),
        std::time::Duration::from_secs(1),
    );
    let config = crate::commands::cert::validation::provider::bound_provider_configuration(
        Some("prod"),
        temp.path(),
    )
    .await
    .unwrap();
    for (name, solver, provider, cleanup_pending) in [
        ("legacy", "dns_external", "prod", true),
        ("foreign", "dns_provider", "other", true),
        ("idle", "dns_provider", "prod", false),
        ("nonterminal", "dns_provider", "prod", true),
    ] {
        let request = aster_acme::issuance::IssueRequest {
            challenge: aster_acme::challenge::ChallengeKind::Dns01,
            solver_id: solver.into(),
            solver_config: if solver == "dns_provider" && provider == "prod" {
                config.clone()
            } else {
                serde_json::json!({"provider_instance_id":provider})
            },
            name: aster_acme::issuance::CertificateName::new(name).unwrap(),
            identifiers: vec![aster_acme::identifier::DnsIdentifier::new("example.com").unwrap()],
            key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
            account_name: "default".into(),
        };
        let session = issues.create(&request, &account).await.unwrap();
        let mut record = session.record().await.unwrap();
        if name == "nonterminal" {
            record.authorizations = serde_json::from_value(serde_json::json!([{
                "url":"https://ca.example/auth",
                "resource":{"identifier":{"type":"dns","value":"example.com"},"status":"pending","challenges":[]},
                "challenge_url":null,"validation_requirement":null,
                "cleanup_pending":cleanup_pending,"acknowledgement":"not_submitted"
            }])).unwrap();
        }
        if name != "nonterminal" && cleanup_pending {
            record.finalize_rejection = Some(aster_acme::issuance::RequestFailure {
                status: 400,
                problem: None,
                retry_at: None,
            });
        }
        session.save(&record).await.unwrap();
    }
    let report = execute(
        command(&["cleanup", "prod", "--data-dir", root, "--json"]),
        &cli,
    )
    .await
    .unwrap();
    assert!(report.cleanup.is_empty());
}

#[tokio::test]
async fn cleanup_records_open_failures_and_continues_to_later_matching_certificates() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_str().unwrap();
    let executable = std::env::current_exe().unwrap();
    let cli = CommandContext::new(true);
    execute(
        command(&[
            "add",
            "prod",
            "--exec",
            executable.to_str().unwrap(),
            "--data-dir",
            root,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    let account: aster_acme::account::AccountRecord = serde_json::from_value(serde_json::json!({
        "key_algorithm":"ecdsa-p256", "account_id":"test-account",
        "directory_url":"https://ca.example/directory",
        "account_url":"https://ca.example/account/1", "key_thumbprint":"test-thumbprint",
        "contacts":[], "server_contacts":null, "last_status":"valid",
        "deactivation":"not_requested", "key_rotation":null, "accepted_terms_url":null,
        "state":"registered"
    }))
    .unwrap();
    let issues = aster_acme_cli_storage::issuance::CliIssueStore::new(
        temp.path().into(),
        std::time::Duration::from_secs(1),
    );
    let config = crate::commands::cert::validation::provider::bound_provider_configuration(
        Some("prod"),
        temp.path(),
    )
    .await
    .unwrap();
    let mut held = Vec::new();
    for name in ["a-locked", "b-available"] {
        let request = aster_acme::issuance::IssueRequest {
            challenge: aster_acme::challenge::ChallengeKind::Dns01,
            solver_id: "dns_provider".into(),
            solver_config: config.clone(),
            name: aster_acme::issuance::CertificateName::new(name).unwrap(),
            identifiers: vec![aster_acme::identifier::DnsIdentifier::new("example.com").unwrap()],
            key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
            account_name: "default".into(),
        };
        let session = issues.create(&request, &account).await.unwrap();
        let mut record = session.record().await.unwrap();
        record.finalize_rejection = Some(aster_acme::issuance::RequestFailure {
            status: 400,
            problem: None,
            retry_at: None,
        });
        record.authorizations = serde_json::from_value(serde_json::json!([{
            "url":"https://ca.example/auth",
            "resource":{"identifier":{"type":"dns","value":"example.com"},"status":"invalid","challenges":[]},
            "challenge_url":null,"validation_requirement":null,
            "cleanup_pending":true,"acknowledgement":"not_submitted"
        }])).unwrap();
        session.save(&record).await.unwrap();
        if name == "a-locked" {
            held.push(session);
        }
    }
    let report = execute(
        command(&["cleanup", "prod", "--data-dir", root, "--json"]),
        &cli,
    )
    .await
    .unwrap();
    assert_eq!(report.cleanup.len(), 2);
    let locked = report
        .cleanup
        .iter()
        .find(|entry| entry.certificate == "a-locked")
        .unwrap();
    assert!(!locked.completed);
    assert!(locked.error.as_deref().unwrap().contains("lock"));
    let later = report
        .cleanup
        .iter()
        .find(|entry| entry.certificate == "b-available")
        .unwrap();
    assert!(!later.completed);
    assert!(later.error.is_none());
    drop(held);
}

#[tokio::test]
async fn provider_crud_outputs_are_redacted_and_no_binary_is_executed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_str().unwrap();
    let executable = std::env::current_exe().unwrap();
    let cli = CommandContext::new(true);
    execute(
        command(&[
            "add",
            "prod",
            "--exec",
            executable.to_str().unwrap(),
            "--allow-zone",
            "example.com",
            "--data-dir",
            root,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    let path = temp.path().join("providers/prod.toml");
    let mut document: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
    document["provider_custom"] = toml::Value::Table(toml::Table::from_iter([(
        "token".into(),
        toml::Value::String("secret-sentinel".into()),
    )]));
    std::fs::write(&path, toml::to_string(&document).unwrap()).unwrap();
    for operation in ["show", "list"] {
        let words = if operation == "list" {
            vec!["list", "--data-dir", root, "--json"]
        } else {
            vec!["show", "prod", "--data-dir", root, "--json"]
        };
        let report = execute(command(&words), &cli).await.unwrap();
        let json = render(
            &report,
            Format {
                json: true,
                color: false,
            },
        )
        .unwrap();
        assert!(!json.contains("secret-sentinel"));
        assert!(json.contains("redacted"));
        assert!(
            !render(
                &report,
                Format {
                    json: false,
                    color: false
                }
            )
            .unwrap()
            .contains("secret-sentinel")
        );
    }
    execute(
        command(&[
            "update",
            "prod",
            "--clear-args",
            "--data-dir",
            root,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("secret-sentinel")
    );
    assert!(
        execute(
            command(&["remove", "prod", "--data-dir", root, "--json"]),
            &cli
        )
        .await
        .is_err()
    );
    execute(
        command(&["remove", "prod", "--yes", "--data-dir", root, "--json"]),
        &cli,
    )
    .await
    .unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn explicit_update_replaces_and_clears_fields_and_duplicate_add_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_str().unwrap();
    let executable = std::env::current_exe().unwrap();
    let cli = CommandContext::new(true);
    execute(
        command(&[
            "add",
            "prod",
            "--exec",
            executable.to_str().unwrap(),
            "--arg=old",
            "--allow-zone",
            "old.example",
            "--data-dir",
            root,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    assert!(
        execute(
            command(&[
                "add",
                "prod",
                "--exec",
                executable.to_str().unwrap(),
                "--data-dir",
                root,
                "--json",
            ]),
            &cli
        )
        .await
        .is_err()
    );
    let updated = execute(
        command(&[
            "update",
            "prod",
            "--exec",
            executable.to_str().unwrap(),
            "--arg=--label=hello world",
            "--allow-zone",
            "updated.example",
            "--data-dir",
            root,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    assert_eq!(updated.profiles[0].args, ["--label=hello world"]);
    assert_eq!(updated.profiles[0].allowed_zones, ["updated.example"]);
    assert_eq!(updated.profiles[0].executable, executable);
    let cleared = execute(
        command(&[
            "update",
            "prod",
            "--clear-args",
            "--clear-zones",
            "--data-dir",
            root,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    assert_eq!(cleared.profiles[0].args, Vec::<String>::new());
    assert_eq!(cleared.profiles[0].allowed_zones, Vec::<String>::new());
}
#[tokio::test]
async fn zone_restriction_is_optional_and_can_be_added_or_cleared() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_str().unwrap();
    let executable = std::env::current_exe().unwrap();
    let cli = CommandContext::new(true);
    let report = execute(
        command(&[
            "add",
            "prod",
            "--exec",
            executable.to_str().unwrap(),
            "--data-dir",
            root,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    let plain = render(
        &report,
        Format {
            json: false,
            color: false,
        },
    )
    .unwrap();
    assert!(plain.contains("all (unrestricted)"));
    let restricted = execute(
        command(&[
            "update",
            "prod",
            "--allow-zone",
            "example.com",
            "--data-dir",
            root,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    assert_eq!(restricted.profiles[0].allowed_zones, ["example.com"]);
    let cleared = execute(
        command(&[
            "update",
            "prod",
            "--clear-zones",
            "--data-dir",
            root,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    assert_eq!(
        cleared.profiles[0].allowed_zones,
        [] as [std::string::String; 0]
    );
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        temp.path().into(),
        std::time::Duration::from_secs(1),
    );
    assert_eq!(
        store.get("prod".into()).await.unwrap().allowed_zones,
        [] as [std::string::String; 0]
    );
    assert!(
        Args::try_parse_from([
            "aster-acme",
            "provider",
            "update",
            "prod",
            "--clear-zones",
            "--allow-zone",
            "example.com"
        ])
        .is_err()
    );
}

#[test]
fn malformed_provider_and_external_dns_arguments_are_rejected() {
    for words in [
        vec![
            "provider",
            "add",
            "../escape",
            "--exec",
            "/bin/true",
            "--allow-zone",
            "example.com",
        ],
        vec!["provider", "show", "prod", "--yes"],
    ] {
        assert!(Args::try_parse_from(["aster-acme"].into_iter().chain(words)).is_err());
    }
}
mod builtin;

mod ttl;
