//! Complete config presentation in human/JSON output, including partial targets and quoting.
use crate::commands::cert::render::deployment::*;
use aster_acme::deployment::DeploymentPhase;

fn binding(target: DeploymentTarget) -> DeploymentBinding {
    DeploymentBinding {
        permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
        id: "nginx".into(),
        target,
        reload_command: vec![
            "/usr/local/bin/reload service".into(),
            "--value".into(),
            "two words".into(),
        ],
        timeout_seconds: 42,
        max_retries: 4,
        generation: Some("generation-one".into()),
        phase: DeploymentPhase::ReloadFailed,
        attempts: 5,
        retry_failures: 0,
        retry_at: None,
        last_error: Some("reload failed\ncheck service".into()),
    }
}

#[test]
fn directory_details_show_all_resolved_paths_config_and_saved_state() {
    let root = std::path::PathBuf::from("/configured/certs");
    let entry = binding(DeploymentTarget::Directory { path: root.clone() });
    let plain = details("web", &entry, Format::plain(false)).unwrap();
    for file in ["cert.pem", "private-key.pem", "ca.pem", "fullchain.pem"] {
        assert!(plain.contains(&root.join(file).display().to_string()));
    }
    for expected in [
        "directory",
        "42 seconds per attempt",
        "generation-one",
        "reload failed\\ncheck service",
        "saved local state; service health not queried",
    ] {
        assert!(plain.contains(expected), "missing {expected}");
    }
    let line = plain
        .lines()
        .find(|line| line.trim_start().starts_with("Reload command:"))
        .unwrap();
    assert_eq!(
        shlex::split(
            line.trim_start()
                .trim_start_matches("Reload command:")
                .trim()
        )
        .unwrap(),
        entry.reload_command
    );
    assert!(!plain.contains('\x1b'));
    let colored = details(
        "web",
        &entry,
        Format {
            json: false,
            color: true,
        },
    )
    .unwrap();
    assert!(colored.contains("\x1b[1;36m"));
    assert!(colored.contains("\x1b[31mreload failed"));
    let json: serde_json::Value =
        serde_json::from_str(&details("web", &entry, Format::plain(true)).unwrap()).unwrap();
    assert_eq!(json["certificate"], "web");
    assert_eq!(json["deployment"], serde_json::to_value(entry).unwrap());
    assert_eq!(json["observation"], "saved local state");
}

#[test]
fn exact_files_report_only_configured_destinations_and_optional_reload() {
    let root = std::path::PathBuf::from("/configured/partial");
    for mask in 1_u32..16 {
        let paths = ["cert", "key", "ca", "chain"].map(|name| root.join(name));
        let mut entry = binding(DeploymentTarget::Files {
            certificate: (mask & 1 != 0).then(|| paths[0].clone()),
            private_key: (mask & 2 != 0).then(|| paths[1].clone()),
            ca_chain: (mask & 4 != 0).then(|| paths[2].clone()),
            fullchain: (mask & 8 != 0).then(|| paths[3].clone()),
        });
        entry.reload_command.clear();
        entry.generation = None;
        entry.last_error = None;
        entry.phase = DeploymentPhase::Configured;
        entry.attempts = 0;
        let plain = details("web\n", &entry, Format::plain(false)).unwrap();
        assert!(plain.contains("not configured (file publication only)"));
        assert!(plain.contains("exact files"));
        assert!(plain.contains("web\\n"));
        for (index, path) in paths.iter().enumerate() {
            assert_eq!(
                plain.contains(&path.display().to_string()),
                mask & (1 << index) != 0
            );
        }
        assert_eq!(
            plain.matches("not configured").count(),
            5 - usize::try_from(mask.count_ones()).unwrap()
        );
        let json: serde_json::Value =
            serde_json::from_str(&details("web", &entry, Format::plain(true)).unwrap()).unwrap();
        assert_eq!(json["deployment"]["reload_command"], serde_json::json!([]));
    }
}
