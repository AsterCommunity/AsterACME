use crate::{
    commands::provider::{execute, tests::command},
    common::context::CommandContext,
};
#[tokio::test]
async fn backend_inventory_reports_only_compiled_implementations_without_provider_execution() {
    let root = tempfile::tempdir().unwrap();
    let cli = CommandContext::new(true);
    let report = execute(
        command(&[
            "backends",
            "--data-dir",
            root.path().to_str().unwrap(),
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    let json = serde_json::to_value(&report).unwrap();
    let ids = json["backends"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(ids.contains(&"com.astercosm.acme.adpp"));
    assert_eq!(
        ids.contains(&"com.astercosm.acme.dns.cloudflare"),
        cfg!(feature = "dns-cloudflare")
    );
    assert!(!root.path().join("providers").exists());
}
#[cfg(feature = "dns-cloudflare")]
#[tokio::test]
async fn native_profile_crud_is_offline_redacted_and_invalid_update_is_atomic() {
    use crate::{commands::provider::render, common::session::Format};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("settings.toml");
    let settings = aster_acme_cli_storage::state_file::StateDirectory::open(root.path()).unwrap();
    settings
        .atomic_write(
            "settings.toml",
            b"zone_id = '0123456789abcdef0123456789abcdef'\napi_token = 'credential-sentinel'\n",
        )
        .unwrap();
    let cli = CommandContext::new(true);
    let dir = root.path().to_str().unwrap();
    let input = path.to_str().unwrap();
    let report = execute(
        command(&[
            "add",
            "native",
            "--backend",
            "com.astercosm.acme.dns.cloudflare",
            "--settings-file",
            input,
            "--data-dir",
            dir,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    let format = Format {
        json: true,
        color: false,
    };
    let json = render(&report, format).unwrap();
    assert!(!json.contains("credential-sentinel"));
    assert!(json.contains("com.astercosm.acme.dns.cloudflare"));
    let profile = root.path().join("providers/native.toml");
    let before = std::fs::read(&profile).unwrap();
    settings
        .atomic_write(
            "settings.toml",
            b"zone_id = 'bad-zone'\napi_token = 'never-echo-this'\n",
        )
        .unwrap();
    let error = execute(
        command(&[
            "update",
            "native",
            "--settings-file",
            input,
            "--data-dir",
            dir,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap_err();
    assert!(!error.to_string().contains("never-echo-this"));
    assert_eq!(std::fs::read(&profile).unwrap(), before);
    let shown = execute(
        command(&["show", "native", "--data-dir", dir, "--json"]),
        &cli,
    )
    .await
    .unwrap();
    let text = render(
        &shown,
        Format {
            json: false,
            color: false,
        },
    )
    .unwrap();
    assert!(!text.contains("Executable:"));
    assert!(text.contains("Backend:"));
    assert!(!text.contains("credential-sentinel"));
    execute(
        command(&["remove", "native", "--yes", "--data-dir", dir, "--json"]),
        &cli,
    )
    .await
    .unwrap();
    assert!(!profile.exists());
}
#[tokio::test]
async fn unknown_backend_fails_before_creating_a_profile() {
    let root = tempfile::tempdir().unwrap();
    let cli = CommandContext::new(true);
    assert!(
        execute(
            command(&[
                "add",
                "unknown",
                "--backend",
                "org.example.dns.unavailable",
                "--data-dir",
                root.path().to_str().unwrap(),
                "--json"
            ]),
            &cli
        )
        .await
        .is_err()
    );
    assert!(!root.path().join("providers/unknown.toml").exists());
}
