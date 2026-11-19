use crate::{
    commands::provider::{execute::execute, tests::command},
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
    for (id, enabled) in [
        (
            "com.astercosm.acme.dns.aliyun",
            cfg!(feature = "dns-aliyun"),
        ),
        (
            "com.astercosm.acme.dns.tencent-cloud",
            cfg!(feature = "dns-tencent-cloud"),
        ),
        (
            "com.astercosm.acme.dns.huawei-cloud",
            cfg!(feature = "dns-huawei-cloud"),
        ),
    ] {
        assert_eq!(ids.contains(&id), enabled);
    }
    assert!(!root.path().join("providers").exists());
}
#[cfg(feature = "dns-cloudflare")]
#[tokio::test]
async fn native_profile_crud_is_offline_redacted_and_invalid_update_is_atomic() {
    use crate::{commands::provider::render::render, common::session::Format};
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

#[cfg(feature = "dns-cloudflare")]
#[tokio::test]
async fn native_backend_rejects_executable_and_argv_before_profile_creation() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().to_str().unwrap();
    let executable = std::env::current_exe().unwrap();
    let executable = executable.to_str().unwrap();
    for args in [vec!["--exec", executable], vec!["--arg=--unexpected"]] {
        let mut words = vec![
            "add",
            "bad",
            "--backend",
            "com.astercosm.acme.dns.cloudflare",
            "--data-dir",
            directory,
            "--json",
        ];
        words.extend(args);
        assert!(
            execute(command(&words), &CommandContext::new(true))
                .await
                .is_err()
        );
        assert!(!root.path().join("providers/bad.toml").exists());
    }
}

#[cfg(any(
    feature = "dns-aliyun",
    feature = "dns-tencent-cloud",
    feature = "dns-huawei-cloud"
))]
#[tokio::test]
async fn signed_backends_accept_private_settings_and_redact_both_credential_fields() {
    let cases = [
        #[cfg(feature = "dns-aliyun")]
        (
            "com.astercosm.acme.dns.aliyun",
            "access_key_id",
            "access_key_secret",
        ),
        #[cfg(feature = "dns-tencent-cloud")]
        (
            "com.astercosm.acme.dns.tencent-cloud",
            "secret_id",
            "secret_key",
        ),
        #[cfg(feature = "dns-huawei-cloud")]
        (
            "com.astercosm.acme.dns.huawei-cloud",
            "access_key_id",
            "access_key_secret",
        ),
    ];
    for (backend, id, secret) in cases {
        check_signed_profile(backend, id, secret).await;
    }
}

#[cfg(any(
    feature = "dns-aliyun",
    feature = "dns-tencent-cloud",
    feature = "dns-huawei-cloud"
))]
async fn check_signed_profile(backend: &str, id: &str, secret: &str) {
    use crate::{commands::provider::render::render, common::session::Format};
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().to_str().unwrap();
    let path = root.path().join("settings.toml");
    let settings = aster_acme_cli_storage::state_file::StateDirectory::open(root.path()).unwrap();
    let project = "";
    settings
        .atomic_write(
            "settings.toml",
            format!("{id} = 'fixture-key-id'\n{secret} = 'secret-sentinel'\n{project}").as_bytes(),
        )
        .unwrap();
    let cli = CommandContext::new(true);
    let registry = crate::commands::provider::runtime::registry().unwrap();
    let descriptors = registry.descriptors();
    let descriptor = descriptors.iter().find(|item| item.id == backend).unwrap();
    assert_signed_backend_fields(backend, descriptor);
    execute(
        command(&[
            "add",
            "native",
            "--backend",
            backend,
            "--settings-file",
            path.to_str().unwrap(),
            "--ttl-seconds",
            "120",
            "--data-dir",
            directory,
            "--json",
        ]),
        &cli,
    )
    .await
    .unwrap();
    let shown = execute(
        command(&["show", "native", "--data-dir", directory, "--json"]),
        &cli,
    )
    .await
    .unwrap();
    for json in [true, false] {
        let output = render(&shown, Format { json, color: false }).unwrap();
        assert!(output.contains(backend));
        assert!(output.contains("120"));
        assert!(!output.contains("fixture-key-id"));
        assert!(!output.contains("secret-sentinel"));
    }
    settings
        .atomic_write(
            "settings.toml",
            format!("{id} = 'invalid id'\n{secret} = 'secret-sentinel'\n{project}").as_bytes(),
        )
        .unwrap();
    let Err(error) = execute(
        command(&[
            "update",
            "native",
            "--settings-file",
            path.to_str().unwrap(),
            "--data-dir",
            directory,
            "--json",
        ]),
        &cli,
    )
    .await
    else {
        panic!("invalid API key ID accepted")
    };
    assert!(!error.to_string().contains("secret-sentinel"));
}

#[cfg(any(
    feature = "dns-aliyun",
    feature = "dns-tencent-cloud",
    feature = "dns-huawei-cloud"
))]
fn assert_signed_backend_fields(
    backend: &str,
    descriptor: &aster_acme_dns::backend::BackendDescriptor,
) {
    assert_eq!(
        descriptor.fields.len(),
        if backend.ends_with("huawei-cloud") {
            4
        } else {
            2
        }
    );
    assert!(
        descriptor
            .fields
            .iter()
            .filter(|field| field.sensitive)
            .all(|field| field.required)
    );
    if backend.ends_with("huawei-cloud") {
        assert!(
            !descriptor
                .fields
                .iter()
                .find(|field| field.name == "project_id")
                .unwrap()
                .required
        );
        assert!(
            !descriptor
                .fields
                .iter()
                .find(|field| field.name == "region")
                .unwrap()
                .required
        );
    }
}
