//! Private, per-profile storage for external and built-in DNS providers.

use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};

const PROFILE_VERSION: u32 = 1;
const PROFILE_LIMIT: usize = 64 * 1024;

/// One provider profile. Every custom value is considered sensitive.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProfile {
    /// Profile schema version passed to the provider executable.
    pub provider_profile_version: u32,
    /// Per-process timeout (1..=300 seconds).
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Total DNS propagation wait (1..=3600 seconds), within the operation budget.
    #[serde(default = "default_propagation_timeout")]
    pub propagation_timeout: u64,
    /// Delay between observations (1..=60 seconds).
    #[serde(default = "default_propagation_interval")]
    pub propagation_interval: u64,
    /// Absolute executable path.
    pub executable: PathBuf,
    /// Exact argv values; never interpreted by a shell.
    #[serde(default)]
    pub args: Vec<String>,
    /// Optional zone restrictions; omitted or empty allows any valid publication owner.
    #[serde(default)]
    pub allowed_zones: Vec<String>,
    /// Opaque provider-specific values, redacted by every CLI view.
    #[serde(default)]
    pub provider_custom: serde_json::Map<String, serde_json::Value>,
}

fn default_timeout() -> u64 {
    30
}
fn default_propagation_timeout() -> u64 {
    120
}
fn default_propagation_interval() -> u64 {
    5
}
impl std::fmt::Debug for ProviderProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderProfile")
            .field("executable", &self.executable)
            .field("provider_custom", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Shared provider registry lease; held while issuance can create references.
pub struct ProviderLease {
    _lease: crate::toml_file::FileLease,
}

impl ProviderProfile {
    /// Construct a new profile with the current profile schema version.
    /// # Errors
    /// Rejects unsupported schemas, relative executables and invalid profile limits.
    pub fn new(
        executable: PathBuf,
        args: Vec<String>,
        allowed_zones: Vec<String>,
    ) -> io::Result<Self> {
        let profile = Self {
            provider_profile_version: PROFILE_VERSION,
            timeout_seconds: default_timeout(),
            propagation_timeout: default_propagation_timeout(),
            propagation_interval: default_propagation_interval(),
            executable,
            args,
            allowed_zones,
            provider_custom: serde_json::Map::new(),
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Reject invalid or unsupported persisted profiles before execution.
    /// # Errors
    /// Rejects unsupported versions, invalid zones, paths, arguments and resource bounds.
    pub fn validate(&self) -> io::Result<()> {
        if !(1..=300).contains(&self.timeout_seconds)
            || !(1..=3600).contains(&self.propagation_timeout)
            || !(1..=60).contains(&self.propagation_interval)
            || self.provider_profile_version != PROFILE_VERSION
            || !self.executable.is_absolute()
            || self
                .allowed_zones
                .iter()
                .any(|zone| validate_zone(zone).is_err())
            || self.args.iter().any(|arg| arg.contains('\0'))
            || serde_json::to_vec(&self.provider_custom)
                .map_or(true, |bytes| bytes.len() > PROFILE_LIMIT / 2)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid provider profile",
            ));
        }
        Ok(())
    }
}

/// Storage root for `<data-dir>/providers/<name>.toml` profiles.
#[derive(Debug, Clone)]
pub struct ProviderProfileStore {
    root: PathBuf,
    lock_timeout: Duration,
}

impl ProviderProfileStore {
    /// Construct a provider profile store below the common data directory.
    #[must_use]
    pub const fn new(root: PathBuf, lock_timeout: Duration) -> Self {
        Self { root, lock_timeout }
    }

    /// Acquire a shared registry lease before creating or executing certificate references.
    /// # Errors
    /// Reports unsafe lock files, lock contention deadlines and I/O failure.
    pub async fn lease(&self) -> io::Result<ProviderLease> {
        let root = self.root.clone();
        let timeout = self.lock_timeout;
        tokio::task::spawn_blocking(move || {
            catalog_lock(&root, timeout, true).map(|lease| ProviderLease { _lease: lease })
        })
        .await
        .map_err(|_| io::Error::other("provider registry lock worker failed"))?
    }

    /// Edit the latest profile under the registry and per-profile locks.
    /// # Errors
    /// Reports unsafe/missing profiles, invalid edits, lock timeout and durable write failure.
    pub async fn edit(
        &self,
        name: String,
        edit: impl FnOnce(&mut ProviderProfile) -> io::Result<()> + Send + 'static,
    ) -> io::Result<ProviderProfile> {
        validate_name(&name)?;
        let root = self.root.clone();
        let timeout = self.lock_timeout;
        tokio::task::spawn_blocking(move || {
            let _catalog = catalog_lock(&root, timeout, false)?;
            let _lease = profile_lock(&root, &name, timeout)?;
            let path = profile_path(&root, &name)?;
            let mut profile = read_profile(&path)?;
            edit(&mut profile)?;
            write_profile(&path, &profile)?;
            Ok(profile)
        })
        .await
        .map_err(|_| io::Error::other("provider profile update worker failed"))?
    }

    /// Add a profile; existing names are never overwritten.
    /// # Errors
    /// Rejects existing names, invalid/unsafe profiles, lock timeout and durable write failure.
    pub async fn add(&self, name: String, profile: ProviderProfile) -> io::Result<()> {
        validate_name(&name)?;
        profile.validate()?;
        let root = self.root.clone();
        let timeout = self.lock_timeout;
        tokio::task::spawn_blocking(move || {
            let _catalog = catalog_lock(&root, timeout, false)?;
            let path = profile_path(&root, &name)?;
            let _lease = profile_lock(&root, &name, timeout)?;
            ensure_profile_directory(&root)?;
            match read_profile(&path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "provider profile already exists",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            write_profile(&path, &profile)
        })
        .await
        .map_err(|_| io::Error::other("provider profile worker failed"))?
    }

    /// Read one validated profile without exposing its values to diagnostics.
    /// # Errors
    /// Rejects missing, insecure, oversized or invalid profile files and lock failures.
    pub async fn get(&self, name: String) -> io::Result<ProviderProfile> {
        validate_name(&name)?;
        let root = self.root.clone();
        let timeout = self.lock_timeout;
        tokio::task::spawn_blocking(move || {
            let _lease = profile_lock(&root, &name, timeout)?;
            let path = profile_path(&root, &name)?;
            read_profile(&path)
        })
        .await
        .map_err(|_| io::Error::other("provider profile read worker failed"))?
    }

    /// List profile names only; custom values are never returned by this method.
    /// # Errors
    /// Rejects linked/unsafe directories and corrupt profiles; never exposes custom values.
    pub async fn names(&self) -> io::Result<Vec<String>> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || list_names(&root))
            .await
            .map_err(|_| io::Error::other("provider profile list worker failed"))?
    }

    /// Replace one profile atomically, preserving the stable profile ID.
    /// # Errors
    /// Rejects missing or unsafe profiles, invalid values, lock timeout and durable write failure.
    pub async fn update(&self, name: String, profile: ProviderProfile) -> io::Result<()> {
        validate_name(&name)?;
        profile.validate()?;
        let root = self.root.clone();
        let timeout = self.lock_timeout;
        tokio::task::spawn_blocking(move || {
            let _catalog = catalog_lock(&root, timeout, false)?;
            let _lease = profile_lock(&root, &name, timeout)?;
            let path = profile_path(&root, &name)?;
            read_profile(&path)?;
            write_profile(&path, &profile)
        })
        .await
        .map_err(|_| io::Error::other("provider profile update worker failed"))?
    }

    /// Remove an unused profile. Callers check certificate references first.
    /// # Errors
    /// Rejects referenced or unsafe profiles, lock contention and removal/sync failures.
    pub async fn remove(&self, name: String) -> io::Result<()> {
        validate_name(&name)?;
        let root = self.root.clone();
        let timeout = self.lock_timeout;
        tokio::task::spawn_blocking(move || {
            let _catalog = catalog_lock(&root, timeout, false)?;
            let _lease = profile_lock(&root, &name, timeout)?;
            let path = profile_path(&root, &name)?;
            read_profile(&path)?;
            if crate::issuance::provider_referenced(&root, &name)? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "provider profile is referenced by a retained certificate",
                ));
            }
            fs::remove_file(&path)?;
            crate::state_file::sync_directory(&root.join("providers"))
        })
        .await
        .map_err(|_| io::Error::other("provider profile removal worker failed"))?
    }
}

fn catalog_lock(
    root: &Path,
    timeout: Duration,
    shared: bool,
) -> io::Result<crate::toml_file::FileLease> {
    if timeout.is_zero() || timeout > Duration::from_secs(300) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid provider lock timeout",
        ));
    }
    let path =
        crate::toml_file::object_lock(root, crate::toml_file::ObjectKind::Provider, ".registry")
            .map_err(|_| io::Error::other("cannot prepare provider registry lock"))?;
    let file = crate::toml_file::open_lock(&path)?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let result = if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        };
        match result {
            Ok(()) => return Ok(crate::toml_file::FileLease(file)),
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "provider registry is busy",
                ));
            }
            Err(_) => return Err(io::Error::other("cannot lock provider registry")),
        }
    }
}

fn validate_name(name: &str) -> io::Result<()> {
    if crate::account::valid_account_name(name) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid provider profile name",
        ))
    }
}

fn validate_zone(zone: &str) -> io::Result<()> {
    let value = zone.strip_suffix('.').unwrap_or(zone);
    if value.is_empty()
        || value.len() > 253
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid allowed DNS zone",
        ));
    }
    Ok(())
}

fn profile_path(root: &Path, name: &str) -> io::Result<PathBuf> {
    validate_name(name)?;
    Ok(root.join("providers").join(format!("{name}.toml")))
}

fn profile_lock(
    root: &Path,
    name: &str,
    timeout: Duration,
) -> io::Result<crate::toml_file::FileLease> {
    let path = crate::toml_file::object_lock(root, crate::toml_file::ObjectKind::Provider, name)
        .map_err(|_| io::Error::other("cannot prepare provider profile lock"))?;
    crate::toml_file::lock(&path, timeout)
}

fn ensure_profile_directory(root: &Path) -> io::Result<()> {
    crate::toml_file::durable_private_dir(root)
        .map_err(|_| io::Error::other("cannot prepare data directory"))?;
    crate::toml_file::durable_private_dir(&root.join("providers"))
        .map_err(|_| io::Error::other("cannot prepare provider profile directory"))
}

fn read_profile(path: &Path) -> io::Result<ProviderProfile> {
    let bytes = crate::state_file::read_private(path, PROFILE_LIMIT)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "provider profile is not UTF-8"))?;
    let profile: ProviderProfile = toml::from_str(text)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid provider profile TOML"))?;
    profile.validate()?;
    Ok(profile)
}

fn write_profile(path: &Path, profile: &ProviderProfile) -> io::Result<()> {
    profile.validate()?;
    let text = toml::to_string(profile).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "cannot encode provider profile")
    })?;
    if text.len() > PROFILE_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "provider profile exceeds size limit",
        ));
    }
    crate::toml_file::atomic_write(path, text.as_bytes())
}

fn list_names(root: &Path) -> io::Result<Vec<String>> {
    let directory = root.join("providers");
    if !directory.exists() {
        return Ok(Vec::new());
    }
    crate::toml_file::ensure_real_dir(&directory).map_err(|_| {
        io::Error::new(io::ErrorKind::PermissionDenied, "unsafe provider directory")
    })?;
    let mut names = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "provider directory contains a symbolic link",
            ));
        }
        if !file_type.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid provider filename"))?
            .to_owned();
        validate_name(&name)?;
        read_profile(&path)?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use crate::provider::*;

    fn profile(executable: PathBuf) -> ProviderProfile {
        ProviderProfile::new(
            executable,
            vec!["--profile".into(), "prod".into()],
            vec!["example.net".into()],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn profile_crud_uses_one_private_file_and_preserves_custom_values() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProviderProfileStore::new(temp.path().into(), Duration::from_secs(2));
        let mut original = profile(std::env::current_exe().unwrap());
        original
            .provider_custom
            .insert("api_token".into(), serde_json::json!("sentinel-secret"));
        store
            .add("dns-prod".into(), original.clone())
            .await
            .unwrap();

        let path = temp.path().join("providers/dns-prod.toml");
        let saved = store.get("dns-prod".into()).await.unwrap();
        assert_eq!(saved, original);
        assert_eq!(store.names().await.unwrap(), vec!["dns-prod"]);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("sentinel-secret"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let mut update = saved;
        update.executable = temp.path().join("updated-provider");
        store
            .update("dns-prod".into(), update.clone())
            .await
            .unwrap();
        assert_eq!(store.get("dns-prod".into()).await.unwrap(), update);
        store.remove("dns-prod".into()).await.unwrap();
        assert!(store.get("dns-prod".into()).await.is_err());
        assert_eq!(store.names().await.unwrap(), [] as [std::string::String; 0]);
    }

    #[tokio::test]
    async fn invalid_profile_names_paths_zones_and_versions_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProviderProfileStore::new(temp.path().into(), Duration::from_secs(2));
        assert!(
            store
                .add(
                    "../escape".into(),
                    profile(std::env::current_exe().unwrap()),
                )
                .await
                .is_err()
        );
        assert!(
            ProviderProfile::new(
                PathBuf::from("relative/provider"),
                Vec::new(),
                vec!["example.net".into()]
            )
            .is_err()
        );
        assert!(
            ProviderProfile::new(
                std::env::current_exe().unwrap(),
                Vec::new(),
                vec!["-example.net".into()]
            )
            .is_err()
        );
        let mut profile = profile(std::env::current_exe().unwrap());
        profile.provider_profile_version = PROFILE_VERSION + 1;
        assert!(profile.validate().is_err());
    }

    #[tokio::test]
    async fn registry_lease_blocks_removal_and_invalid_updates_keep_previous_secret() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProviderProfileStore::new(temp.path().into(), Duration::from_millis(50));
        let mut value = profile(std::env::current_exe().unwrap());
        value
            .provider_custom
            .insert("token".into(), serde_json::json!("secret-sentinel"));
        store.add("prod".into(), value.clone()).await.unwrap();
        assert!(!format!("{value:?}").contains("secret-sentinel"));
        assert!(store.add("prod".into(), value.clone()).await.is_err());
        let lease = store.lease().await.unwrap();
        assert_eq!(
            store.remove("prod".into()).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(lease);
        assert!(
            store
                .edit("prod".into(), |profile| {
                    profile.allowed_zones = vec!["bad..zone".into()];
                    Ok(())
                })
                .await
                .is_err()
        );
        assert_eq!(store.get("prod".into()).await.unwrap(), value);
        store
            .edit("prod".into(), |profile| {
                profile.args.push("--new".into());
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            store.get("prod".into()).await.unwrap().provider_custom,
            value.provider_custom
        );
    }
    #[tokio::test]
    async fn corrupt_oversized_or_unsafe_profile_input_never_appears_in_errors() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProviderProfileStore::new(temp.path().into(), Duration::from_secs(1));
        store
            .add("prod".into(), profile(std::env::current_exe().unwrap()))
            .await
            .unwrap();
        let path = temp.path().join("providers/prod.toml");
        for bad in [
            "token = ['secret-sentinel'".to_owned(),
            "secret-sentinel".repeat(65536),
        ] {
            std::fs::write(&path, bad).unwrap();
            let error = store.get("prod".into()).await.unwrap_err();
            assert!(!error.to_string().contains("secret-sentinel"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::write(&path, "provider_profile_version = 1").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                store.get("prod".into()).await.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(temp.path().join("absent"), &path).unwrap();
            assert!(store.get("prod".into()).await.is_err());
            assert!(store.names().await.is_err());
        }
    }
    #[tokio::test]
    async fn referenced_profile_removal_is_checked_inside_registry_transaction() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProviderProfileStore::new(temp.path().into(), Duration::from_secs(1));
        store
            .add("prod".into(), profile(std::env::current_exe().unwrap()))
            .await
            .unwrap();
        let slot = temp.path().join("certs/test-cert");
        std::fs::create_dir_all(&slot).unwrap();
        let config = serde_json::json!({"version":1,"cert":{"name":"test-cert","identifiers":["example.com"],"key_algorithm":"ecdsa-p256","account_name":"default","account_id":"account","directory":"https://ca.example/directory","challenge":"dns-01","solver_id":"dns_external","solver_config":{"provider_instance_id":"prod"}}});
        crate::toml_file::atomic_write(
            &slot.join("cert.toml"),
            toml::to_string(&config).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(
            store.remove("prod".into()).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(store.get("prod".into()).await.is_ok());
    }
    #[tokio::test]
    async fn profile_named_registry_does_not_collide_with_registry_lock() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProviderProfileStore::new(temp.path().into(), Duration::from_millis(100));
        store
            .add("registry".into(), profile(std::env::current_exe().unwrap()))
            .await
            .unwrap();
        store.remove("registry".into()).await.unwrap();
    }
    #[tokio::test]
    async fn omitted_or_empty_profile_zones_mean_unrestricted_without_weakening_zone_validation() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProviderProfileStore::new(temp.path().into(), Duration::from_secs(1));
        let profile =
            ProviderProfile::new(std::env::current_exe().unwrap(), Vec::new(), Vec::new()).unwrap();
        store.add("prod".into(), profile.clone()).await.unwrap();
        assert_eq!(
            store.get("prod".into()).await.unwrap().allowed_zones,
            [] as [std::string::String; 0]
        );
        let path = temp.path().join("providers/prod.toml");
        let mut document: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        document.remove("allowed_zones");
        std::fs::write(&path, toml::to_string(&document).unwrap()).unwrap();
        assert_eq!(
            store.get("prod".into()).await.unwrap().allowed_zones,
            [] as [std::string::String; 0]
        );
        assert!(
            store
                .edit("prod".into(), |profile| {
                    profile.allowed_zones = vec!["*".into()];
                    Ok(())
                })
                .await
                .is_err()
        );
    }
}
