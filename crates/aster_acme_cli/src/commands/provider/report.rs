//! Safe provider report models, without credentials.
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub(super) struct ProfileView {
    pub(super) ttl_seconds: u32,
    pub(super) backend_id: String,
    pub(super) backend_config_version: u32,
    pub(super) name: String,
    pub(super) profile_path: PathBuf,
    pub(super) executable: PathBuf,
    pub(super) args: Vec<String>,
    pub(super) allowed_zones: Vec<String>,
    pub(super) profile_version: u32,
    pub(super) custom_values: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CleanupView {
    pub(super) certificate: String,
    pub(super) operation: String,
    pub(super) completed: bool,
    pub(super) error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProviderReport {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) backends: Vec<aster_acme_dns::backend::BackendDescriptor>,
    pub(super) operation: &'static str,
    pub(super) profiles: Vec<ProfileView>,
    pub(super) removed: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) cleanup: Vec<CleanupView>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(super) cancelled: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(super) incomplete: bool,
}

impl ProviderReport {
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    pub(crate) fn has_failures(&self) -> bool {
        self.incomplete || self.cleanup.iter().any(|item| !item.completed)
    }
}

pub(super) fn view(
    name: String,
    profile_path: PathBuf,
    profile: aster_acme_cli_storage::provider::ProviderProfile,
) -> ProfileView {
    ProfileView {
        ttl_seconds: profile.ttl_seconds,
        backend_id: profile.backend_id,
        backend_config_version: profile.backend_config_version,
        name,
        profile_path,
        executable: profile.executable,
        args: profile.args,
        allowed_zones: profile.allowed_zones,
        profile_version: profile.provider_profile_version,
        custom_values: format!("<redacted: {} value(s)>", profile.provider_custom.len()),
    }
}
