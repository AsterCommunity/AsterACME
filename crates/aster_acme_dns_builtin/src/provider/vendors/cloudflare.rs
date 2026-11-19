//! Cloudflare API v4 configuration and backend registration.
//! <https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/>
use aster_acme_dns::{
    ProviderError,
    backend::{
        BackendConfig, BackendDescriptor, BackendImplementation, BackendRegistration, ConfigField,
        DnsBackend, configuration_error,
    },
};
use serde::Deserialize;
use serde_json::Value;
use std::{path::PathBuf, sync::Arc};
mod operation;

/// Backend identifier under which the Cloudflare provider registers.
pub const BACKEND_ID: &str = "com.astercosm.acme.dns.cloudflare";
const API: &str = "https://api.cloudflare.com/client/v4";
const FIELDS: &[ConfigField] = &[
    ConfigField {
        name: "api_token",
        label: "Cloudflare API token (or use token_file)",
        required: false,
        kind: aster_acme_dns::backend::ConfigFieldKind::Text,
        sensitive: true,
    },
    ConfigField {
        name: "token_file",
        label: "Absolute private token file (or use api_token)",
        required: false,
        kind: aster_acme_dns::backend::ConfigFieldKind::Text,
        sensitive: false,
    },
    ConfigField {
        name: "zone_id",
        label: "Cloudflare zone ID (optional)",
        required: false,
        kind: aster_acme_dns::backend::ConfigFieldKind::Text,
        sensitive: false,
    },
];

#[linkme::distributed_slice(aster_acme_dns::backend::BACKENDS)]
static REGISTRATION: BackendRegistration = BackendRegistration {
    create: || Arc::new(CloudflareBackend),
};

/// Cloudflare DNS backend built from the Cloudflare API v4 record endpoints.
pub struct CloudflareBackend;

/// Cloudflare configuration. Explicit zone identity survives token rotation.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareConfig {
    /// Pinned Cloudflare zone ID; discovery by name is used when empty.
    #[serde(default)]
    pub zone_id: String,
    /// Cloudflare API token given inline; mutually exclusive with `token_file`.
    pub api_token: Option<String>,
    /// Private file holding the API token; mutually exclusive with `api_token`.
    pub token_file: Option<PathBuf>,
}

impl CloudflareConfig {
    /// Validate pinned zone and mutually exclusive credential sources without I/O.
    /// # Errors
    /// Rejects malformed zone IDs, missing/conflicting credentials and invalid token paths.
    pub fn validate(&self) -> Result<(), ProviderError> {
        if !self.zone_id.is_empty() && !valid_zone(&self.zone_id) {
            return Err(configuration_error(
                "Cloudflare zone_id must be 32 hexadecimal characters",
            ));
        }
        match (&self.api_token, &self.token_file) {
            (None, None) => {
                return Err(configuration_error(
                    "Cloudflare requires api_token or token_file",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(configuration_error(
                    "Cloudflare accepts only one of api_token and token_file",
                ));
            }
            (Some(token), None) if !valid_token(token) => {
                return Err(configuration_error(
                    "Cloudflare api_token must be 1–4096 printable ASCII characters without spaces",
                ));
            }
            (None, Some(path)) if !path.is_absolute() => {
                return Err(configuration_error(
                    "Cloudflare token_file must be an absolute path",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

impl DnsBackend for CloudflareBackend {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            id: BACKEND_ID,
            label: "Cloudflare",
            config_version: 1,
            executable: false,
            mutation_model: aster_acme_dns::backend::MutationModel::IndividualRecords,
            fields: FIELDS,
        }
    }
    fn validate(&self, config: &BackendConfig) -> Result<(), ProviderError> {
        decode(config).map(|_| ())
    }
    fn binding(&self, config: &BackendConfig) -> Result<String, ProviderError> {
        let zone = decode(config)?.zone_id.to_ascii_lowercase();
        Ok(if zone.is_empty() { "auto".into() } else { zone })
    }
    fn create(&self, config: &BackendConfig) -> Result<BackendImplementation, ProviderError> {
        Ok(BackendImplementation::Native(Arc::new(Cloudflare::new(
            decode(config)?,
        )?)))
    }
}

fn decode(config: &BackendConfig) -> Result<CloudflareConfig, ProviderError> {
    if config.version != 1 {
        return Err(configuration_error(
            "unsupported Cloudflare configuration version",
        ));
    }
    if !config.executable.as_os_str().is_empty() || !config.args.is_empty() {
        return Err(configuration_error(
            "Cloudflare does not accept executable arguments",
        ));
    }
    let decoded: CloudflareConfig = serde_json::from_value(Value::Object(config.custom.clone()))
        .map_err(|_| configuration_error("invalid Cloudflare configuration"))?;
    decoded.validate()?;
    Ok(decoded)
}

/// Directly constructible operation factory for embedded users; no host I/O occurs here.
pub struct Cloudflare {
    config: CloudflareConfig,
}
impl Cloudflare {
    /// # Errors
    /// Rejects invalid Cloudflare configuration.
    pub fn new(mut config: CloudflareConfig) -> Result<Self, ProviderError> {
        config.validate()?;
        config.zone_id.make_ascii_lowercase();
        Ok(Self { config })
    }
}

fn valid_zone(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn valid_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && value.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests;
