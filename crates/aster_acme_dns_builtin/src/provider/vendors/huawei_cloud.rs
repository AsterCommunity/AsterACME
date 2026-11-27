//! Huawei Cloud public DNS `RRset` backend.
//!
//! The API exposes whole-record-set PUT/DELETE operations without a public
//! revision precondition. This backend therefore preserves values and durable
//! intent, but cannot guarantee that a concurrent remote writer is not
//! overwritten. The official SDK request metadata at a pinned revision
//! declares only the whole-object operations:
//! <https://github.com/huaweicloud/huaweicloud-sdk-go-v3/blob/3da3be180a23bcbf8f6e668606c6ef26e76e95af/services/dns/v2/dns_meta.go#L1711>
use crate::provider::{
    common::rpc::{key_field, settings, validate_keys},
    vendors::huawei_cloud::operation::Factory,
};
use aster_acme_dns::{
    ProviderError,
    backend::{
        BackendConfig, BackendDescriptor, BackendImplementation, BackendRegistration, DnsBackend,
        MutationModel, configuration_error,
    },
};
use serde::Deserialize;
use std::sync::Arc;
use zeroize::ZeroizeOnDrop;
mod api;
mod operation;
mod txt;
/// Backend identifier under which the Huawei Cloud DNS provider registers.
pub const BACKEND_ID: &str = "com.astercosm.acme.dns.huawei-cloud";
const DEFAULT_REGION: &str = "cn-north-4";

#[linkme::distributed_slice(aster_acme_dns::backend::BACKENDS)]
static REGISTRATION: BackendRegistration = BackendRegistration {
    create: || Arc::new(HuaweiCloudBackend),
};

/// Huawei Cloud DNS backend over the Huawei Cloud public API.
pub struct HuaweiCloudBackend;

#[derive(Clone, Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Config {
    access_key_id: String,
    access_key_secret: String,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default = "default_region")]
    region: String,
}

fn default_region() -> String {
    DEFAULT_REGION.into()
}

fn decode_config(config: &BackendConfig) -> Result<Config, ProviderError> {
    let mut config: Config = settings(config)?;
    validate_keys(&config.access_key_id, &config.access_key_secret)?;
    if config.region.len() > 32
        || config.region.is_empty()
        || !config
            .region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-'))
    {
        return Err(configuration_error("invalid Huawei Cloud region"));
    }
    if config
        .project_id
        .as_ref()
        .is_some_and(|id| !valid_project_id(id))
    {
        return Err(configuration_error(
            "Huawei Cloud project_id must contain 32 hexadecimal characters",
        ));
    }
    if let Some(project_id) = &mut config.project_id {
        *project_id = project_id.to_ascii_lowercase();
    }
    Ok(config)
}

const FIELDS: &[aster_acme_dns::backend::ConfigField] = &[
    key_field("access_key_id", "Huawei Cloud Access Key ID"),
    key_field("access_key_secret", "Huawei Cloud Secret Access Key"),
    aster_acme_dns::backend::ConfigField {
        name: "project_id",
        label: "Huawei Cloud project ID (optional; discover automatically)",
        required: false,
        kind: aster_acme_dns::backend::ConfigFieldKind::Text,
        sensitive: false,
    },
    aster_acme_dns::backend::ConfigField {
        name: "region",
        label: "Huawei Cloud region (optional; default cn-north-4)",
        required: false,
        kind: aster_acme_dns::backend::ConfigFieldKind::Text,
        sensitive: false,
    },
];

impl DnsBackend for HuaweiCloudBackend {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            id: BACKEND_ID,
            label: "Huawei Cloud DNS (non-atomic RRset)",
            config_version: 1,
            executable: false,
            mutation_model: MutationModel::BestEffortRrsets,
            fields: FIELDS,
        }
    }

    fn validate(&self, config: &BackendConfig) -> Result<(), ProviderError> {
        decode_config(config).map(|_| ())
    }

    fn binding(&self, config: &BackendConfig) -> Result<String, ProviderError> {
        let config = decode_config(config)?;
        Ok(format!(
            "{}:{}:best-effort",
            config.region,
            config
                .project_id
                .as_ref()
                .map_or_else(|| "auto".into(), |id| id.to_ascii_lowercase())
        ))
    }

    fn create(&self, config: &BackendConfig) -> Result<BackendImplementation, ProviderError> {
        Ok(BackendImplementation::Native(Arc::new(Factory {
            config: decode_config(config)?,
        })))
    }
}

pub(super) fn valid_project_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests;
