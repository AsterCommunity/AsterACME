//! Google Cloud DNS changes transactions with durable publication ownership.
use crate::provider::{common::rpc::settings, vendors::google_cloud_dns::operation::Factory};
use aster_acme_dns::{
    ProviderError,
    backend::{
        BackendConfig, BackendDescriptor, BackendImplementation, BackendRegistration, ConfigField,
        ConfigFieldKind, DnsBackend, MutationModel, configuration_error,
    },
};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use zeroize::ZeroizeOnDrop;

mod api;
mod auth;
mod operation;

/// Registry identity of the opt-in Google Cloud DNS backend.
pub const BACKEND_ID: &str = "com.astercosm.acme.dns.google-cloud-dns";

#[linkme::distributed_slice(aster_acme_dns::backend::BACKENDS)]
static REGISTRATION: BackendRegistration = BackendRegistration {
    create: || Arc::new(GoogleCloudDnsBackend),
};

/// Service-account authenticated Google Cloud DNS backend; no direct I/O.
pub struct GoogleCloudDnsBackend;

#[derive(Clone, Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Config {
    service_account: ServiceAccount,
}

// Google key downloads include additional non-secret certificate metadata.
#[derive(Clone, Deserialize, ZeroizeOnDrop)]
struct ServiceAccount {
    #[serde(rename = "type")]
    kind: String,
    project_id: String,
    client_email: String,
    private_key: String,
    private_key_id: String,
    token_uri: String,
}

fn config(input: &BackendConfig) -> Result<Config, ProviderError> {
    let result: Config = settings(input)?;
    let account = &result.service_account;
    if account.kind != "service_account"
        || !safe_id(&account.project_id)
        || account.client_email.len() > 254
        || !account.client_email.ends_with(".gserviceaccount.com")
        || !account
            .client_email
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._-".contains(&b))
        || account.client_email.bytes().filter(|b| *b == b'@').count() != 1
        || !safe_id(&account.private_key_id)
        || account.token_uri != auth::TOKEN_URL
    {
        return Err(configuration_error(
            "invalid Google service account identity or token endpoint",
        ));
    }
    auth::key(account)?;
    Ok(result)
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

impl DnsBackend for GoogleCloudDnsBackend {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            id: BACKEND_ID,
            label: "Google Cloud DNS",
            config_version: 1,
            executable: false,
            mutation_model: MutationModel::ConditionalRrsets,
            fields: &[ConfigField {
                name: "service_account",
                label: "Google service account JSON",
                required: true,
                kind: ConfigFieldKind::Json,
                sensitive: true,
            }],
        }
    }

    fn validate(&self, input: &BackendConfig) -> Result<(), ProviderError> {
        config(input).map(|_| ())
    }

    fn binding(&self, input: &BackendConfig) -> Result<String, ProviderError> {
        Ok(format!(
            "google-cloud-dns:{}",
            config(input)?.service_account.project_id
        ))
    }

    fn create(&self, input: &BackendConfig) -> Result<BackendImplementation, ProviderError> {
        Ok(BackendImplementation::Native(Arc::new(Factory {
            config: config(input)?,
            token: Arc::new(Mutex::new(None)),
        })))
    }
}

#[cfg(test)]
mod tests;
