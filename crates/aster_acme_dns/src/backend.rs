//! Validated provider catalog: metadata and construction share one owner.
use crate::{
    DnsProvider, ProviderError, ProviderErrorCode, SideEffect,
    operation::{OperationFactory, ProviderHost, RegisteredProvider},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

/// External executable backend; independent of the ADPP wire version.
pub const ADPP_BACKEND_ID: &str = "com.astercosm.acme.adpp";

/// Host-renderable value kinds; provider validation owns domain constraints.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigFieldKind {
    Text,
    Boolean,
    Integer,
    Json,
}

/// One provider-owned configuration field used by generic hosts.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ConfigField {
    pub name: &'static str,
    pub label: &'static str,
    pub required: bool,
    pub kind: ConfigFieldKind,
    pub sensitive: bool,
}

/// Remote write primitive required by this implementation.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationModel {
    IndividualRecords,
    ConditionalRrsets,
    BestEffortRrsets,
    ExternalProtocol,
}

/// Transport-independent metadata; describes precisely the implementation built here.
#[derive(Debug, Clone, Serialize)]
pub struct BackendDescriptor {
    pub id: &'static str,
    pub label: &'static str,
    pub config_version: u32,
    pub executable: bool,
    pub mutation_model: MutationModel,
    pub fields: &'static [ConfigField],
}

/// Private construction input. Never log or display arbitrary configuration values.
#[derive(Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub version: u32,
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub custom: serde_json::Map<String, serde_json::Value>,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            version: 1,
            executable: PathBuf::new(),
            args: Vec::new(),
            custom: serde_json::Map::new(),
        }
    }
}

impl std::fmt::Debug for BackendConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendConfig").finish_non_exhaustive()
    }
}

/// Implementation selected by a descriptor, without host I/O during construction.
pub enum BackendImplementation {
    Native(Arc<dyn OperationFactory>),
    External(Arc<dyn DnsProvider>),
}

/// One backend owns its configuration, remote identity and operation construction.
pub trait DnsBackend: Send + Sync {
    fn descriptor(&self) -> BackendDescriptor;
    /// Validate configuration offline. Errors must not echo credentials.
    /// # Errors
    /// Rejects malformed or unsupported backend configuration without echoing values.
    fn validate(&self, config: &BackendConfig) -> Result<(), ProviderError>;
    /// Stable, non-sensitive remote scope; credential rotation must not change it.
    /// # Errors
    /// Rejects configurations whose stable remote identity cannot be determined offline.
    fn binding(&self, config: &BackendConfig) -> Result<String, ProviderError>;
    /// # Errors
    /// Rejects invalid configuration or unavailable operation implementations.
    fn create(&self, config: &BackendConfig) -> Result<BackendImplementation, ProviderError>;
}

/// Statically collected factories. Runtime registry instances remain caller-owned.
pub struct BackendRegistration {
    pub create: fn() -> Arc<dyn DnsBackend>,
}

#[linkme::distributed_slice]
pub static BACKENDS: [BackendRegistration];

/// Explicit, immutable registry, also usable with injected third-party implementations.
#[derive(Clone)]
pub struct ProviderRegistry {
    backends: BTreeMap<String, Arc<dyn DnsBackend>>,
}

impl ProviderRegistry {
    /// Collect only backends actually linked into this binary.
    /// # Errors
    /// Rejects duplicate IDs and invalid descriptor contracts.
    pub fn linked() -> Result<Self, ProviderError> {
        Self::new(BACKENDS.iter().map(|entry| (entry.create)()).collect())
    }

    /// Construct an isolated registry without changing global runtime state.
    /// # Errors
    /// Rejects invalid descriptors and duplicate IDs instead of order-dependent overrides.
    pub fn new(backends: Vec<Arc<dyn DnsBackend>>) -> Result<Self, ProviderError> {
        let mut entries = BTreeMap::new();
        for backend in backends {
            let descriptor = backend.descriptor();
            let mut fields = BTreeSet::new();
            if !valid_backend_id(descriptor.id)
                || descriptor.label.is_empty()
                || descriptor.config_version == 0
                || descriptor.fields.iter().any(|field| {
                    field.name.is_empty() || field.label.is_empty() || !fields.insert(field.name)
                })
                || entries.insert(descriptor.id.to_owned(), backend).is_some()
            {
                return Err(configuration_error(
                    "invalid or duplicate DNS backend descriptor",
                ));
            }
        }
        Ok(Self { backends: entries })
    }

    #[must_use]
    pub fn descriptors(&self) -> Vec<BackendDescriptor> {
        self.backends
            .values()
            .map(|backend| backend.descriptor())
            .collect()
    }

    /// Resolve both configuration and runtime dispatch through the same catalog.
    /// # Errors
    /// Unknown/disabled backend IDs fail closed.
    pub fn require(&self, id: &str) -> Result<&dyn DnsBackend, ProviderError> {
        self.backends
            .get(id)
            .map(AsRef::as_ref)
            .ok_or_else(|| configuration_error("DNS backend is unavailable in this build"))
    }

    /// Construct a bound provider with host-owned execution and durable recovery storage.
    /// # Errors
    /// Rejects unavailable implementations, invalid configuration and invalid bindings.
    pub fn provider(
        &self,
        id: &str,
        config: &BackendConfig,
        host: ProviderHost,
    ) -> Result<Arc<dyn DnsProvider>, ProviderError> {
        if host.timeout.is_zero() || host.timeout > std::time::Duration::from_secs(300) {
            return Err(configuration_error(
                "DNS provider timeout must be within 1..=300 seconds",
            ));
        }
        let backend = self.require(id)?;
        if config.version != backend.descriptor().config_version {
            return Err(configuration_error(
                "unsupported DNS backend configuration version",
            ));
        }
        backend.validate(config)?;
        let binding = backend.binding(config)?;
        if binding.is_empty() || binding.len() > 4096 || binding.chars().any(char::is_control) {
            return Err(configuration_error("invalid DNS backend binding"));
        }
        Ok(Arc::new(RegisteredProvider::new(
            id.to_owned(),
            binding,
            backend.create(config)?,
            host,
        )))
    }
}

#[must_use]
pub fn valid_backend_id(id: &str) -> bool {
    id.len() <= 192
        && id.split('.').count() >= 3
        && id.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

#[must_use]
pub fn configuration_error(message: &'static str) -> ProviderError {
    ProviderError {
        code: ProviderErrorCode::InvalidRequest,
        message: message.into(),
        side_effect: SideEffect::None,
        retry_after_seconds: None,
        provider_code: None,
    }
}
