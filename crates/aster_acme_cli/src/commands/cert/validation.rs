//! CLI publication implementation choices, distinct from ACME protocol methods.
//! ACME owns derivation/acknowledgement/state; adapters own filesystem/user actions.
use crate::commands::cert::progress::Progress;
use aster_acme::{
    challenge::ChallengeKind,
    issuance::{IssueError, IssueRecord},
    solver::ChallengeSolver,
};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

mod dns_provider;
mod listener;
mod manual;
mod standalone;
mod tls_alpn;
mod webroot;

/// Stable user-facing implementation IDs; protocol method choices remain in ACME.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub(crate) enum ValidationMethod {
    /// Publish DNS-01 records through a configured native or external backend profile.
    #[value(name = "dns_provider")]
    #[serde(rename = "dns_provider")]
    DnsProvider,
    /// Publish DNS TXT values yourself.
    #[value(name = "manual_dns")]
    #[serde(rename = "manual_dns")]
    ManualDns,
    /// Provision persistent DNS TXT records once, then reuse them for renewals (draft-02).
    #[value(name = "dns_persist")]
    #[serde(rename = "dns_persist")]
    DnsPersist,
    /// Publish HTTP challenge files yourself using your existing HTTP server.
    #[value(name = "manual_http")]
    #[serde(rename = "manual_http")]
    ManualHttp,
    /// Write HTTP challenge files below the document root of your existing server.
    #[value(name = "webroot")]
    #[serde(rename = "webroot")]
    Webroot,
    /// Temporarily serve HTTP-01 challenges without an existing web server.
    #[value(name = "standalone")]
    #[serde(rename = "standalone")]
    Standalone,
    /// Temporarily serve TLS-ALPN-01 challenge certificates on a TLS listener.
    #[value(name = "tls_alpn")]
    #[serde(rename = "tls_alpn")]
    TlsAlpn,
}
impl ValidationMethod {
    pub(super) const fn automatic(self) -> bool {
        matches!(
            self,
            Self::DnsPersist | Self::DnsProvider | Self::Webroot | Self::Standalone | Self::TlsAlpn
        )
    }

    pub(super) const fn kind(self) -> ChallengeKind {
        match self {
            Self::ManualDns | Self::DnsProvider => ChallengeKind::Dns01,
            Self::DnsPersist => ChallengeKind::DnsPersist01,
            Self::ManualHttp | Self::Webroot | Self::Standalone => ChallengeKind::Http01,
            Self::TlsAlpn => ChallengeKind::TlsAlpn01,
        }
    }
    pub(super) const fn id(self) -> &'static str {
        match self {
            Self::ManualDns => "manual_dns",
            Self::DnsPersist => "dns_persist",
            Self::DnsProvider => "dns_provider",
            Self::ManualHttp => "manual_http",
            Self::Webroot => "webroot",
            Self::Standalone => "standalone",
            Self::TlsAlpn => "tls_alpn",
        }
    }
    pub(crate) fn from_id(id: &str) -> Result<Self, IssueError> {
        serde_json::from_value(serde_json::Value::String(id.to_owned())).map_err(|_| {
            IssueError::InvalidInput("saved validation implementation is not supported")
        })
    }

    pub(super) fn from_record(record: &IssueRecord) -> Result<Self, IssueError> {
        let method = Self::from_id(&record.solver_id)?;
        if method.kind() != record.challenge {
            return Err(IssueError::InvalidInput(
                "saved implementation does not match its ACME method",
            ));
        }
        Ok(method)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WebrootConfig {
    pub(super) root: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualConfig {}

/// The local endpoint is immutable across resume/renew. Public HTTP-01 still uses
/// port 80; nonstandard local ports require explicit forwarding by the operator.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StandaloneConfig {
    pub(super) listen_address: std::net::SocketAddr,
}

/// Resolve paths once before the request is saved. Resume/renew never re-resolve
/// a different cwd or replace the persisted implementation configuration.
pub(super) fn configuration(
    method: ValidationMethod,
    root: Option<&std::path::Path>,
    listen_address: Option<std::net::SocketAddr>,
) -> Result<serde_json::Value, IssueError> {
    if !matches!(
        method,
        ValidationMethod::Standalone | ValidationMethod::TlsAlpn
    ) && listen_address.is_some()
    {
        return Err(IssueError::InvalidInput(
            "--listen-address is only valid with -c standalone or -c tls_alpn",
        ));
    }
    match (method, root) {
        (ValidationMethod::Standalone, None) => {
            let address =
                listen_address.unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 80)));
            if address.port() == 0 {
                return Err(IssueError::InvalidInput(
                    "standalone listen port must be nonzero",
                ));
            }
            serde_json::to_value(StandaloneConfig {
                listen_address: address,
            })
            .map_err(|_| IssueError::InvalidInput("cannot encode standalone configuration"))
        }
        (ValidationMethod::TlsAlpn, None) => {
            let address =
                listen_address.unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 443)));
            if address.port() == 0 {
                return Err(IssueError::InvalidInput(
                    "TLS-ALPN listen port must be nonzero",
                ));
            }
            serde_json::to_value(StandaloneConfig {
                listen_address: address,
            })
            .map_err(|_| IssueError::InvalidInput("cannot encode TLS-ALPN configuration"))
        }
        (ValidationMethod::Webroot, Some(path)) => {
            let root = path.canonicalize().map_err(|_| {
                IssueError::InvalidInput("webroot must be an existing readable directory")
            })?;
            if !root.is_dir() {
                return Err(IssueError::InvalidInput("webroot must be a directory"));
            }
            serde_json::to_value(WebrootConfig { root })
                .map_err(|_| IssueError::InvalidInput("cannot encode webroot configuration"))
        }
        (ValidationMethod::Webroot, None) => Err(IssueError::InvalidInput(
            "webroot validation requires --webroot <PATH>",
        )),
        (ValidationMethod::DnsProvider, _) => Err(IssueError::InvalidInput(
            "dns_provider requires its provider profile configuration",
        )),
        (
            ValidationMethod::ManualDns
            | ValidationMethod::DnsPersist
            | ValidationMethod::ManualHttp,
            None,
        ) => serde_json::to_value(ManualConfig {})
            .map_err(|_| IssueError::InvalidInput("cannot encode manual validation configuration")),
        (
            ValidationMethod::ManualDns
            | ValidationMethod::DnsPersist
            | ValidationMethod::ManualHttp
            | ValidationMethod::Standalone
            | ValidationMethod::TlsAlpn,
            Some(_),
        ) => Err(IssueError::InvalidInput(
            "--webroot is only valid with -c webroot",
        )),
    }
}

pub(super) fn adapter(
    record: &IssueRecord,
    interactive: bool,
    yes: bool,
    progress: Arc<Progress>,
) -> Result<Box<dyn ChallengeSolver>, IssueError> {
    match ValidationMethod::from_record(record)? {
        ValidationMethod::Standalone => {
            let config: StandaloneConfig = serde_json::from_value(record.solver_config.clone())
                .map_err(|_| IssueError::InvalidInput("invalid saved standalone configuration"))?;
            if config.listen_address.port() == 0 {
                return Err(IssueError::InvalidInput(
                    "saved standalone listen port must be nonzero",
                ));
            }
            Ok(Box::new(standalone::Standalone::new(
                config.listen_address,
                progress,
            )))
        }
        ValidationMethod::DnsProvider => Err(IssueError::InvalidInput(
            "dns_provider requires its saved provider profile to be loaded by the CLI",
        )),
        ValidationMethod::TlsAlpn => {
            let config: StandaloneConfig = serde_json::from_value(record.solver_config.clone())
                .map_err(|_| IssueError::InvalidInput("invalid saved TLS-ALPN configuration"))?;
            if config.listen_address.port() == 0 {
                return Err(IssueError::InvalidInput(
                    "saved TLS-ALPN listen port must be nonzero",
                ));
            }
            Ok(Box::new(tls_alpn::TlsAlpn::new(
                config.listen_address,
                progress,
            )))
        }
        ValidationMethod::ManualDns
        | ValidationMethod::DnsPersist
        | ValidationMethod::ManualHttp => {
            let _: ManualConfig =
                serde_json::from_value(record.solver_config.clone()).map_err(|_| {
                    IssueError::InvalidInput("invalid saved manual validation configuration")
                })?;
            Ok(Box::new(manual::Manual {
                reusable: record
                    .renewal_of
                    .as_ref()
                    .map_or_else(Vec::new, |previous| previous.retained_validation.clone()),
                prompt: std::sync::Mutex::new(None),
                method: record.challenge,
                saved: record
                    .authorizations
                    .iter()
                    .any(|auth| auth.validation_requirement.is_some()),
                interactive,
                yes,
                progress,
            }))
        }
        ValidationMethod::Webroot => {
            let config: WebrootConfig = serde_json::from_value(record.solver_config.clone())
                .map_err(|_| IssueError::InvalidInput("invalid saved webroot configuration"))?;
            if !config.root.is_absolute() {
                return Err(IssueError::InvalidInput("saved webroot must be absolute"));
            }
            Ok(Box::new(webroot::Webroot {
                workers: crate::commands::cert::validation::webroot::workers::Workers::default(),
                root: config.root,
                operation: record.operation_id.clone(),
                progress,
            }))
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DnsProviderConfig {
    #[serde(default)]
    pub(super) dns_targets: std::collections::BTreeMap<String, String>,
    pub(super) backend_id: String,
    pub(super) backend_binding: String,
    pub(super) backend_config_version: u32,
    pub(super) provider_instance_id: String,
    pub(super) provider_profile_version: u32,
}

pub(super) fn parse_dns_targets(
    values: &[String],
) -> Result<std::collections::BTreeMap<String, String>, IssueError> {
    let mut result = std::collections::BTreeMap::new();
    let mut owner_targets = std::collections::BTreeMap::new();
    for value in values {
        let (domain, target) = value.split_once('=').ok_or(IssueError::InvalidInput(
            "DNS target must be DOMAIN=TXT_NAME",
        ))?;
        let identifier = aster_acme::identifier::DnsIdentifier::new(domain)?;
        let target = aster_acme_dns::routing::absolute_name(target).map_err(IssueError::from)?;
        if owner_targets
            .insert(identifier.name().as_str().to_owned(), target.clone())
            .is_some_and(|previous| previous != target)
        {
            return Err(IssueError::InvalidInput(
                "domains sharing a DNS challenge name must use the same target",
            ));
        }
        if result.insert(identifier.value(), target).is_some() {
            return Err(IssueError::InvalidInput("duplicate DNS target domain"));
        }
    }
    Ok(result)
}

pub(super) fn provider_configuration(
    provider: Option<&str>,
) -> Result<serde_json::Value, IssueError> {
    let Some(provider_instance_id) = provider else {
        return Err(IssueError::InvalidInput(
            "dns_provider requires --provider <PROFILE>",
        ));
    };
    if !aster_acme_cli_storage::account::valid_account_name(provider_instance_id) {
        return Err(IssueError::InvalidInput(
            "invalid DNS provider profile name",
        ));
    }
    serde_json::to_value(DnsProviderConfig {
        dns_targets: std::collections::BTreeMap::new(),
        backend_id: String::new(),
        backend_binding: String::new(),
        backend_config_version: 1,
        provider_instance_id: provider_instance_id.to_owned(),
        provider_profile_version:
            aster_acme_cli_storage::provider::ProviderProfile::CURRENT_VERSION,
    })
    .map_err(|_| IssueError::InvalidInput("cannot encode DNS provider configuration"))
}

pub(super) async fn bound_provider_configuration(
    provider: Option<&str>,
    root: &std::path::Path,
) -> Result<serde_json::Value, IssueError> {
    let mut config: DnsProviderConfig =
        serde_json::from_value(provider_configuration(provider)?)
            .map_err(|_| IssueError::InvalidInput("invalid DNS provider reference"))?;
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        root.into(),
        std::time::Duration::from_secs(5),
    );
    let profile = store
        .get(config.provider_instance_id.clone())
        .await
        .map_err(|_| IssueError::InvalidInput("cannot load DNS provider profile"))?;
    let registry = crate::commands::provider::runtime::registry()
        .map_err(aster_acme_dns::ProviderFailure::from)?;
    let backend = registry
        .require(&profile.backend_id)
        .map_err(aster_acme_dns::ProviderFailure::from)?;
    let options = (&profile).into();
    backend
        .validate(&options)
        .map_err(aster_acme_dns::ProviderFailure::from)?;
    config.backend_id = profile.backend_id;
    config.backend_binding = backend
        .binding(&options)
        .map_err(aster_acme_dns::ProviderFailure::from)?;
    config.backend_config_version = backend.descriptor().config_version;
    serde_json::to_value(config)
        .map_err(|_| IssueError::InvalidInput("cannot encode bound DNS provider reference"))
}

pub(super) async fn validate_provider_binding(
    saved: &serde_json::Value,
    root: &std::path::Path,
) -> Result<(), IssueError> {
    let mut config: DnsProviderConfig = serde_json::from_value(saved.clone())
        .map_err(|_| IssueError::InvalidInput("invalid saved DNS provider profile reference"))?;
    let mappings = config.dns_targets;
    let expected = bound_provider_configuration(Some(&config.provider_instance_id), root).await?;
    config = serde_json::from_value(expected)
        .map_err(|_| IssueError::InvalidInput("cannot validate DNS provider binding"))?;
    config.dns_targets = mappings;
    let expected = serde_json::to_value(config)
        .map_err(|_| IssueError::InvalidInput("cannot validate DNS provider binding"))?;
    if &expected != saved {
        return Err(IssueError::InvalidInput(
            "DNS provider backend or remote scope changed before request creation",
        ));
    }
    Ok(())
}

pub(super) async fn provider_adapter(
    record: &IssueRecord,
    root: &std::path::Path,
    progress: Arc<Progress>,
    http: aster_acme_dns_http::ForgeDnsHttp,
) -> Result<Box<dyn ChallengeSolver>, IssueError> {
    let config: DnsProviderConfig = serde_json::from_value(record.solver_config.clone())
        .map_err(|_| IssueError::InvalidInput("invalid saved DNS provider profile reference"))?;
    let saved_mappings = config
        .dns_targets
        .iter()
        .map(|(domain, target)| format!("{domain}={target}"))
        .collect::<Vec<_>>();
    if parse_dns_targets(&saved_mappings).ok().as_ref() != Some(&config.dns_targets)
        || config.dns_targets.keys().any(|domain| {
            !record
                .identifiers
                .iter()
                .any(|identifier| identifier.value() == *domain)
        })
    {
        return Err(IssueError::InvalidInput("invalid saved DNS target mapping"));
    }
    let store = aster_acme_cli_storage::provider::ProviderProfileStore::new(
        root.to_path_buf(),
        std::time::Duration::from_secs(5),
    );
    let profile = store
        .get(config.provider_instance_id.clone())
        .await
        .map_err(|error| {
            IssueError::Publication(format!(
                "cannot load DNS provider profile '{}': {error}",
                config.provider_instance_id
            ))
        })?;
    profile
        .validate()
        .map_err(|_| IssueError::InvalidInput("saved DNS provider profile is invalid"))?;
    if profile.provider_profile_version != config.provider_profile_version {
        return Err(IssueError::InvalidInput(
            "provider profile version differs from saved certificate definition",
        ));
    }
    let registry = crate::commands::provider::runtime::registry()
        .map_err(aster_acme_dns::ProviderFailure::from)?;
    let backend = registry
        .require(&profile.backend_id)
        .map_err(aster_acme_dns::ProviderFailure::from)?;
    let options = (&profile).into();
    if config.backend_id != profile.backend_id
        || config.backend_config_version != backend.descriptor().config_version
        || config.backend_binding
            != backend
                .binding(&options)
                .map_err(aster_acme_dns::ProviderFailure::from)?
    {
        return Err(IssueError::InvalidInput(
            "DNS provider backend or remote scope differs from saved certificate definition",
        ));
    }
    let lookup = aster_acme_dns_resolver::SystemDns::new();
    Ok(Box::new(dns_provider::ProviderDns {
        context: aster_acme_dns::ProviderContext {
            provider_instance_id: config.provider_instance_id,
            provider_profile_version: profile.provider_profile_version,
            provider_custom: profile.provider_custom.clone().into_iter().collect(),
        },
        provider: crate::commands::provider::runtime::registry()
            .map_err(aster_acme_dns::ProviderFailure::from)?
            .provider(
                &profile.backend_id,
                &(&profile).into(),
                aster_acme_dns::operation::ProviderHost {
                    timeout: std::time::Duration::from_secs(profile.timeout_seconds),
                    http: Arc::new(http),
                    credentials: Some(Arc::new(
                        crate::commands::provider::runtime::PrivateCredentials,
                    )),
                    publications: Arc::new(
                        aster_acme_cli_storage::provider_publication::ProviderPublicationStore::new(
                            root.to_path_buf(),
                        ),
                    ),
                },
            )
            .map_err(aster_acme_dns::ProviderFailure::from)?,
        lookup: Arc::new(lookup),
        allowed_zones: profile.allowed_zones,
        dns_targets: config.dns_targets,
        propagation: aster_acme_dns::propagation::PropagationPolicy {
            initial_delay: std::time::Duration::from_secs(profile.propagation_interval),
            timeout: std::time::Duration::from_secs(profile.propagation_timeout),
            ..aster_acme_dns::propagation::PropagationPolicy::default()
        },
        progress,
    }))
}

/// Retry a saved provider's terminal publication cleanup without any CA/account key.
pub(crate) async fn cleanup_provider(
    root: &std::path::Path,
    session: &dyn aster_acme::storage::issuance::IssueSession,
    output: crate::common::session::OutputSession,
    execution: &aster_acme::solver::ExecutionContext,
    http: aster_acme_dns_http::ForgeDnsHttp,
) -> Result<IssueRecord, IssueError> {
    let saved = session.record().await?;
    if ValidationMethod::from_record(&saved)? != ValidationMethod::DnsProvider {
        return Err(IssueError::InvalidInput(
            "provider cleanup requires DNS provider validation",
        ));
    }
    let solver = provider_adapter(&saved, root, Arc::new(Progress::new(output)), http).await?;
    let result =
        aster_acme::issuance::publication::cleanup(session, solver.as_ref(), execution).await;
    solver.shutdown().await;
    result
}

#[cfg(test)]
pub(crate) mod tests;
