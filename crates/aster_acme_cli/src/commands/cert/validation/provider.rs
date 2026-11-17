//! CLI provider profile binding and solver construction.
use crate::commands::cert::{
    progress::Progress,
    validation::{ValidationMethod, dns_provider},
};
use aster_acme::{
    issuance::{IssueError, IssueRecord},
    solver::ChallengeSolver,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::commands::cert) struct DnsProviderConfig {
    #[serde(default)]
    pub(in crate::commands::cert) dns_targets: std::collections::BTreeMap<String, String>,
    pub(in crate::commands::cert) backend_id: String,
    pub(in crate::commands::cert) backend_binding: String,
    pub(in crate::commands::cert) backend_config_version: u32,
    pub(in crate::commands::cert) provider_instance_id: String,
    pub(in crate::commands::cert) provider_profile_version: u32,
}

pub(in crate::commands::cert) fn parse_dns_targets(
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

pub(in crate::commands::cert) fn provider_configuration(
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

pub(in crate::commands) async fn bound_provider_configuration(
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

pub(in crate::commands::cert) async fn validate_provider_binding(
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

pub(in crate::commands::cert) async fn provider_adapter(
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
        ttl_seconds: profile.ttl_seconds,
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
