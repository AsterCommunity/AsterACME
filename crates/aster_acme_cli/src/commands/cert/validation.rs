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

mod dns_external;
mod listener;
mod manual;
mod standalone;
mod tls_alpn;
mod webroot;

/// Stable user-facing implementation IDs; protocol method choices remain in ACME.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub(crate) enum ValidationMethod {
    /// Publish DNS TXT values yourself.
    #[value(name = "manual_dns")]
    #[serde(rename = "manual_dns")]
    ManualDns,
    /// Provision persistent DNS TXT records once, then reuse them for renewals (draft-02).
    #[value(name = "dns_persist")]
    #[serde(rename = "dns_persist")]
    DnsPersist,
    /// Publish DNS-01 records through a configured ADPP executable profile.
    #[value(name = "dns_external")]
    #[serde(rename = "dns_external")]
    DnsExternal,
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
            Self::DnsPersist | Self::DnsExternal | Self::Webroot | Self::Standalone | Self::TlsAlpn
        )
    }

    pub(super) const fn kind(self) -> ChallengeKind {
        match self {
            Self::ManualDns | Self::DnsExternal => ChallengeKind::Dns01,
            Self::DnsPersist => ChallengeKind::DnsPersist01,
            Self::ManualHttp | Self::Webroot | Self::Standalone => ChallengeKind::Http01,
            Self::TlsAlpn => ChallengeKind::TlsAlpn01,
        }
    }
    pub(super) const fn id(self) -> &'static str {
        match self {
            Self::ManualDns => "manual_dns",
            Self::DnsPersist => "dns_persist",
            Self::DnsExternal => "dns_external",
            Self::ManualHttp => "manual_http",
            Self::Webroot => "webroot",
            Self::Standalone => "standalone",
            Self::TlsAlpn => "tls_alpn",
        }
    }
    pub(super) fn from_record(record: &IssueRecord) -> Result<Self, IssueError> {
        let method: Self =
            serde_json::from_value(serde_json::Value::String(record.solver_id.clone())).map_err(
                |_| IssueError::InvalidInput("saved validation implementation is not supported"),
            )?;
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
        (ValidationMethod::DnsExternal, _) => Err(IssueError::InvalidInput(
            "dns_external requires its provider profile configuration",
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
        ValidationMethod::DnsExternal => Err(IssueError::InvalidInput(
            "dns_external requires its saved provider profile to be loaded by the CLI",
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
pub(super) struct DnsExternalConfig {
    pub(super) provider_instance_id: String,
    pub(super) provider_profile_version: u32,
}

pub(super) fn external_configuration(
    provider: Option<&str>,
) -> Result<serde_json::Value, IssueError> {
    let Some(provider_instance_id) = provider else {
        return Err(IssueError::InvalidInput(
            "dns_external requires --provider <PROFILE>",
        ));
    };
    if !aster_acme_cli_storage::account::valid_account_name(provider_instance_id) {
        return Err(IssueError::InvalidInput(
            "invalid DNS provider profile name",
        ));
    }
    serde_json::to_value(DnsExternalConfig {
        provider_instance_id: provider_instance_id.to_owned(),
        provider_profile_version: 1,
    })
    .map_err(|_| IssueError::InvalidInput("cannot encode DNS provider configuration"))
}

pub(super) async fn external_adapter(
    record: &IssueRecord,
    root: &std::path::Path,
    progress: Arc<Progress>,
) -> Result<Box<dyn ChallengeSolver>, IssueError> {
    let config: DnsExternalConfig = serde_json::from_value(record.solver_config.clone())
        .map_err(|_| IssueError::InvalidInput("invalid saved DNS provider profile reference"))?;
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
    let lookup = aster_acme_dns_resolver::SystemDns::new();
    Ok(Box::new(dns_external::ExternalDns {
        context: aster_acme_dns::ProviderContext {
            provider_instance_id: config.provider_instance_id,
            provider_profile_version: profile.provider_profile_version,
            provider_custom: profile.provider_custom.into_iter().collect(),
        },
        provider: Arc::new(aster_acme_dns_adpp::AdppProvider::new(
            aster_acme_dns_adpp::Executable {
                program: profile.executable,
                args: profile.args.into_iter().map(Into::into).collect(),
                timeout: std::time::Duration::from_secs(profile.timeout_seconds),
            },
        )),
        lookup: Arc::new(lookup),
        allowed_zones: profile.allowed_zones,
        propagation: aster_acme_dns::propagation::PropagationPolicy {
            interval: std::time::Duration::from_secs(profile.propagation_interval),
            timeout: std::time::Duration::from_secs(profile.propagation_timeout),
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
) -> Result<IssueRecord, IssueError> {
    let saved = session.record().await?;
    if ValidationMethod::from_record(&saved)? != ValidationMethod::DnsExternal {
        return Err(IssueError::InvalidInput(
            "provider cleanup requires external DNS",
        ));
    }
    let solver = external_adapter(&saved, root, Arc::new(Progress::new(output))).await?;
    let result =
        aster_acme::issuance::publication::cleanup(session, solver.as_ref(), execution).await;
    solver.shutdown().await;
    result
}

#[cfg(test)]
pub(crate) mod tests;
