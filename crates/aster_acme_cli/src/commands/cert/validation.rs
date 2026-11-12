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

mod http;
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
    pub(super) const fn kind(self) -> ChallengeKind {
        match self {
            Self::ManualDns => ChallengeKind::Dns01,
            Self::ManualHttp | Self::Webroot | Self::Standalone => ChallengeKind::Http01,
            Self::TlsAlpn => ChallengeKind::TlsAlpn01,
        }
    }
    pub(super) const fn id(self) -> &'static str {
        match self {
            Self::ManualDns => "manual_dns",
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
        (ValidationMethod::ManualDns | ValidationMethod::ManualHttp, None) => {
            serde_json::to_value(ManualConfig {}).map_err(|_| {
                IssueError::InvalidInput("cannot encode manual validation configuration")
            })
        }
        (
            ValidationMethod::ManualDns
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
        ValidationMethod::ManualDns | ValidationMethod::ManualHttp => {
            let _: ManualConfig =
                serde_json::from_value(record.solver_config.clone()).map_err(|_| {
                    IssueError::InvalidInput("invalid saved manual validation configuration")
                })?;
            Ok(Box::new(manual::Manual {
                prompt: std::sync::Mutex::new(None),
                method: record.challenge,
                saved: record
                    .authorizations
                    .iter()
                    .any(|auth| auth.validation.is_some()),
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
                root: config.root,
                operation: record.operation_id.clone(),
                progress,
            }))
        }
    }
}

/// Reuse the command pool for advisory HTTP checks without teaching protocol
/// services about local DNS/network reachability or CLI publication policy.
pub(super) fn with_http_precheck(
    solver: Box<dyn ChallengeSolver>,
    pool: aster_acme::transport::HttpPool,
    progress: Arc<Progress>,
) -> Box<dyn ChallengeSolver> {
    if solver.kind() == ChallengeKind::Http01 {
        Box::new(http::Checked {
            inner: solver,
            pool,
            progress,
        })
    } else {
        solver
    }
}

#[cfg(test)]
mod tests;
