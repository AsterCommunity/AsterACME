//! Resolve configuration and local storage once; HTTP is initialized only by remote commands.
use aster_acme_protocol::url::AcmeUrl;

use crate::{
    commands::account::args::AccountArgs,
    common::error::CliResult,
    config::{self, Config, DEFAULT_CA_DIRECTORY},
};
use aster_acme::transport::TransportOptions;
use aster_acme_cli_storage::CliAccountStore;
use std::{path::PathBuf, sync::Arc, time::Duration};

pub(crate) struct CliContext {
    pub(crate) config: Config,
    pub(crate) config_path: PathBuf,
    pub(crate) name: String,
    pub(crate) directory: AcmeUrl,
    pub(crate) store: Arc<CliAccountStore>,
}

#[derive(Clone)]
pub(crate) struct CliSettings {
    pub(crate) config: Config,
    pub(crate) config_path: PathBuf,
    pub(crate) data_dir: PathBuf,
}

impl CliSettings {
    pub(crate) async fn load(options: &AccountArgs) -> CliResult<Self> {
        let data_dir = match &options.data_dir {
            Some(root) => root.clone(),
            None => config::default_data_dir()?,
        };
        let config_path = data_dir.join("config.toml");
        let config = config::load(&data_dir).await?;
        Ok(Self {
            config,
            config_path,
            data_dir,
        })
    }

    pub(crate) async fn account(self, options: &AccountArgs) -> CliResult<CliContext> {
        let Self {
            config,
            config_path,
            data_dir,
        } = self;
        let name = options
            .name
            .clone()
            .or_else(|| config.default_account.clone())
            .unwrap_or_else(|| "default".into());
        let store = Arc::new(CliAccountStore::open(
            data_dir,
            &name,
            Duration::from_secs(5),
        )?);
        let bound = store.directory().await?;
        let directory = match (options.ca_directory.as_deref(), bound) {
            (Some(explicit), Some(bound)) if explicit != bound.as_str() => {
                return Err("Account name is bound to another CA; choose another --name.".into());
            }
            (Some(explicit), _) => AcmeUrl::new(explicit)?,
            (None, Some(bound)) => bound,
            (None, None) => AcmeUrl::new(
                crate::ca::resolve(config.ca, config.ca_directory.as_deref())?
                    .unwrap_or(DEFAULT_CA_DIRECTORY),
            )?,
        };
        Ok(CliContext {
            config,
            config_path,
            name,
            directory,
            store,
        })
    }
}

impl CliContext {
    /// Network-only settings are validated only when a command actually requests HTTP.
    pub(crate) fn transport_options(&self, options: &AccountArgs) -> CliResult<TransportOptions> {
        let timeout = options.timeout.or(self.config.timeout).unwrap_or(30);
        if !(1..=300).contains(&timeout) {
            return Err("Timeout must be between 1 and 300 seconds.".into());
        }
        Ok(TransportOptions {
            request_timeout: Duration::from_secs(timeout),
            user_agent: options
                .user_agent
                .clone()
                .or_else(|| self.config.user_agent.clone()),
            ..TransportOptions::default()
        })
    }
}
