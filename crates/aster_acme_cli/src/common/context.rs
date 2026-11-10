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
    pub(crate) account_user_agent: Option<String>,
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
        let saved = store.metadata().await?;
        let account_user_agent = saved.as_ref().and_then(|record| record.user_agent.clone());
        let bound = saved.map(|record| record.directory_url);
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
            account_user_agent,
            config,
            config_path,
            name,
            directory,
            store,
        })
    }
}

impl CliContext {
    /// Check local existence before prompts, signer initialization or CA discovery.
    /// Registration is the only operation that may create a missing account identity.
    pub(crate) async fn require_account(&self) -> CliResult<aster_acme::account::AccountRecord> {
        self.store.metadata().await?.ok_or_else(|| {
            Box::new(super::error::MissingLocalAccount {
                name: self.name.clone(),
            }) as Box<dyn std::error::Error>
        })
    }

    /// Network-only settings are validated only when a command actually requests HTTP.
    pub(crate) fn transport_options(&self, options: &AccountArgs) -> CliResult<TransportOptions> {
        let timeout = options.timeout.or(self.config.timeout).unwrap_or(30);
        if !(1..=300).contains(&timeout) {
            return Err("Timeout must be between 1 and 300 seconds.".into());
        }
        let transport = TransportOptions {
            request_timeout: Duration::from_secs(timeout),
            user_agent: options
                .user_agent
                .clone()
                .or_else(|| self.account_user_agent.clone()),
            ..TransportOptions::default()
        };
        transport.validate()?;
        Ok(transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::account::{
        args::{AccountCommand, CaArgs, HttpArgs, LocalArgs, NameArgs, RegisterArgs},
        execute,
    };
    use aster_acme::account::{AccountKeyStore, AccountStore};

    #[tokio::test]
    async fn explicit_account_user_agent_survives_restart_and_temporary_override() {
        let temp = tempfile::tempdir().unwrap();
        let ca = "http://127.0.0.1:1/directory";
        let register = RegisterArgs {
            identity: NameArgs {
                name: Some("work".into()),
                ..NameArgs::default()
            },
            http: HttpArgs {
                user_agent: Some("AsterDrive/0.3.7".into()),
                ..HttpArgs::default()
            },
            ca: CaArgs {
                ca_directory: Some(ca.into()),
                ..CaArgs::default()
            },
            local: LocalArgs {
                data_dir: Some(temp.path().into()),
                json: true,
            },
            ..RegisterArgs::default()
        };
        // Discovery fails, but validated explicit intent must already be durable.
        assert!(
            execute::execute(AccountCommand::Register(register))
                .await
                .is_err()
        );
        let account_path = temp.path().join("accounts/work/account.toml");
        let text = std::fs::read_to_string(&account_path).unwrap();
        assert!(text.contains("user_agent = \"AsterDrive/0.3.7\""));
        let config = std::fs::read_to_string(temp.path().join("config.toml")).unwrap();
        assert!(!config.contains("user_agent"));
        assert!(!config.contains("one-command"));
        let options = AccountArgs {
            data_dir: Some(temp.path().into()),
            name: Some("work".into()),
            ..AccountArgs::default()
        };
        let context = CliSettings::load(&options)
            .await
            .unwrap()
            .account(&options)
            .await
            .unwrap();
        assert_eq!(
            context
                .transport_options(&options)
                .unwrap()
                .user_agent
                .as_deref(),
            Some("AsterDrive/0.3.7")
        );
        let override_options = AccountArgs {
            user_agent: Some("temporary/2".into()),
            ..AccountArgs::default()
        };
        assert_eq!(
            context
                .transport_options(&override_options)
                .unwrap()
                .user_agent
                .as_deref(),
            Some("temporary/2")
        );
        let invalid = AccountArgs {
            user_agent: Some("bad\nagent".into()),
            ..AccountArgs::default()
        };
        assert!(context.transport_options(&invalid).is_err());
        let key = context
            .store
            .signer(&context.directory, "work", false)
            .await
            .unwrap();
        let record = context
            .store
            .load(
                &context.directory,
                &key.jwk().unwrap().thumbprint().unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.user_agent.as_deref(), Some("AsterDrive/0.3.7"));
        assert_eq!(std::fs::read_to_string(&account_path).unwrap(), text);
    }

    #[tokio::test]
    async fn default_user_agent_is_not_written_to_account_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let default_options = AccountArgs {
            data_dir: Some(temp.path().into()),
            name: Some("plain".into()),
            ca_directory: Some("http://127.0.0.1:1/directory".into()),
            ..AccountArgs::default()
        };
        let plain = CliSettings::load(&default_options)
            .await
            .unwrap()
            .account(&default_options)
            .await
            .unwrap();
        plain
            .store
            .signer(&plain.directory, "plain", true)
            .await
            .unwrap();
        assert_eq!(
            plain
                .transport_options(&default_options)
                .unwrap()
                .user_agent,
            None
        );
        assert!(
            !std::fs::read_to_string(temp.path().join("accounts/plain/account.toml"))
                .unwrap()
                .contains("user_agent")
        );
    }
}
