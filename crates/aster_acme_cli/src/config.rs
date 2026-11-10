//! Versioned CLI configuration, comment-preserving edits, and first-use defaults.

use crate::common::error::CliResult;
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
use toml_edit::{DocumentMut, Item, Table, value};

/// Build an editable TOML document without persisting secrets or blanket terms consent.
fn template() -> DocumentMut {
    let mut document = DocumentMut::new();
    document["version"] = value(1);
    if let Some(mut key) = document.key_mut("version") {
        key.leaf_decor_mut()
            .set_prefix("# Managed by aster-acme. DO NOT EDIT version.\n");
    }
    let mut table = Table::new();
    table.decor_mut().set_prefix("\n");
    document["config"] = Item::Table(table);
    for (name, item, comment) in [
        (
            "ca",
            value("letsencrypt"),
            "# Public CA preset: letsencrypt, zerossl or google.
# For a custom CA, replace ca with ca_directory = \"https://ca.example/directory\".\n",
        ),
        (
            "default_account",
            value("default"),
            "\n# Default local account; changed by account switch.\n",
        ),
        (
            "timeout",
            value(30),
            "\n# Whole-request timeout in seconds (1-300).\n",
        ),
        (
            "user_agent",
            value(concat!("AsterACME/", env!("CARGO_PKG_VERSION"))),
            "\n# HTTP User-Agent sent to the CA.\n",
        ),
        (
            "contact",
            value(toml_edit::Array::new()),
            "\n# Optional email addresses, e.g. [\"you@example.com\"].\n# Terms acceptance is supplied explicitly with --accept-terms, never stored here.\n",
        ),
    ] {
        document["config"][name] = item;
        if let Some(value) = document["config"][name].as_value_mut() {
            value.decor_mut().set_prefix(" ");
        }
        if let Some(mut key) = document["config"]
            .as_table_mut()
            .and_then(|table| table.key_mut(name))
        {
            key.leaf_decor_mut().set_prefix(comment);
        }
    }
    document
}

/// Create missing explicit or implicit configuration atomically and parse its bounded bytes.
/// A configured `data_dir` redirects state, without recursively loading another configuration.
pub(crate) async fn load(root: &std::path::Path) -> CliResult<Config> {
    let path = root.join("config.toml");
    let bytes = aster_acme_cli_storage::toml_file::load_or_create(
        path.clone(),
        template().to_string(),
        Duration::from_secs(5),
    )
    .await
    .map_err(|error| {
        format!(
            "Could not load or initialize configuration {}: {error}",
            path.display()
        )
    })?;
    let text = std::str::from_utf8(&bytes)?;
    // Keep an editable document so parsing and any future targeted edits preserve TOML trivia.
    let document: DocumentMut = text.parse()?;
    parse(&document.to_string())
}

fn parse(text: &str) -> CliResult<Config> {
    let document: ConfigDocument = toml::from_str(text)?;
    if document.version != 1 {
        return Err(format!(
            "Unsupported config version {}; expected 1.",
            document.version
        )
        .into());
    }
    crate::ca::resolve(document.config.ca, document.config.ca_directory.as_deref())?;
    if let Some(name) = &document.config.default_account
        && !aster_acme_cli_storage::valid_account_name(name)
    {
        return Err(
            "Invalid config.default_account: use 1–64 letters, digits, hyphens or underscores."
                .into(),
        );
    }
    if let Some(timeout) = document.config.timeout
        && !(1..=300).contains(&timeout)
    {
        return Err("Configuration timeout must be between 1 and 300 seconds.".into());
    }
    if let Some(directory) = &document.config.ca_directory {
        aster_acme_protocol::url::AcmeUrl::new(directory)?;
    }
    if let Some(agent) = &document.config.user_agent
        && (agent.is_empty() || agent.len() > 512 || agent.chars().any(char::is_control))
    {
        return Err("Invalid configuration user_agent.".into());
    }
    super::commands::account::contact::normalize(document.config.contact.clone())?;
    Ok(document.config)
}

/// Persist only explicit user intent, editing the latest locked document rather than
/// serializing a stale config snapshot. Registration contact defaults are plain emails.
pub(crate) async fn persist(
    path: PathBuf,
    name: Option<String>,
    contacts: Option<Vec<String>>,
) -> CliResult<()> {
    aster_acme_cli_storage::toml_file::update(path, Duration::from_secs(5), move |text| {
        parse(text).map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut document: DocumentMut = text.parse().map_err(std::io::Error::other)?;
        if let Some(name) = name {
            set_value(
                document["config"]
                    .as_table_mut()
                    .ok_or_else(|| std::io::Error::other("missing config table"))?,
                "default_account",
                value(name),
            );
        }
        if let Some(contacts) = contacts {
            let mut array = toml_edit::Array::new();
            for contact in contacts {
                array.push(contact.strip_prefix("mailto:").unwrap_or(&contact));
            }
            set_value(
                document["config"]
                    .as_table_mut()
                    .ok_or_else(|| std::io::Error::other("missing config table"))?,
                "contact",
                value(array),
            );
        }
        Ok(document.to_string())
    })
    .await?;
    Ok(())
}

fn set_value(document: &mut Table, key: &str, mut item: toml_edit::Item) {
    if let (Some(previous), Some(next)) = (document[key].as_value(), item.as_value_mut()) {
        *next.decor_mut() = previous.decor().clone();
    }
    document[key] = item;
}

/// Clear a removed default only if it is still the same account in the latest file.
/// A concurrent switch to another account is preserved.
pub(crate) async fn clear_removed_default(path: PathBuf, removed: String) -> CliResult<()> {
    aster_acme_cli_storage::toml_file::update(path, Duration::from_secs(5), move |text| {
        let config = parse(text).map_err(|error| std::io::Error::other(error.to_string()))?;
        if config.default_account.as_deref() != Some(removed.as_str()) {
            return Ok(text.to_owned());
        }
        let mut document: DocumentMut = text.parse().map_err(std::io::Error::other)?;
        document["config"]
            .as_table_mut()
            .ok_or_else(|| std::io::Error::other("missing config table"))?
            .remove("default_account");
        Ok(document.to_string())
    })
    .await?;
    Ok(())
}

pub(crate) const DEFAULT_CA_DIRECTORY: &str =
    aster_acme_protocol::directory::Provider::Letsencrypt.directory();

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDocument {
    version: u32,
    config: Config,
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) ca_directory: Option<String>,
    pub(crate) ca: Option<aster_acme_protocol::directory::Provider>,
    pub(crate) default_account: Option<String>,
    #[serde(default)]
    pub(crate) contact: Vec<String>,
    pub(crate) user_agent: Option<String>,
    pub(crate) timeout: Option<u64>,
}

/// Resolve platform paths like gcop-rs, keeping config and private state under one root.
pub(crate) fn default_data_dir() -> CliResult<PathBuf> {
    directories::ProjectDirs::from("com", "astercosm", "acme")
        .map(|dirs| dirs.config_dir().to_path_buf())
        .ok_or_else(|| {
            "Cannot determine the default state directory; pass --data-dir <PATH>.".into()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    #[tokio::test]
    async fn removal_preserves_a_different_default_and_comments() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        let text = "# mine\nversion=1\n[config]\ndefault_account='other' # keep\n";
        std::fs::write(&path, text).unwrap();
        clear_removed_default(path.clone(), "personal".into())
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        clear_removed_default(path.clone(), "other".into())
            .await
            .unwrap();
        assert_eq!(load(temp.path()).await.unwrap().default_account, None);
        assert!(std::fs::read_to_string(path).unwrap().contains("# mine"));
    }

    #[test]
    fn config_version_is_required_and_unknown_versions_are_rejected() {
        for input in ["", "version=0", "version=2", "version='1'"] {
            assert!(parse(input).is_err(), "{input}");
        }
        assert!(parse("version=1\n[config]").is_ok());
    }

    #[test]
    fn config_rejects_invalid_semantics_and_removed_location_fields() {
        for setting in [
            "ca='unknown'",
            "ca='google'\nca_directory='https://ca.example/directory'",
            "directory='https://ca.example/directory'",
            "data_dir='./elsewhere'",
            "timeout=0",
            "timeout=301",
            "default_account='../bad'",
            "ca_directory='https://ca.example/#fragment'",
            "user_agent=''",
            "contact=['not-an-email']",
        ] {
            assert!(
                parse(&format!("version=1\n[config]\n{setting}")).is_err(),
                "{setting}"
            );
        }
        assert_eq!(
            parse("version=1\n[config]\nca='google'").unwrap().ca,
            Some(aster_acme_protocol::directory::Provider::Google)
        );
        assert!(
            parse("version=1\n[config]\nca_directory='https://custom.example/directory'").is_ok()
        );
    }

    #[tokio::test]
    async fn targeted_edits_preserve_comments_and_serialize_concurrent_updates() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        let text = "# header\nversion=1 # schema\n\n[config]\ndefault_account = 'default' # selection\ncontact = [] # emails\ntimeout=17 # keep\n";
        std::fs::write(&path, text).unwrap();
        let (a, b) = tokio::join!(
            persist(path.clone(), Some("personal".into()), None),
            persist(
                path.clone(),
                None,
                Some(vec!["mailto:you@example.com".into()])
            ),
        );
        a.unwrap();
        b.unwrap();
        let result = std::fs::read_to_string(&path).unwrap();
        let config = parse(&result).unwrap();
        assert_eq!(config.default_account.as_deref(), Some("personal"));
        assert_eq!(config.contact, ["you@example.com"]);
        for preserved in [
            "# header",
            "# schema",
            "# selection",
            "# emails",
            "timeout=17 # keep",
        ] {
            assert!(result.contains(preserved), "{result}");
        }
        std::fs::write(&path, "version=2").unwrap();
        assert!(
            persist(path.clone(), Some("work".into()), None)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), "version=2");
    }

    #[test]
    fn default_directory_uses_the_platform_reverse_domain_identity() {
        let expected = directories::ProjectDirs::from("com", "astercosm", "acme").unwrap();
        assert_eq!(default_data_dir().unwrap(), expected.config_dir());
    }

    #[test]
    fn config_rejects_automatic_consent_and_secrets() {
        for input in [
            "accept_terms=true",
            "eab_key='secret'",
            "name='legacy'",
            "unexpected=1",
        ] {
            assert!(parse(input).is_err());
        }
        let config = parse(
            "version=1\n[config]\ndefault_account='work'\nuser_agent='my client'\ntimeout=20",
        )
        .unwrap();
        assert_eq!(config.default_account.as_deref(), Some("work"));
    }

    #[tokio::test]
    async fn data_directory_config_is_loaded_without_requiring_an_extra_path() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        assert_eq!(
            config::load(&root)
                .await
                .unwrap()
                .default_account
                .as_deref(),
            Some("default")
        );
        std::fs::write(
            root.join("config.toml"),
            "version=1\n[config]\ndefault_account='work'",
        )
        .unwrap();
        assert_eq!(
            config::load(&root)
                .await
                .unwrap()
                .default_account
                .as_deref(),
            Some("work")
        );
    }

    #[tokio::test]
    async fn generated_config_is_commented_and_existing_config_is_preserved() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let explicit = root.join("config.toml");
        let loaded = config::load(root).await.unwrap();
        assert_eq!(
            loaded.ca,
            Some(aster_acme_protocol::directory::Provider::Letsencrypt)
        );
        let generated = std::fs::read_to_string(&explicit).unwrap();
        assert!(generated.contains("# Public CA preset"));
        assert!(!generated.contains("terms_accepted ="));
        assert!(root.join("config.toml").exists());
        let custom = "# user comment\nversion=1\n[config]\ndefault_account = 'personal' # keep\n";
        std::fs::write(&explicit, custom).unwrap();
        assert_eq!(
            config::load(root).await.unwrap().default_account.as_deref(),
            Some("personal")
        );
        assert_eq!(std::fs::read_to_string(&explicit).unwrap(), custom);
        for malformed in ["bad = [", "accept_terms = true", "timeout = 'slow'"] {
            std::fs::write(&explicit, malformed).unwrap();
            assert!(config::load(root).await.is_err());
            assert_eq!(std::fs::read_to_string(&explicit).unwrap(), malformed);
        }
    }
}
