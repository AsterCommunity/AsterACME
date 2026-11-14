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
            "request_timeout",
            value(30),
            "\n# Single HTTP request timeout in seconds (1-300).\n",
        ),
        (
            "operation_timeout",
            value(600),
            "\n# Total seconds for each certificate issue/resume/renew invocation (1-86400).\n",
        ),
        (
            "poll_interval",
            value(5),
            "\n# Local CA polling interval in seconds (1-300); valid Retry-After takes precedence.\n",
        ),
        (
            "max_polls",
            value(30),
            "\n# Maximum order-poll rounds per certificate invocation (1-1000).\n",
        ),
        (
            "daemon_interval",
            value(60),
            "\n# Delay between resident daemon maintenance cycles in seconds (1-86400).\n",
        ),
        (
            "contact",
            value(toml_edit::Array::new()),
            "\n# Optional default contacts, e.g. [\"you@example.com\"].\n# Terms acceptance is supplied explicitly with --accept-terms, never stored here.\n",
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

/// Create the data directory's configuration atomically and parse its bounded bytes.
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
        && !aster_acme_cli_storage::account::valid_account_name(name)
    {
        return Err(
            "Invalid config.default_account: use 1–64 letters, digits, hyphens or underscores."
                .into(),
        );
    }
    if let Some(request_timeout) = document.config.request_timeout
        && !(1..=300).contains(&request_timeout)
    {
        return Err("Configuration request_timeout must be between 1 and 300 seconds.".into());
    }
    if document
        .config
        .operation_timeout
        .is_some_and(|value| !(1..=86400).contains(&value))
    {
        return Err("Configuration operation_timeout must be between 1 and 86400 seconds.".into());
    }
    if document
        .config
        .max_polls
        .is_some_and(|value| !(1..=1000).contains(&value))
    {
        return Err("Configuration max_polls must be between 1 and 1000.".into());
    }
    if document
        .config
        .poll_interval
        .is_some_and(|value| !(1..=300).contains(&value))
    {
        return Err("Configuration poll_interval must be between 1 and 300 seconds.".into());
    }
    if document
        .config
        .daemon_interval
        .is_some_and(|value| !(1..=86400).contains(&value))
    {
        return Err("Configuration daemon_interval must be between 1 and 86400 seconds.".into());
    }
    if let Some(directory) = &document.config.ca_directory {
        aster_acme_protocol::url::AcmeUrl::new(directory)?;
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
    edit(path, move |_, table| {
        if let Some(name) = name {
            set_value(table, "default_account", value(name));
        }
        if let Some(contacts) = contacts {
            let mut array = toml_edit::Array::new();
            for contact in contacts {
                array.push(contact.strip_prefix("mailto:").unwrap_or(&contact));
            }
            set_value(table, "contact", value(array));
        }
    })
    .await
}

// Parse and validate the latest locked document once for every targeted config edit.
// Optional fields use get/insert; indexing never reads user-controlled missing values.
async fn edit(
    path: PathBuf,
    change: impl FnOnce(&Config, &mut Table) + Send + 'static,
) -> CliResult<()> {
    aster_acme_cli_storage::toml_file::update(path, Duration::from_secs(5), move |text| {
        let config = parse(text).map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut document: DocumentMut = text.parse().map_err(std::io::Error::other)?;
        let table = document
            .get_mut("config")
            .and_then(Item::as_table_mut)
            .ok_or_else(|| std::io::Error::other("missing config table"))?;
        change(&config, table);
        Ok(document.to_string())
    })
    .await?;
    Ok(())
}

fn set_value(document: &mut Table, key: &str, mut item: Item) {
    if let (Some(old), Some(next)) = (document.get(key).and_then(Item::as_str), item.as_str())
        && old == next
    {
        return;
    }
    if let (Some(previous), Some(next)) = (
        document.get(key).and_then(Item::as_value),
        item.as_value_mut(),
    ) {
        *next.decor_mut() = previous.decor().clone();
    }
    document.insert(key, item);
}

/// Restore a default only after successful registration, without replacing another selection.
pub(crate) async fn default_after_registration(path: PathBuf, name: String) -> CliResult<()> {
    edit(path, move |config, table| {
        if config.default_account.is_none() {
            set_value(table, "default_account", value(name));
        }
    })
    .await
}

/// Clear a removed default only if it still points at that account in the latest file.
pub(crate) async fn clear_removed_default(path: PathBuf, removed: String) -> CliResult<()> {
    edit(path, move |config, table| {
        if config.default_account.as_deref() == Some(removed.as_str()) {
            table.remove("default_account");
        }
    })
    .await
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
    pub(crate) request_timeout: Option<u64>,
    pub(crate) operation_timeout: Option<u64>,
    pub(crate) max_polls: Option<u32>,
    pub(crate) poll_interval: Option<u64>,
    pub(crate) daemon_interval: Option<u64>,
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
    use crate::config;
    use crate::config::*;

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
            "user_agent='legacy-global-agent'",
            "request_timeout=0",
            "request_timeout=301",
            "daemon_interval=0",
            "daemon_interval=86401",
            "default_account='../bad'",
            "ca_directory='https://ca.example/#fragment'",
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
        let text = "# header\nversion=1 # schema\n\n[config]\ndefault_account = 'default' # selection\ncontact = [] # emails\nrequest_timeout=17 # keep\n";
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
            "request_timeout=17 # keep",
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
        let config =
            parse("version=1\n[config]\ndefault_account='work'\nrequest_timeout=20").unwrap();
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
        assert!(generated.contains("daemon_interval = 60"));
        assert!(generated.contains("Delay between resident daemon maintenance cycles"));
        assert!(!generated.contains("user_agent"));
        assert!(!generated.contains("terms_accepted ="));
        assert!(root.join("config.toml").exists());
        let custom = "# user comment\nversion=1\n[config]\ndefault_account = 'personal' # keep\n";
        std::fs::write(&explicit, custom).unwrap();
        assert_eq!(
            config::load(root).await.unwrap().default_account.as_deref(),
            Some("personal")
        );
        assert_eq!(std::fs::read_to_string(&explicit).unwrap(), custom);
        for malformed in ["bad = [", "accept_terms = true", "request_timeout = 'slow'"] {
            std::fs::write(&explicit, malformed).unwrap();
            assert!(config::load(root).await.is_err());
            assert_eq!(std::fs::read_to_string(&explicit).unwrap(), malformed);
        }
    }
    #[tokio::test]
    async fn optional_config_fields_can_be_added_removed_and_recreated_without_panics() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        let original = "# keep header\nversion = 1\n\n[config]\n# keep request_timeout\nrequest_timeout = 17 # retained\n";
        std::fs::write(&path, original).unwrap();
        persist(
            path.clone(),
            Some("default".into()),
            Some(vec!["mailto:a@example.com".into()]),
        )
        .await
        .unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        assert!(first.contains("# keep header"));
        assert!(first.contains("request_timeout = 17 # retained"));
        assert_eq!(
            parse(&first).unwrap().default_account.as_deref(),
            Some("default")
        );
        assert_eq!(parse(&first).unwrap().contact, ["a@example.com"]);
        persist(path.clone(), Some("default".into()), None)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
        clear_removed_default(path.clone(), "default".into())
            .await
            .unwrap();
        assert_eq!(load(temp.path()).await.unwrap().default_account, None);
        default_after_registration(path.clone(), "default".into())
            .await
            .unwrap();
        assert_eq!(
            load(temp.path()).await.unwrap().default_account.as_deref(),
            Some("default")
        );
        persist(path.clone(), Some("other".into()), None)
            .await
            .unwrap();
        let selected = std::fs::read_to_string(&path).unwrap();
        default_after_registration(path.clone(), "default".into())
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), selected);
    }

    #[tokio::test]
    async fn targeted_edits_reject_invalid_tables_and_versions_without_changing_user_text() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        for text in [
            "version=2\n[config]\n",
            "version=1\nconfig='wrong'\n",
            "version=1\n[config]\ndefault_account=7\n",
            "version=1\n[config]\ncontact='wrong'\n",
            "invalid=[",
        ] {
            std::fs::write(&path, text).unwrap();
            assert!(
                persist(path.clone(), Some("default".into()), None)
                    .await
                    .is_err()
            );
            assert!(
                default_after_registration(path.clone(), "default".into())
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        }
    }

    #[tokio::test]
    async fn conditional_default_and_contact_updates_keep_both_intents_under_one_lock() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        std::fs::write(&path, "version=1\n[config]\n").unwrap();
        let (default, contacts) = tokio::join!(
            default_after_registration(path.clone(), "work".into()),
            persist(
                path.clone(),
                None,
                Some(vec!["mailto:a@example.com".into()])
            )
        );
        default.unwrap();
        contacts.unwrap();
        let config = load(temp.path()).await.unwrap();
        assert_eq!(config.default_account.as_deref(), Some("work"));
        assert_eq!(config.contact, ["a@example.com"]);
    }

    #[test]
    fn all_three_limits_have_explicit_validated_config_defaults_without_old_aliases() {
        let generated = template().to_string();
        let config = parse(&generated).unwrap();
        assert_eq!(config.request_timeout, Some(30));
        assert_eq!(config.operation_timeout, Some(600));
        assert_eq!(config.max_polls, Some(30));
        for (field, invalid) in [
            ("request_timeout", "0"),
            ("request_timeout", "301"),
            ("operation_timeout", "0"),
            ("operation_timeout", "86401"),
            ("max_polls", "0"),
            ("max_polls", "1001"),
            ("max_polls", "-1"),
            ("timeout", "30"),
            ("wait_timeout", "600"),
        ] {
            assert!(
                parse(&format!("version=1\n[config]\n{field}={invalid}\n")).is_err(),
                "{field}={invalid}"
            );
        }
    }

    #[test]
    fn absent_and_partial_limits_deserialize_without_requiring_generated_defaults() {
        let empty = parse("version=1\n[config]\n").unwrap();
        assert_eq!(empty.request_timeout.unwrap_or(30), 30);
        assert_eq!(empty.operation_timeout.unwrap_or(600), 600);
        assert_eq!(empty.max_polls.unwrap_or(30), 30);
        for (field, expected) in [
            ("request_timeout=12", (12, 600, 30)),
            ("operation_timeout=90", (30, 90, 30)),
            ("max_polls=8", (30, 600, 8)),
        ] {
            let config = parse(&format!("version=1\n[config]\n{field}\n")).unwrap();
            assert_eq!(
                (
                    config.request_timeout.unwrap_or(30),
                    config.operation_timeout.unwrap_or(600),
                    config.max_polls.unwrap_or(30)
                ),
                expected
            );
        }
    }

    #[test]
    fn polling_interval_config_is_optional_bounded_and_generated_as_five_seconds() {
        assert_eq!(
            parse(&template().to_string()).unwrap().poll_interval,
            Some(5)
        );
        assert_eq!(parse("version=1\n[config]\n").unwrap().poll_interval, None);
        for value in ["0", "301", "-1", "'slow'"] {
            assert!(parse(&format!("version=1\n[config]\npoll_interval={value}\n")).is_err());
        }
        for value in [1, 5, 300] {
            assert_eq!(
                parse(&format!("version=1\n[config]\npoll_interval={value}\n"))
                    .unwrap()
                    .poll_interval,
                Some(value)
            );
        }
    }
}
