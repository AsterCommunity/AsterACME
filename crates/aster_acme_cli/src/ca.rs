//! CLI parsing adapters for protocol-owned public CA providers.

use aster_acme_protocol::directory::Provider;
use clap::builder::{PossibleValue, TypedValueParser};

#[derive(Clone)]
pub(crate) struct ProviderParser;

impl TypedValueParser for ProviderParser {
    type Value = Provider;

    fn parse_ref(
        &self,
        command: &clap::Command,
        _argument: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        value.to_str().and_then(Provider::from_name).ok_or_else(|| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                "Unknown CA; choose letsencrypt, zerossl or google.",
            )
            .with_cmd(command)
        })
    }

    fn possible_values(&self) -> Option<Box<dyn Iterator<Item = PossibleValue> + '_>> {
        Some(Box::new(
            Provider::ALL
                .into_iter()
                .map(|provider| PossibleValue::new(provider.name())),
        ))
    }
}

/// Shared preset/custom URL parsing for interactive input.
pub(crate) fn input(value: &str) -> Result<String, String> {
    match Provider::from_name(value) {
        Some(ca) => Ok(ca.directory().to_owned()),
        None => aster_acme_protocol::url::AcmeUrl::new(value)
            .map(|url| url.as_str().to_owned())
            .map_err(|error| error.to_string()),
    }
}

/// Explicit provider and explicit directory are alternatives, never ambiguous precedence.
pub(crate) fn resolve(
    ca: Option<Provider>,
    directory: Option<&str>,
) -> Result<Option<&str>, &'static str> {
    match (ca, directory) {
        (Some(_), Some(_)) => Err("Choose ca or ca_directory, not both."),
        (Some(ca), None) => Ok(Some(ca.directory())),
        (None, directory) => Ok(directory),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_registry_uses_public_directories_and_has_no_test_presets() {
        for provider in Provider::ALL {
            let name = provider.name();
            let expected = provider.directory();
            let ca = Provider::from_name(name).unwrap();
            assert_eq!(ca.directory(), expected);
            assert_eq!(input(name).unwrap(), expected);
            assert_eq!(resolve(Some(ca), None).unwrap(), Some(expected));
            assert!(resolve(Some(ca), Some("https://custom.example/directory")).is_err());
        }
        assert_eq!(Provider::ALL.len(), 3);
        assert!(input("unknown").is_err());
        assert_eq!(
            input("https://custom.example/directory").unwrap(),
            "https://custom.example/directory"
        );
        assert_eq!(resolve(None, None).unwrap(), None);
    }
}
