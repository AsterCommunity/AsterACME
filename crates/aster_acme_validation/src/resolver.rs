//! System resolver construction and initialization diagnostics shared by DNS consumers.
use hickory_resolver::{Resolver, TokioResolver, net::NetError};

/// Initialization failed before any query. Preserve the underlying diagnostic,
/// without dumping system configuration, environment variables or DNS response data.
#[derive(Debug, thiserror::Error)]
pub enum InitializationError {
    /// Hickory could not load or parse the operating system's DNS configuration.
    #[error("cannot load system DNS configuration: {0}")]
    SystemConfiguration(#[source] NetError),
    /// Configuration was loaded but resolver construction failed.
    #[error("cannot build local DNS resolver: {0}")]
    Build(#[source] NetError),
}

/// Initialize using the operator's system configuration, without performing DNS queries.
///
/// # Errors
/// Preserves configuration-read and resolver-build errors separately. No fallback
/// nameservers or configuration rewriting is performed.
pub fn system() -> Result<TokioResolver, InitializationError> {
    initialize(
        Resolver::builder_tokio,
        hickory_resolver::ResolverBuilder::build,
    )
}

fn initialize<B, R>(
    load: impl FnOnce() -> Result<B, NetError>,
    build: impl FnOnce(B) -> Result<R, NetError>,
) -> Result<R, InitializationError> {
    let builder = load().map_err(InitializationError::SystemConfiguration)?;
    build(builder).map_err(InitializationError::Build)
}

#[cfg(test)]
mod tests {
    use crate::resolver::{InitializationError, initialize};
    use hickory_resolver::net::NetError;
    use std::{cell::Cell, error::Error as _};

    #[test]
    fn configuration_failure_keeps_source_and_never_attempts_build() {
        let builds = Cell::new(0);
        let result = initialize::<(), ()>(
            || {
                Err(NetError::from(
                    "failed to parse nameserver address: invalid IP address syntax",
                ))
            },
            |()| {
                builds.set(builds.get() + 1);
                Ok(())
            },
        );
        let error = result.unwrap_err();
        assert!(matches!(error, InitializationError::SystemConfiguration(_)));
        assert_eq!(builds.get(), 0);
        assert_eq!(
            error.to_string(),
            "cannot load system DNS configuration: failed to parse nameserver address: invalid IP address syntax"
        );
        assert_eq!(
            error.source().unwrap().to_string(),
            "failed to parse nameserver address: invalid IP address syntax"
        );
    }

    #[test]
    fn build_failure_is_distinct_and_success_preserves_loaded_configuration() {
        let error = initialize(
            || Ok(42),
            |value| {
                assert_eq!(value, 42);
                Err::<(), _>(NetError::from("injected resolver construction failure"))
            },
        )
        .unwrap_err();
        assert!(matches!(error, InitializationError::Build(_)));
        assert_eq!(
            error.to_string(),
            "cannot build local DNS resolver: injected resolver construction failure"
        );
        assert!(error.source().is_some());
        assert_eq!(initialize(|| Ok(42), |value| Ok(value + 1)).unwrap(), 43);
    }
}
