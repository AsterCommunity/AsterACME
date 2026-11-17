//! Generic backend discovery, host HTTP execution and private credential access.
use crate::common::error::CliResult;
use aster_acme_dns::{
    ProviderError, ProviderErrorCode, ProviderExecution, SideEffect, backend::ProviderRegistry,
    operation::CredentialReader,
};
use aster_acme_dns_adpp as _;
use aster_acme_dns_builtin as _;
use async_trait::async_trait;

pub(crate) fn registry() -> Result<ProviderRegistry, ProviderError> {
    ProviderRegistry::linked()
}

pub(crate) async fn read_settings(
    path: &std::path::Path,
) -> CliResult<serde_json::Map<String, serde_json::Value>> {
    let path = path.to_path_buf();
    let bytes = tokio::task::spawn_blocking(move || {
        aster_acme_cli_storage::state_file::read_private(&path, 32768)
    })
    .await?
    .map_err(|_| "cannot read private backend settings file")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "backend settings must be UTF-8 TOML")?;
    toml::from_str(text).map_err(|_| "invalid backend settings TOML".into())
}

#[derive(Clone, Default)]
pub(crate) struct PrivateCredentials;

#[async_trait]
impl CredentialReader for PrivateCredentials {
    async fn read(
        &self,
        path: &std::path::Path,
        execution: &ProviderExecution,
    ) -> Result<String, ProviderError> {
        if execution.cancellation.is_cancelled() || std::time::Instant::now() >= execution.deadline
        {
            return Err(secret_error());
        }
        let path = path.to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            aster_acme_cli_storage::state_file::read_private(&path, 4096)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .map(|text| text.trim_end_matches(['\r', '\n']).to_owned())
        });
        tokio::select! {
            biased;
            () = execution.cancellation.cancelled() => Err(secret_error()),
            result = tokio::time::timeout_at(execution.deadline.into(), result) => result.ok().and_then(Result::ok).flatten().ok_or_else(secret_error),
        }
    }
}

fn secret_error() -> ProviderError {
    ProviderError {
        code: ProviderErrorCode::CredentialsUnavailable,
        message: "private provider credential file unavailable".into(),
        side_effect: SideEffect::None,
        retry_after_seconds: None,
        provider_code: None,
    }
}

#[cfg(test)]
mod tests {
    use crate::commands::provider::runtime::PrivateCredentials;
    use aster_acme_dns::{ProviderExecution, operation::CredentialReader};
    use std::time::{Duration, Instant};
    #[tokio::test]
    async fn credential_files_are_private_bounded_and_cancellation_aware() {
        let root = tempfile::tempdir().unwrap();
        let directory =
            aster_acme_cli_storage::state_file::StateDirectory::open(root.path()).unwrap();
        directory
            .atomic_write("token", b"private-value\r\n")
            .unwrap();
        let path = root.path().join("token");
        let http = PrivateCredentials;
        let scope = ProviderExecution {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(1),
        };
        assert_eq!(http.read(&path, &scope).await.unwrap(), "private-value");
        directory.atomic_write("token", &vec![b'x'; 4097]).unwrap();
        assert!(http.read(&path, &scope).await.is_err());
        scope.cancellation.cancel();
        assert!(http.read(&path, &scope).await.is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            directory.atomic_write("token", b"private-value").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let active = ProviderExecution {
                cancellation: tokio_util::sync::CancellationToken::new(),
                deadline: Instant::now() + Duration::from_secs(1),
            };
            assert!(http.read(&path, &active).await.is_err());
        }
    }
}
