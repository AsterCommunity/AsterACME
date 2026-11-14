//! Optional HTTP content checker; operator proxy policy and TLS verification apply.
use crate::{
    issuance::ValidationRequirement,
    precheck::{Check, Failure},
    solver::ExecutionContext,
    transport::HttpPool,
};
use async_trait::async_trait;

/// The caller supplies its reusable pool; construction performs no network IO.
pub struct Http<'a> {
    pool: &'a HttpPool,
}
impl<'a> Http<'a> {
    /// Reuse the caller's proxy, connection and TLS policy for explicit observations.
    #[must_use]
    pub const fn new(pool: &'a HttpPool) -> Self {
        Self { pool }
    }
}
#[async_trait]
impl Check for Http<'_> {
    type Input = ValidationRequirement;
    type Output = bool;
    async fn observe(
        &self,
        input: &Self::Input,
        execution: &ExecutionContext,
    ) -> Result<bool, Failure> {
        let ValidationRequirement::Http01 { url, content, .. } = input else {
            return Err(Failure::UnsupportedInput);
        };
        let remaining = execution
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        self.pool
            .check_http_challenge(url, content.as_bytes(), remaining)
            .await
            .map_err(|_| Failure::LookupFailed)
    }
}

#[cfg(test)]
mod tests {
    use crate::precheck::{Check, Failure, http::Http};
    use crate::{issuance::ValidationRequirement, solver::ExecutionContext, transport::HttpPool};
    #[tokio::test]
    async fn wrong_method_is_reported_without_an_http_request() {
        let pool = HttpPool::default();
        let context = ExecutionContext {
            cancellation: tokio_util::sync::CancellationToken::new(),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
        };
        assert_eq!(
            Http::new(&pool)
                .observe(
                    &ValidationRequirement::Dns01 {
                        name: "_acme-challenge.example.com".into(),
                        value: "txt".into()
                    },
                    &context
                )
                .await,
            Err(Failure::UnsupportedInput)
        );
    }
}
