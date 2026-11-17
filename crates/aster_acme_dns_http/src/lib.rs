//! Host-owned Forge HTTP execution. Provider code never receives the client pool.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::unimplemented,
        clippy::todo
    )
)]
use aster_acme_dns::{
    ProviderErrorCode, ProviderExecution, SideEffect,
    operation::{HttpExecutor, HttpFailure, HttpRequest, HttpResponse},
};
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};

/// Lazily initialized shared transport; no network or file side effects at construction.
#[derive(Clone, Default)]
pub struct ForgeDnsHttp {
    client: Arc<tokio::sync::OnceCell<aster_forge_http::HttpClient>>,
    #[cfg(test)]
    loopback_http: bool,
}

#[async_trait]
impl HttpExecutor for ForgeDnsHttp {
    async fn execute(
        &self,
        request: HttpRequest,
        execution: &ProviderExecution,
    ) -> Result<HttpResponse, HttpFailure> {
        let before = HttpFailure {
            code: ProviderErrorCode::ProviderUnavailable,
            side_effect: SideEffect::None,
        };
        let after = HttpFailure {
            code: ProviderErrorCode::ProviderUnavailable,
            side_effect: if request.mutation {
                SideEffect::Unknown
            } else {
                SideEffect::None
            },
        };
        let header_bytes = request.headers.iter().fold(0usize, |total, (name, value)| {
            total.saturating_add(name.len()).saturating_add(value.len())
        });
        if request.method.len() > 32
            || request.body.len() > 1024 * 1024
            || request.url.len() > 8192
            || header_bytes > 65536
        {
            return Err(before);
        }
        let url = reqwest::Url::parse(&request.url).map_err(|_| before)?;
        if url.as_str() != request.url {
            return Err(before);
        }
        let https = url.scheme() == "https";
        #[cfg(test)]
        let https = https
            || (self.loopback_http
                && url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost")));
        if !https
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(before);
        }
        let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|_| before)?;
        let exchange = async {
            let client = self
                .client
                .get_or_try_init(|| async {
                    aster_forge_http::HttpClient::builder()
                        .tls_backend(aster_forge_http::TlsBackend::Rustls)
                        .without_total_timeout()
                        .without_read_timeout()
                        .connect_timeout(Duration::from_secs(10))
                        .user_agent(concat!("AsterACME/", env!("CARGO_PKG_VERSION")))
                        .build()
                })
                .await
                .map_err(|_| before)?;
            let mut builder = client.request(method, url);
            for (name, value) in request.headers {
                let mut value = reqwest::header::HeaderValue::from_bytes(value.as_bytes())
                    .map_err(|_| before)?;
                // Providers may authenticate through arbitrary header names. Keep all
                // values out of downstream Debug/trace formatting without changing bytes.
                value.set_sensitive(true);
                builder = builder.header(name, value);
            }
            let built = builder.body(request.body).build().map_err(|_| before)?;
            let mut response = client.execute(built).await.map_err(|_| after)?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .map(|(name, value)| (name.as_str().into(), value.as_bytes().to_vec()))
                .collect();
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| after)? {
                if body.len().saturating_add(chunk.len()) > 1024 * 1024 {
                    return Err(after);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        };
        if execution.cancellation.is_cancelled() || std::time::Instant::now() >= execution.deadline
        {
            return Err(HttpFailure {
                code: ProviderErrorCode::ProviderTimeout,
                ..before
            });
        }
        tokio::select! {
            biased;
            () = execution.cancellation.cancelled() => Err(HttpFailure { code: ProviderErrorCode::ProviderTimeout, ..after }),
            result = tokio::time::timeout_at(execution.deadline.into(), exchange) => result.unwrap_or(Err(HttpFailure { code: ProviderErrorCode::ProviderTimeout, ..after })),
        }
    }
}

#[cfg(test)]
mod tests;
