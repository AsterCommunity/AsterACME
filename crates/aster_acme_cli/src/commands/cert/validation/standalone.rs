//! Minimal HTTP-01 publication: exact Host/path GETs, no filesystem or generic routes.
//! Hyper owns HTTP parsing; the shared listener owns bounded connection lifetimes.
use crate::commands::cert::validation::{
    Arc, ChallengeKind, ChallengeSolver, IssueError, Progress, listener::Listener,
};
use crate::common::output::MessageKind;
use aster_acme::{
    challenge::ChallengeToken,
    issuance::ValidationRequirement,
    solver::{ChallengePublication, CleanupResult, ExecutionContext, ReadyResult, RestoreResult},
};
use async_trait::async_trait;
use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING},
};
use hyper_util::rt::TokioIo;
use std::{collections::BTreeMap, convert::Infallible, net::SocketAddr};
use tokio::sync::{Mutex, RwLock};

type Requirements = BTreeMap<(String, String), String>;

pub(super) struct Standalone {
    address: SocketAddr,
    progress: Arc<Progress>,
    requirements: Arc<RwLock<Requirements>>,
    listener: Mutex<Option<Listener>>,
}

impl Standalone {
    pub(super) fn new(address: SocketAddr, progress: Arc<Progress>) -> Self {
        Self {
            address,
            progress,
            requirements: Arc::default(),
            listener: Mutex::new(None),
        }
    }

    async fn publish(
        &self,
        requirements: &[ValidationRequirement],
        execution: &ExecutionContext,
    ) -> Result<(), IssueError> {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        let additions = validate(requirements)?;
        let mut listener = self.listener.lock().await;
        let mut table = self.requirements.write().await;
        for (key, value) in &additions {
            if table.get(key).is_some_and(|previous| previous != value) {
                return Err(IssueError::InvalidInput(
                    "standalone challenge content changed",
                ));
            }
        }
        table.extend(additions);
        drop(table);
        if let Some(active) = listener.as_ref() {
            if active.is_finished() {
                return Err(IssueError::Publication(
                    "HTTP challenge listener stopped unexpectedly".into(),
                ));
            }
            return Ok(());
        }
        let table = self.requirements.clone();
        let active = Listener::bind(self.address, execution, move |stream| {
            let table = table.clone();
            async move {
                let service =
                    hyper::service::service_fn(move |request| respond(request, table.clone()));
                // One request per connection; never buffer a request body. The
                // supervisor bounds lifetime/concurrency even for slow clients.
                let _ = hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
                    .max_headers(32)
                    .max_buf_size(8192)
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            }
        })
        .await?;
        self.progress.output.progress(
            MessageKind::Info,
            &format!(
                "HTTP-01 standalone listener started at {}; public port 80 must reach this socket",
                active.address
            ),
        );
        tracing::debug!(listen_address = %active.address, "Forward public HTTP port 80 for every requested domain to this listener; only exact challenge Host/path GETs are served");
        *listener = Some(active);
        Ok(())
    }
}

#[async_trait]
impl ChallengeSolver for Standalone {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::Http01
    }

    async fn ready(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<ReadyResult, IssueError> {
        let requirements = publications
            .iter()
            .map(|publication| publication.requirement.clone())
            .collect::<Vec<_>>();
        self.publish(&requirements, execution).await?;
        Ok(ReadyResult {
            ready: true,
            ..ReadyResult::default()
        })
    }

    async fn restore(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<RestoreResult, IssueError> {
        let requirements = publications
            .iter()
            .map(|publication| publication.requirement.clone())
            .collect::<Vec<_>>();
        self.publish(&requirements, execution).await?;
        Ok(RestoreResult::default())
    }

    async fn cleanup(
        &self,
        publications: &[ChallengePublication],
        _: &ExecutionContext,
    ) -> Result<CleanupResult, IssueError> {
        self.shutdown().await;
        Ok(CleanupResult {
            completed: publications
                .iter()
                .map(|publication| publication.publication_id.clone())
                .collect(),
            failure: None,
            retry_at: None,
        })
    }

    async fn shutdown(&self) {
        if let Some(listener) = self.listener.lock().await.take() {
            let address = listener.address;
            listener.shutdown().await;
            self.requirements.write().await.clear();
            self.progress.output.progress(
                MessageKind::Info,
                &format!("HTTP-01 standalone listener stopped at {address}"),
            );
        }
    }
}

fn validate(requirements: &[ValidationRequirement]) -> Result<Requirements, IssueError> {
    if requirements.is_empty() {
        return Err(IssueError::InvalidInput(
            "standalone requires HTTP challenge material",
        ));
    }
    let mut table = Requirements::new();
    for requirement in requirements {
        let ValidationRequirement::Http01 { url, path, content } = requirement else {
            return Err(IssueError::InvalidInput(
                "standalone received another validation method",
            ));
        };
        let token =
            path.strip_prefix("/.well-known/acme-challenge/")
                .ok_or(IssueError::InvalidInput(
                    "invalid standalone challenge path",
                ))?;
        ChallengeToken::new(token)?;
        let parsed = url::Url::parse(url)
            .map_err(|_| IssueError::InvalidInput("invalid standalone public URL"))?;
        let domain = parsed.domain().ok_or(IssueError::InvalidInput(
            "standalone requires a DNS hostname",
        ))?;
        if parsed.scheme() != "http"
            || parsed.port_or_known_default() != Some(80)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.query().is_some()
            || parsed.path() != path
            || content.len() > 8192
            || !content.starts_with(&format!("{token}."))
            || !content
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(IssueError::InvalidInput(
                "invalid standalone HTTP challenge material",
            ));
        }
        let key = (domain.to_owned(), path.clone());
        if table
            .insert(key, content.clone())
            .is_some_and(|previous| previous != *content)
        {
            return Err(IssueError::InvalidInput(
                "conflicting standalone challenge material",
            ));
        }
    }
    Ok(table)
}

async fn respond(
    request: Request<Incoming>,
    table: Arc<RwLock<Requirements>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut status = StatusCode::NOT_FOUND;
    let mut content = String::new();
    if request.method() != Method::GET {
        status = StatusCode::METHOD_NOT_ALLOWED;
    } else if request.headers().contains_key(TRANSFER_ENCODING)
        || request
            .headers()
            .get(CONTENT_LENGTH)
            .is_some_and(|v| v != "0")
    {
        status = StatusCode::BAD_REQUEST;
    } else if request.uri().scheme().is_none()
        && request.uri().authority().is_none()
        && request.uri().query().is_none()
        && request.headers().get_all(HOST).iter().count() == 1
        && let Some(host) = request.headers().get(HOST).and_then(|v| v.to_str().ok())
        && let Ok(authority) = host.parse::<hyper::http::uri::Authority>()
        && (authority.port().is_none() || authority.port_u16().is_some())
    {
        let key = (
            authority.host().trim_end_matches('.').to_ascii_lowercase(),
            request.uri().path().to_owned(),
        );
        if let Some(value) = table.read().await.get(&key) {
            status = StatusCode::OK;
            content.clone_from(value);
        }
    }
    let mut response = Response::new(Full::new(Bytes::from(content)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    if status == StatusCode::METHOD_NOT_ALLOWED {
        response.headers_mut().insert(
            hyper::header::ALLOW,
            hyper::header::HeaderValue::from_static("GET"),
        );
    }
    Ok(response)
}

#[cfg(test)]
mod tests;
