//! Invocation-owned TCP service supervision, shared by HTTP-01 and future TLS-ALPN.
//! Protocol parsing stays in each handler. No detached connections survive shutdown.
use aster_acme::{issuance::IssueError, solver::ExecutionContext};
use std::{future::Future, net::SocketAddr, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

const MAX_CONNECTIONS: usize = 64;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct Listener {
    pub(super) address: SocketAddr,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl Listener {
    /// Binding completes before readiness or a CA acknowledgement is reported.
    /// A TLS-ALPN handler can perform its handshake inside the same bounded task.
    pub(super) async fn bind<F, Fut>(
        address: SocketAddr,
        execution: &ExecutionContext,
        handler: F,
    ) -> Result<Self, IssueError>
    where
        F: Fn(TcpStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        let listener = tokio::select! {
            biased;
            () = execution.cancellation.cancelled() => return Err(IssueError::Interrupted),
            result = tokio::time::timeout_at(execution.deadline.into(), TcpListener::bind(address)) => {
                result.map_err(|_| IssueError::Interrupted)?.map_err(|error| IssueError::Publication(format!("cannot bind {address}: {error}")))?
            }
        };
        let address = listener.local_addr().map_err(|error| {
            IssueError::Publication(format!("cannot read listener address: {error}"))
        })?;
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let cancellation = execution.cancellation.clone();
        let deadline = execution.deadline;
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    () = stopped.cancelled() => break,
                    () = cancellation.cancelled() => break,
                    () = tokio::time::sleep_until(deadline.into()) => break,
                    _ = connections.join_next(), if !connections.is_empty() => {},
                    accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                        match accepted {
                            Ok((stream, _)) => {
                                let serving = handler(stream);
                                connections.spawn(async move {
                                    let _ = tokio::time::timeout(CONNECTION_TIMEOUT, serving).await;
                                });
                            }
                            Err(error) => {
                                tracing::warn!(kind = ?error.kind(), "Challenge listener accept failed; closing listener");
                                break;
                            }
                        }
                    }
                }
            }
            // Close the public socket first, then abort and join active handlers.
            drop(listener);
            connections.shutdown().await;
        });
        Ok(Self {
            address,
            stop,
            task: Some(task),
        })
    }

    pub(super) fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub(super) async fn shutdown(mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // Dropping the solver must not leave a background server running.
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::execution;
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn concurrency_is_bounded_and_shutdown_joins_all_handlers() {
        let active = Arc::new(AtomicUsize::new(0));
        let count = active.clone();
        let controls = ExecutionContext {
            deadline: std::time::Instant::now() + Duration::from_secs(10),
            ..execution()
        };
        let listener = Listener::bind(([127, 0, 0, 1], 0).into(), &controls, move |_stream| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                let _guard = Active(count);
                std::future::pending::<()>().await;
            }
        })
        .await
        .unwrap();
        let address = listener.address;
        let mut clients = Vec::new();
        for _ in 0..MAX_CONNECTIONS + 4 {
            clients.push(TcpStream::connect(address).await.unwrap());
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) < MAX_CONNECTIONS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(active.load(Ordering::SeqCst), MAX_CONNECTIONS);
        listener.shutdown().await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(TcpListener::bind(address).await.is_ok());
    }

    #[tokio::test]
    async fn per_connection_deadline_releases_idle_handlers_before_operation_deadline() {
        let active = Arc::new(AtomicUsize::new(0));
        let count = active.clone();
        let controls = ExecutionContext {
            deadline: std::time::Instant::now() + Duration::from_secs(15),
            ..execution()
        };
        let listener = Listener::bind(([127, 0, 0, 1], 0).into(), &controls, move |_stream| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                let _guard = Active(count);
                std::future::pending::<()>().await;
            }
        })
        .await
        .unwrap();
        let _client = TcpStream::connect(listener.address).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(CONNECTION_TIMEOUT + Duration::from_millis(50)).await;
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(!listener.is_finished());
        listener.shutdown().await;
    }
}
