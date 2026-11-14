//! Invocation-owned Ctrl-C subscription. Dropping an operation always aborts its waiter.
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub(crate) struct InterruptGuard(JoinHandle<()>);

impl InterruptGuard {
    pub(crate) fn new(cancellation: CancellationToken) -> Self {
        Self(tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                cancellation.cancel();
            }
        }))
    }

    pub(crate) fn daemon(cancellation: CancellationToken) -> Self {
        #[cfg(unix)]
        {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut terminate) => Self(tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {},
                        _ = terminate.recv() => {},
                    }
                    cancellation.cancel();
                })),
                Err(_) => Self::new(cancellation),
            }
        }
        #[cfg(not(unix))]
        {
            Self::new(cancellation)
        }
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use crate::common::signal::InterruptGuard;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn dropping_guard_aborts_waiter_without_cancelling_unrelated_work() {
        let token = CancellationToken::new();
        let guard = InterruptGuard::new(token.clone());
        let waiter = guard.0.abort_handle();
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !waiter.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!token.is_cancelled());
    }
}
