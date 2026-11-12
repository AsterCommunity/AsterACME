//! Blocking file work stays owned until solver shutdown, even if ready is dropped.
use aster_acme::issuance::IssueError;
use std::sync::Mutex;
use tokio::task::JoinHandle;

#[derive(Default)]
pub(in crate::commands::cert::validation) struct Workers(Mutex<Vec<JoinHandle<()>>>);
impl Workers {
    pub(super) async fn run(
        &self,
        work: impl FnOnce() -> Result<(), IssueError> + Send + 'static,
    ) -> Result<(), IssueError> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        {
            let mut workers = self
                .0
                .lock()
                .map_err(|_| IssueError::InvalidInput("webroot worker state poisoned"))?;
            workers.retain(|worker| !worker.is_finished());
            workers.push(tokio::task::spawn_blocking(move || {
                let _ = sender.send(work());
            }));
        }
        receiver
            .await
            .map_err(|_| IssueError::InvalidInput("webroot worker failed"))?
    }
    pub(super) async fn shutdown(&self) {
        let workers = self
            .0
            .lock()
            .map(|mut workers| std::mem::take(&mut *workers))
            .unwrap_or_default();
        for worker in workers {
            let _ = worker.await;
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::commands::cert::validation::webroot::workers::*;
    #[tokio::test]
    async fn dropped_waiter_does_not_release_worker_before_shutdown() {
        let workers = Workers::default();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        {
            let mut running = Box::pin(workers.run(move || {
                let _ = entered.send(());
                blocked.recv().unwrap();
                Ok(())
            }));
            tokio::select! { _ = &mut running => panic!("worker finished early"), _ = ready => {} }
        }
        let mut shutdown = Box::pin(workers.shutdown());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut shutdown)
                .await
                .is_err()
        );
        release.send(()).unwrap();
        shutdown.await;
    }
}
