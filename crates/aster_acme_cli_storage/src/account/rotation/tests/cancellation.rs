//! Deterministic suspension at the durable-intent/HTTP submission boundary.
use crate::account::rotation::tests::{post_count, setup};
use aster_acme::{
    account::AccountRecord,
    crypto::{JwsSigner, key_algorithm::KeyAlgorithm},
    storage::account::{AccountRotation, AccountRotationStore, AccountStoreError},
};
use aster_acme_core::account::KeyRotationPhase;
use aster_acme_protocol::url::AcmeUrl;
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};
use tokio::sync::Notify;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

struct PausingStore {
    inner: Arc<crate::account::CliAccountStore>,
    pending: Arc<Notify>,
    release: Arc<Notify>,
    confirmed: Arc<Notify>,
}
struct PausingRotation {
    inner: Box<dyn AccountRotation>,
    pending: Arc<Notify>,
    release: Arc<Notify>,
    confirmed: Arc<Notify>,
}
#[async_trait]
impl AccountRotationStore for PausingStore {
    async fn rotation(
        &self,
        directory: &AcmeUrl,
    ) -> Result<Box<dyn AccountRotation>, AccountStoreError> {
        Ok(Box::new(PausingRotation {
            inner: self.inner.rotation(directory).await?,
            pending: self.pending.clone(),
            release: self.release.clone(),
            confirmed: self.confirmed.clone(),
        }))
    }
}
#[async_trait]
impl AccountRotation for PausingRotation {
    fn record(&self) -> AccountRecord {
        self.inner.record()
    }
    fn old_signer(&self) -> Arc<dyn JwsSigner> {
        self.inner.old_signer()
    }
    async fn stage(
        &self,
        algorithm: Option<KeyAlgorithm>,
    ) -> Result<Arc<dyn JwsSigner>, AccountStoreError> {
        self.inner.stage(algorithm).await
    }
    async fn save(&self, record: &AccountRecord) -> Result<(), AccountStoreError> {
        self.inner.save(record).await?;
        if record
            .key_rotation
            .as_ref()
            .is_some_and(|state| state.phase == KeyRotationPhase::Pending)
        {
            self.pending.notify_one();
            self.release.notified().await;
        }
        if record
            .key_rotation
            .as_ref()
            .is_some_and(|state| state.phase == KeyRotationPhase::Confirmed)
        {
            self.confirmed.notify_one();
        }
        Ok(())
    }
    async fn commit(&self, record: &AccountRecord) -> Result<(), AccountStoreError> {
        self.inner.commit(record).await
    }
}

#[tokio::test]
async fn cancelling_after_pending_save_keeps_submission_owned_and_confirmed_recovery_offline() {
    let fixture = setup(true, Duration::from_secs(3)).await;
    Mock::given(method("POST"))
        .and(path("/vendor/rollover"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&fixture.server)
        .await;
    let pending = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let confirmed = Arc::new(Notify::new());
    let task = tokio::spawn({
        let service = fixture.service.clone();
        let store = PausingStore {
            inner: fixture.store.clone(),
            pending: pending.clone(),
            release: release.clone(),
            confirmed: confirmed.clone(),
        };
        async move { service.rotate_key(&store, None, None).await }
    });
    tokio::time::timeout(Duration::from_secs(3), pending.notified())
        .await
        .unwrap();
    assert_eq!(
        post_count(
            &fixture.server.received_requests().await.unwrap(),
            "/vendor/rollover"
        ),
        0
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    // Pending has crossed the durable intent boundary: the owned worker must
    // finish the one submission even though its original caller disappeared.
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), confirmed.notified())
        .await
        .unwrap();
    let result = fixture
        .service
        .rotate_key(fixture.store.as_ref(), None, None)
        .await
        .unwrap();
    assert!(result.key_rotation.is_none());
    assert_ne!(result.key_thumbprint, fixture.before.key_thumbprint);
    assert_eq!(
        post_count(
            &fixture.server.received_requests().await.unwrap(),
            "/vendor/rollover"
        ),
        1
    );
}
