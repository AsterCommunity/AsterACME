use crate::daemon::DaemonLease;
use std::time::Duration;

#[tokio::test]
async fn daemon_lease_is_exclusive_and_released_on_drop() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let lease = DaemonLease::acquire(root.clone(), Duration::from_millis(30))
        .await
        .unwrap();
    assert!(
        DaemonLease::acquire(root.clone(), Duration::from_millis(30))
            .await
            .is_err()
    );
    drop(lease);
    assert!(
        DaemonLease::acquire(root, Duration::from_secs(1))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_second_process_cannot_start_a_resident_daemon_for_the_same_root() {
    const ROOT: &str = "ASTER_ACME_DAEMON_LOCK_TEST_ROOT";
    if let Some(root) = std::env::var_os(ROOT) {
        assert!(
            DaemonLease::acquire(root.into(), Duration::from_millis(50))
                .await
                .is_err()
        );
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let lease = DaemonLease::acquire(temp.path().to_path_buf(), Duration::from_secs(1))
        .await
        .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "daemon::tests::a_second_process_cannot_start_a_resident_daemon_for_the_same_root",
            "--nocapture",
        ])
        .env(ROOT, temp.path())
        .status()
        .unwrap();
    drop(lease);
    assert!(status.success());
}
