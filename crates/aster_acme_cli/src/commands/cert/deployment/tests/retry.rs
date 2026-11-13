//! Automatic admission is rechecked after acquiring a process-shared certificate lease.
use crate::commands::cert::deployment::run_target;
use crate::commands::cert::deployment::tests::Fixture;
use aster_acme::deployment::{DeploymentIntent, DeploymentPhase};
use aster_acme_cli_storage::issuance::{CliIssueStore, DeploymentBinding, DeploymentPatch};
use std::{fs, path::Path, time::Duration};

#[tokio::test]
async fn stale_daemon_snapshot_cannot_bypass_changed_retry_uncertainty_or_generation() {
    let fixture = Fixture::new().await;
    let target = fixture.add("retry", Vec::new(), 0).await;
    let generation = fixture.generation().await;
    let mut session = fixture
        .store
        .open_deployment(&fixture.name, "retry")
        .await
        .unwrap();
    session
        .save_state(DeploymentPhase::PublishFailed, 0, Some("original".into()))
        .await
        .unwrap();
    let snapshot = session.definition().clone();
    session
        .record_failure(
            DeploymentPhase::PublishFailed,
            0,
            "new failure".into(),
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    let future = session.definition().clone();
    drop(session);
    assert_skipped(&fixture, &generation, &snapshot).await;
    assert_eq!(fixture.status("retry").await, future);
    assert!(!target.join("cert.pem").exists());

    for phase in [
        DeploymentPhase::ReloadUncertain,
        DeploymentPhase::Reloading,
        DeploymentPhase::Deployed,
    ] {
        let mut session = fixture
            .store
            .open_deployment(&fixture.name, "retry")
            .await
            .unwrap();
        session.save_state(phase, 1, None).await.unwrap();
        drop(session);
        assert_skipped(&fixture, &generation, &snapshot).await;
    }
    fixture
        .store
        .update_deployment(
            &fixture.name,
            "retry",
            DeploymentPatch {
                timeout_seconds: Some(2),
                ..DeploymentPatch::default()
            },
        )
        .await
        .unwrap();
    assert_skipped(&fixture, &generation, &snapshot).await;
    fixture.complete(true).await;
    let automatic = run_target(
        &fixture.store,
        &fixture.name,
        &snapshot,
        DeploymentIntent::AfterIssuance {
            generation: &generation,
        },
        None,
        None,
    )
    .await;
    assert!(
        !automatic.attempted,
        "an old issuance result cannot deploy a newer generation"
    );
    assert_skipped(&fixture, &generation, &snapshot).await;
    assert!(!target.join("cert.pem").exists());
}

async fn assert_skipped(fixture: &Fixture, generation: &str, snapshot: &DeploymentBinding) {
    let execution = run_target(
        &fixture.store,
        &fixture.name,
        snapshot,
        DeploymentIntent::Retry {
            generation,
            snapshot,
        },
        None,
        None,
    )
    .await;
    assert!(!execution.attempted);
    assert!(
        execution.events.is_empty(),
        "a stale automatic snapshot is skipped, not failed"
    );
}

#[test]
#[ignore = "subprocess reload counter helper"]
fn reload_counter_child() {
    use std::io::Write;
    let counter = std::env::args().next_back().unwrap();
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&counter)
        .unwrap();
    writeln!(file, "reload").unwrap();
    file.flush().unwrap();
    let gate = Path::new(&counter).parent().unwrap().join("hold-reload");
    while gate.exists() {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::process::exit(7);
}

#[tokio::test]
#[ignore = "subprocess daemon deployment retry helper"]
async fn deployment_retry_child() {
    let Ok(root) = std::env::var("ASTER_DEPLOY_RETRY_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let snapshot: DeploymentBinding =
        serde_json::from_slice(&fs::read(root.join("snapshot.json")).unwrap()).unwrap();
    let generation = snapshot.generation.clone().unwrap();
    let store = CliIssueStore::new(root.clone(), Duration::from_secs(10));
    let name = aster_acme::issuance::CertificateName::new("web").unwrap();
    let role = std::env::var("ASTER_DEPLOY_RETRY_ROLE").unwrap();
    fs::write(root.join(format!("ready-{role}")), b"ready").unwrap();
    wait_for(&root.join("start-retry")).await;
    let intent = if role == "manual" {
        DeploymentIntent::Explicit
    } else {
        DeploymentIntent::Retry {
            generation: &generation,
            snapshot: &snapshot,
        }
    };
    let execution = run_target(&store, &name, &snapshot, intent, None, None).await;
    fs::write(
        root.join(format!("result-{role}")),
        execution.attempted.to_string(),
    )
    .unwrap();
}

async fn wait_for(path: &Path) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

fn spawn_retry_worker(root: &Path, role: &str) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "commands::cert::deployment::tests::retry::deployment_retry_child",
            "--ignored",
            "--nocapture",
        ])
        .env("ASTER_DEPLOY_RETRY_ROOT", root)
        .env("ASTER_DEPLOY_RETRY_ROLE", role)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

async fn finish_worker(child: std::process::Child) {
    let output = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn prepare_retry(fixture: &Fixture) {
    let root = fixture.temp.path();
    let command = vec![
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        "--exact".into(),
        "commands::cert::deployment::tests::retry::reload_counter_child".into(),
        "--ignored".into(),
        "--nocapture".into(),
        root.join("reload-count").to_string_lossy().into_owned(),
    ];
    fixture.add("retry", command, 0).await;
    let mut session = fixture
        .store
        .open_deployment(&fixture.name, "retry")
        .await
        .unwrap();
    session
        .save_state(
            DeploymentPhase::ReloadFailed,
            0,
            Some("previous failure".into()),
        )
        .await
        .unwrap();
    fs::write(
        root.join("snapshot.json"),
        serde_json::to_vec(session.definition()).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn daemon_waiting_on_manual_deploy_observes_failure_or_uncertainty_without_replaying() {
    for timeout in [false, true] {
        let fixture = Fixture::new().await;
        prepare_retry(&fixture).await;
        let root = fixture.temp.path();
        fs::write(root.join("hold-reload"), b"hold").unwrap();
        fs::write(root.join("start-retry"), b"start").unwrap();
        let manual = spawn_retry_worker(root, "manual");
        wait_for(&root.join("reload-count")).await;
        let daemon = spawn_retry_worker(root, "daemon");
        wait_for(&root.join("ready-daemon")).await;
        if !timeout {
            fs::remove_file(root.join("hold-reload")).unwrap();
        }
        finish_worker(manual).await;
        finish_worker(daemon).await;
        assert_eq!(
            fs::read_to_string(root.join("reload-count")).unwrap(),
            "reload\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("result-manual")).unwrap(),
            "true"
        );
        assert_eq!(
            fs::read_to_string(root.join("result-daemon")).unwrap(),
            "false"
        );
        assert_eq!(
            fixture.status("retry").await.phase,
            if timeout {
                DeploymentPhase::ReloadUncertain
            } else {
                DeploymentPhase::ReloadFailed
            }
        );
    }
}

#[tokio::test]
async fn two_daemons_only_reload_once_and_the_waiter_observes_the_new_backoff() {
    let fixture = Fixture::new().await;
    prepare_retry(&fixture).await;
    let root = fixture.temp.path();
    let mut children = Vec::new();
    for role in ["first", "second"] {
        children.push(spawn_retry_worker(root, role));
    }
    wait_for(&root.join("ready-first")).await;
    wait_for(&root.join("ready-second")).await;
    fs::write(root.join("start-retry"), b"go").unwrap();
    for child in children {
        finish_worker(child).await;
    }
    let attempted = ["first", "second"]
        .iter()
        .filter(|role| fs::read_to_string(root.join(format!("result-{role}"))).unwrap() == "true")
        .count();
    assert_eq!(attempted, 1);
    assert_eq!(
        fs::read_to_string(root.join("reload-count")).unwrap(),
        "reload\n"
    );
    let saved = fixture.status("retry").await;
    assert_eq!(saved.retry_failures, 1);
    assert!(
        saved
            .retry_at
            .is_some_and(|at| at > time::OffsetDateTime::now_utc())
    );
}
