//! Real test processes exercise concurrent output draining and whole-tree cleanup.
use crate::commands::cert::{
    deployment::reload::*,
    deployment::tests::{assert_descendant_exited, child_command},
};

#[tokio::test]
async fn successful_parent_does_not_leave_background_descendants_running() {
    let temp = tempfile::tempdir().unwrap();
    let heartbeat = temp.path().join("heartbeat");
    let command = child_command(&format!("tree-success:{}", heartbeat.display()));
    let result = run(
        &command,
        Duration::from_secs(5),
        "test",
        1,
        &mut Vec::new(),
        None,
        None,
    )
    .await;
    assert!(result.status.unwrap().success());
    assert!(!result.timed_out);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_descendant_exited(&heartbeat).await;
    let before = std::fs::read(&heartbeat).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(std::fs::read(heartbeat).unwrap(), before);
}

#[tokio::test]
async fn both_streams_exit_status_and_output_limits_are_preserved_without_deadlock() {
    for (mode, success) in [
        ("output-success", true),
        ("output-failure", false),
        ("large-output", true),
    ] {
        let mut events = Vec::new();
        let result = run(
            &child_command(mode),
            Duration::from_secs(5),
            "test",
            1,
            &mut events,
            None,
            None,
        )
        .await;
        assert_eq!(result.status.unwrap().success(), success);
        assert!(!result.timed_out);
        assert!(events.iter().any(|event| event.message.contains("stdout:")));
        assert!(events.iter().any(|event| event.message.contains("stderr:")));
        assert!(
            events
                .iter()
                .all(|event| event.message.len() < MAX_OUTPUT + 256)
        );
        if mode == "large-output" {
            assert_eq!(
                events
                    .iter()
                    .filter(|e| e.message.contains("truncated at 64 KiB"))
                    .count(),
                2
            );
        }
    }
}

#[tokio::test]
async fn timeout_retains_partial_output_and_kills_descendants() {
    let mut events = Vec::new();
    let result = run(
        &child_command("output-timeout"),
        Duration::from_millis(400),
        "test",
        1,
        &mut events,
        None,
        None,
    )
    .await;
    assert!(result.timed_out);
    assert!(
        events
            .iter()
            .any(|event| event.message.contains("output before timeout"))
    );
    let temp = tempfile::tempdir().unwrap();
    let heartbeat = temp.path().join("heartbeat");
    let command = child_command(&format!("tree:{}", heartbeat.display()));
    run(
        &command,
        Duration::from_secs(1),
        "test",
        1,
        &mut events,
        None,
        None,
    )
    .await;
    assert_descendant_exited(&heartbeat).await;
    let before = std::fs::read(&heartbeat).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(std::fs::read(heartbeat).unwrap(), before);
}

#[tokio::test]
async fn dropping_reload_future_terminates_the_owned_process_tree() {
    let temp = tempfile::tempdir().unwrap();
    let heartbeat = temp.path().join("heartbeat");
    let command = child_command(&format!("tree:{}", heartbeat.display()));
    let mut events = Vec::new();
    {
        let execution = run(
            &command,
            Duration::from_secs(30),
            "test",
            1,
            &mut events,
            None,
            None,
        );
        tokio::pin!(execution);
        tokio::select! {
            result = &mut execution => panic!("child unexpectedly exited: {}", result.status.is_ok()),
            () = async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while !heartbeat.exists() { tokio::time::sleep(Duration::from_millis(10)).await; }
                }).await.unwrap();
            } => {},
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_descendant_exited(&heartbeat).await;
    let before = std::fs::read(&heartbeat).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(std::fs::read(heartbeat).unwrap(), before);
}

#[tokio::test]
async fn successful_parent_with_inherited_pipes_does_not_turn_into_a_timeout() {
    let temp = tempfile::tempdir().unwrap();
    let heartbeat = temp.path().join("heartbeat");
    let result = run(
        &child_command(&format!("tree-inherited:{}", heartbeat.display())),
        Duration::from_secs(3),
        "test",
        1,
        &mut Vec::new(),
        None,
        None,
    )
    .await;
    assert!(!result.timed_out);
    assert!(result.status.unwrap().success());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_descendant_exited(&heartbeat).await;
    let before = std::fs::read(&heartbeat).unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(before, std::fs::read(heartbeat).unwrap());
}

#[cfg(unix)]
#[tokio::test]
async fn reload_timeout_terminates_owned_descendants_that_inherit_pipe_handles() {
    let temp = tempfile::tempdir().unwrap();
    let heartbeat = temp.path().join("heartbeat");
    let mut events = Vec::new();
    let result = run(
        &child_command(&format!("tree-wait-inherited:{}", heartbeat.display())),
        Duration::from_secs(2),
        "test",
        1,
        &mut events,
        None,
        None,
    )
    .await;
    assert!(result.timed_out);
    assert_descendant_exited(&heartbeat).await;
    let first = std::fs::read(&heartbeat).unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(first, std::fs::read(heartbeat).unwrap());
}

#[tokio::test]
async fn overall_deadline_terminates_waiting_parent_and_inherited_pipe_descendants() {
    let temp = tempfile::tempdir().unwrap();
    let heartbeat = temp.path().join("heartbeat");
    let command = child_command(&format!("tree-wait-inherited:{}", heartbeat.display()));
    let mut events = Vec::new();
    let execution = crate::commands::cert::deployment::execution::Execution {
        cancellation: tokio_util::sync::CancellationToken::new(),
        deadline: Some(std::time::Instant::now() + Duration::from_secs(2)),
    };
    let result = run(
        &command,
        Duration::from_secs(30),
        "test",
        1,
        &mut events,
        None,
        Some(&execution),
    )
    .await;
    assert!(result.status.is_err());
    assert!(result.timed_out);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_descendant_exited(&heartbeat).await;
    let before = std::fs::read(&heartbeat).unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(before, std::fs::read(&heartbeat).unwrap());
}

#[test]
fn streaming_utf8_preserves_split_characters_and_replaces_only_invalid_bytes() {
    let mut text = StreamText::default();
    let bytes = "中文🙂".as_bytes();
    let mut output = String::new();
    for byte in bytes {
        output.push_str(&text.push(&[*byte], false));
    }
    output.push_str(&text.push(&[], true));
    assert_eq!(output, "中文🙂");
    assert_eq!(text.push(&[0xff, b'a', 0xe4], false), "�a");
    assert_eq!(text.push(&[], true), "�");
}
