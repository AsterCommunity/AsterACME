//! Real hooks run in isolated test subprocesses because installation is process-global.
use super::*;
use std::process::Command;

#[test]
fn hook_child() {
    let Some(root) = std::env::var_os("ASTER_TEST_PANIC_ROOT") else {
        return;
    };
    let json = std::env::var_os("ASTER_TEST_PANIC_JSON").is_some();
    let output = OutputSession::new(json);
    let state = PanicState::install(output.clone(), Some(root.into()));
    if std::env::var_os("ASTER_TEST_PANIC_CONCURRENT").is_some() {
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let tasks = (0..4)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let _ = std::panic::catch_unwind(|| panic!("SECRET_MARKER simultaneous"));
                })
            })
            .collect::<Vec<_>>();
        for task in tasks {
            task.join().unwrap();
        }
        assert!(state.occurred());
    } else if std::env::var_os("ASTER_TEST_PANIC_WORKER").is_some() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let task = tokio::spawn(async {
                panic!("SECRET_MARKER worker credential");
            });
            assert!(task.await.unwrap_err().is_panic());
        });
        assert!(state.occurred());
    } else {
        let outcome = std::panic::catch_unwind(|| panic!("SECRET_MARKER\nmultiline credential"));
        assert!(outcome.is_err() && state.occurred());
    }
    assert!(
        output
            .finish("duplicate", super::super::session::FinalChannel::Result)
            .is_err()
    );
    if std::env::var_os("ASTER_TEST_PANIC_EXIT").is_some() {
        std::process::exit(1);
    }
}

#[test]
fn subprocess_reports_redact_payload_and_preserve_keys_and_json() {
    for json in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("saved-key"), b"untouched").unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "common::panic::tests::hook_child", "--nocapture"])
            .env("ASTER_TEST_PANIC_ROOT", &root)
            .env("NO_COLOR", "1");
        if json {
            command.env("ASTER_TEST_PANIC_JSON", "1");
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert!(
            !stderr.contains("SECRET_MARKER")
                && !stderr.contains("Backtrace:")
                && !stderr.contains('\x1b')
        );
        if json {
            assert!(
                serde_json::from_str::<serde_json::Value>(&stderr)
                    .unwrap()
                    .get("error")
                    .is_some()
            );
        } else {
            assert!(stderr.starts_with("[ERROR]"));
        }
        let report = std::fs::read_to_string(root.join("crash.log")).unwrap();
        assert!(report.contains("Backtrace:") && report.contains(env!("ASTER_BUILD_REVISION")));
        assert!(
            report.contains("hook_child"),
            "release function symbols must remain available"
        );
        assert!(!report.contains("SECRET_MARKER") && !report.contains("multiline credential"));
        assert_eq!(std::fs::read(root.join("saved-key")).unwrap(), b"untouched");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(root.join("crash.log"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}

const REPORT: &str = "=== AsterACME Panic Report ===\nVersion: test\nMessage: private\nmultiline secret\nReport: old\nBacktrace:\nfunction_symbol\n";

#[test]
fn reports_open_lazily_append_redacted_content_and_fail_closed_on_unknown_formats() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let writer = PrivateReports::open(Some(root.clone()), Arc::default());
    assert!(!root.join("crash.log").exists());
    writer.write_report(REPORT).unwrap();
    writer.write_report(REPORT).unwrap();
    let bytes = std::fs::read(root.join("crash.log")).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert_eq!(text.matches("Message:   <redacted>").count(), 2);
    assert!(!text.contains("multiline secret") && !text.contains("private"));
    assert!(writer.write_report("future incompatible format").is_err());
    assert_eq!(std::fs::read(root.join("crash.log")).unwrap(), bytes);
    assert!(
        PrivateReports::open(None, Arc::default())
            .write_report(REPORT)
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn unsafe_files_permissions_links_busy_locks_and_size_limits_never_overwrite_contents() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let writer = PrivateReports::open(Some(root.clone()), Arc::default());
    let path = root.join("crash.log");
    let target = temp.path().join("user-file");
    std::fs::write(&target, b"untouched").unwrap();
    for hard in [false, true] {
        if hard {
            std::fs::hard_link(&target, &path).unwrap();
        } else {
            symlink(&target, &path).unwrap();
        }
        assert!(writer.write_report(REPORT).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        std::fs::remove_file(&path).unwrap();
    }
    std::fs::write(&path, b"public").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(writer.write_report(REPORT).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"public");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.try_lock().unwrap();
    assert!(writer.write_report(REPORT).is_err());
    file.unlock().unwrap();
    file.set_len(1024 * 1024).unwrap();
    assert!(writer.write_report(REPORT).is_err());
    assert_eq!(file.metadata().unwrap().len(), 1024 * 1024);
    let linked = temp.path().join("linked-root");
    symlink(&root, &linked).unwrap();
    assert!(
        PrivateReports::open(Some(linked), Arc::default())
            .write_report(REPORT)
            .is_err()
    );
}

#[test]
fn subprocess_unavailable_report_does_not_fall_back_to_private_stderr_data() {
    let temp = tempfile::tempdir().unwrap();
    let unavailable = temp.path().join("missing-parent/state");
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "common::panic::tests::hook_child", "--nocapture"])
        .env("ASTER_TEST_PANIC_ROOT", &unavailable)
        .env("ASTER_TEST_PANIC_JSON", "1")
        .output()
        .unwrap();
    assert!(result.status.success());
    let text = String::from_utf8(result.stderr).unwrap();
    assert!(!text.contains("SECRET_MARKER") && !text.contains("Backtrace"));
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(
        json["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("unavailable")
    );
    assert!(!unavailable.exists());
}

#[test]
fn worker_panic_is_a_failure_with_one_public_document_even_if_join_error_is_handled() {
    let temp = tempfile::tempdir().unwrap();
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "common::panic::tests::hook_child", "--nocapture"])
        .env("ASTER_TEST_PANIC_ROOT", temp.path())
        .env("ASTER_TEST_PANIC_JSON", "1")
        .env("ASTER_TEST_PANIC_WORKER", "1")
        .env("ASTER_TEST_PANIC_EXIT", "1")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(!stderr.contains("SECRET_MARKER"));
    assert!(
        serde_json::from_str::<serde_json::Value>(&stderr)
            .unwrap()
            .get("error")
            .is_some()
    );
}

#[test]
fn closed_stderr_is_best_effort_and_does_not_prevent_private_report_creation() {
    let temp = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "common::panic::tests::hook_child", "--nocapture"])
        .env("ASTER_TEST_PANIC_ROOT", temp.path())
        .env("ASTER_TEST_PANIC_JSON", "1")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stderr.take());
    assert!(child.wait().unwrap().success());
    assert!(temp.path().join("crash.log").is_file());
}

#[test]
fn root_resolution_preserves_cli_scope_without_config_or_crash_file_side_effects() {
    use clap::Parser;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("uncreated");
    for command in [
        vec!["account", "list"],
        vec!["account", "register"],
        vec!["account", "rotate-key"],
        vec!["cert", "show"],
        vec!["cert", "renew", "--all"],
    ] {
        let mut args = vec!["aster-acme".to_owned()];
        args.extend(command.into_iter().map(str::to_owned));
        args.extend(["--data-dir".into(), root.to_str().unwrap().into()]);
        assert_eq!(
            data_root(&crate::app::Args::parse_from(args)).unwrap(),
            Some(root.clone())
        );
    }
    assert!(!root.exists());
    let version = crate::app::Args::parse_from(["aster-acme", "version"]);
    assert_eq!(data_root(&version).unwrap(), None);
    let default = crate::app::Args::parse_from(["aster-acme", "account", "list"]);
    assert_eq!(
        data_root(&default).unwrap(),
        Some(crate::config::default_data_dir().unwrap())
    );
}

#[test]
fn simultaneous_panics_keep_public_output_single_document_and_private_reports_parseable() {
    let temp = tempfile::tempdir().unwrap();
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "common::panic::tests::hook_child", "--nocapture"])
        .env("ASTER_TEST_PANIC_ROOT", temp.path())
        .env("ASTER_TEST_PANIC_JSON", "1")
        .env("ASTER_TEST_PANIC_CONCURRENT", "1")
        .output()
        .unwrap();
    assert!(result.status.success());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(&stderr)
            .unwrap()
            .get("error")
            .is_some()
    );
    let report = std::fs::read_to_string(temp.path().join("crash.log")).unwrap();
    assert!(!report.contains("SECRET_MARKER"));
    assert_eq!(
        report.matches("Panic Report ===").count(),
        report.matches("Message:   <redacted>").count()
    );
}
