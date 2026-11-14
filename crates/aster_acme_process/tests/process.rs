//! Real child processes cover full-duplex I/O, capture limits and shutdown boundaries.
use aster_acme_process::{ProcessFailure, ProcessSpec, ProcessStream, run};
use std::{
    io::{Read as _, Write as _},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
fn main() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("--process-fixture") {
        let Some(mode) = args.next() else { return };
        child(&mode);
        return;
    }
    tokio::runtime::Runtime::new().unwrap().block_on(check());
    println!(
        "Shared process contract: full-duplex stdin, exact output bounds, sensitive Debug, startup failure, cancellation and deadlines verified"
    );
}
fn child(mode: &str) {
    assert!(std::env::var_os("PATH").is_none());
    if mode == "closed-input" {
        return;
    }
    if mode == "wait" {
        print!("ready");
        std::io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_secs(10));
        return;
    }
    if mode == "tree" {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--process-fixture", "sleeper"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        println!("{}", child.id());
        std::io::stdout().flush().unwrap();
        let _ = child.wait();
        return;
    }
    if mode == "sleeper" {
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    if mode == "duplex" {
        std::io::stdout()
            .write_all(&vec![b'o'; 128 * 1024])
            .unwrap();
        std::io::stderr()
            .write_all(&vec![b'e'; 128 * 1024])
            .unwrap();
    }
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    if mode == "echo" {
        std::io::stdout().write_all(&input).unwrap();
    }
}
fn spec(mode: &str) -> ProcessSpec {
    let mut spec = ProcessSpec::new(std::env::current_exe().unwrap(), Duration::from_secs(5));
    spec.args = vec!["--process-fixture".into(), mode.into()];
    spec.clear_environment = true;
    spec
}
async fn check() {
    let token = CancellationToken::new();
    let mut echo = spec("echo");
    echo.stdin = Some(vec![0xff; 1024 * 1024]);
    echo.stdout_limit = 1024 * 1024;
    let output = run(echo, &token, |_, _| {}).await;
    assert!(output.status.unwrap().success());
    assert_eq!(output.stdout.bytes, vec![0xff; 1024 * 1024]);
    assert!(!output.stdout.truncated);
    assert!(output.stdin_error.is_none());
    let mut duplex = spec("duplex");
    duplex.stdin = Some(vec![b'i'; 1024 * 1024]);
    duplex.stdout_limit = 8;
    duplex.stderr_limit = 9;
    let observed = Arc::new(AtomicUsize::new(0));
    let counter = observed.clone();
    let output = run(duplex, &token, move |_, bytes| {
        counter.fetch_add(bytes.len(), Ordering::SeqCst);
    })
    .await;
    assert!(output.status.unwrap().success());
    assert_eq!(output.stdout.bytes.len(), 8);
    assert_eq!(output.stderr.bytes.len(), 9);
    assert!(output.stdout.truncated && output.stderr.truncated);
    assert_eq!(observed.load(Ordering::SeqCst), 17);
    let mut closed = spec("closed-input");
    closed.stdin = Some(vec![b'i'; 8 * 1024 * 1024]);
    let output = run(closed, &token, |_, _| {}).await;
    assert!(output.status.unwrap().success());
    assert!(output.stdin_error.is_some());
    let mut sensitive = spec("echo");
    sensitive.stdin = Some(b"secret-sentinel".to_vec());
    sensitive.environment = vec![("KEY".into(), "secret-sentinel".into())];
    assert!(!format!("{sensitive:?}").contains("secret-sentinel"));
    let token = CancellationToken::new();
    token.cancel();
    let output = run(spec("echo"), &token, |_, _| {}).await;
    assert!(matches!(
        output.status,
        Err(ProcessFailure::CancelledBeforeStart)
    ));
    assert!(!output.started);
    let token = CancellationToken::new();
    let cancel = token.clone();
    let observed_cancel_pid = Arc::new(AtomicU32::new(0));
    let cancel_pid = observed_cancel_pid.clone();
    let output = run(spec("tree"), &token, move |stream, bytes| {
        if stream == ProcessStream::Stdout && !bytes.is_empty() {
            let text = String::from_utf8_lossy(bytes);
            if let Ok(pid) = text.trim().parse::<u32>() {
                cancel_pid.store(pid, Ordering::SeqCst);
            }
            cancel.cancel();
        }
    })
    .await;
    assert!(matches!(output.status, Err(ProcessFailure::Cancelled)));
    assert!(output.started);
    wait_until_dead(observed_cancel_pid.load(Ordering::SeqCst)).await;
    let mut timeout = spec("tree");
    timeout.timeout = Duration::from_millis(100);
    let timed_out = run(timeout, &CancellationToken::new(), |_, _| {}).await;
    assert!(matches!(timed_out.status, Err(ProcessFailure::TimedOut)));
    let descendant = String::from_utf8_lossy(&timed_out.stdout.bytes)
        .trim()
        .parse::<u32>()
        .unwrap();
    wait_until_dead(descendant).await;
    let mut missing = spec("echo");
    missing.program =
        std::env::temp_dir().join(format!("asteracme-no-provider-{}", std::process::id()));
    let output = run(missing, &CancellationToken::new(), |_, _| {}).await;
    assert!(matches!(output.status, Err(ProcessFailure::Spawn(_))));
    assert!(!output.started);
}

async fn wait_until_dead(pid: u32) {
    assert_ne!(pid, 0, "tree fixture did not report its descendant PID");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while process_alive(pid) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !process_alive(pid),
        "descendant process {pid} survived shutdown"
    );
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).contains(&pid.to_string()))
}
