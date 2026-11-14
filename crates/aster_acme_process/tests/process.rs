//! Real child processes cover full-duplex I/O, capture limits and shutdown boundaries.
use aster_acme_process::{ProcessFailure, ProcessSpec, ProcessStream, run};
use std::{
    io::{Read as _, Write as _},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
fn main() {
    if let Some(mode) = std::env::args().nth(1) {
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
    spec.args = vec![mode.into()];
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
    let output = run(spec("wait"), &token, move |stream, bytes| {
        if stream == ProcessStream::Stdout && !bytes.is_empty() {
            cancel.cancel();
        }
    })
    .await;
    assert!(matches!(output.status, Err(ProcessFailure::Cancelled)));
    assert!(output.started);
    let mut timeout = spec("wait");
    timeout.timeout = Duration::from_millis(100);
    assert!(matches!(
        run(timeout, &CancellationToken::new(), |_, _| {})
            .await
            .status,
        Err(ProcessFailure::TimedOut)
    ));
    let mut missing = spec("echo");
    missing.program =
        std::env::temp_dir().join(format!("asteracme-no-provider-{}", std::process::id()));
    let output = run(missing, &CancellationToken::new(), |_, _| {}).await;
    assert!(matches!(output.status, Err(ProcessFailure::Spawn(_))));
    assert!(!output.started);
}
