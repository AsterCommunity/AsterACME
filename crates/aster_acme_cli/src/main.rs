//! `AsterACME` account CLI; filesystem adapters are injected into the account service.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::unreachable,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo
    )
)]

mod app;
mod ca;
mod commands;
mod common;
mod config;
mod dispatch;

fn main() -> std::process::ExitCode {
    let args = app::Args::parse();
    let json = args.json();
    let cli = common::context::CommandContext::new(json);
    let root = match common::panic::data_root(&args) {
        Ok(root) => root,
        Err(error) => {
            if let Ok(text) = common::error::render(error.as_ref(), cli.output.diagnostic_format())
            {
                let _ = cli
                    .output
                    .finish(&text, common::session::FinalChannel::Diagnostic);
            }
            return std::process::ExitCode::FAILURE;
        }
    };
    let panic = common::panic::PanicState::install(cli.output.clone(), root);
    // Install before constructing Tokio worker threads. Catching only at the
    // executable boundary preserves unwinding/leases without retrying mutations.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let result = runtime.block_on(run(args, &cli));
        // Worker unwinding and retained storage leases finish before any final
        // report. A shutdown-time panic cannot follow a successful JSON document.
        drop(runtime);
        if panic.occurred() {
            let _ = panic.report();
            return Ok(std::process::ExitCode::FAILURE);
        }
        Ok(finish(result, &cli))
    })) {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => finish(Err(error), &cli),
        Err(_) => {
            let _ = panic.report();
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(
    args: app::Args,
    cli: &common::context::CommandContext,
) -> common::error::CliResult<dispatch::CommandReport> {
    let json = args.json();
    tracing_subscriber::fmt()
        .with_env_filter(if json {
            tracing_subscriber::EnvFilter::new("off")
        } else if args.debug {
            tracing_subscriber::EnvFilter::new(
                "off,aster_acme=debug,aster_acme_cli=debug,aster_acme_cli_storage=debug",
            )
        } else {
            tracing_subscriber::EnvFilter::from_default_env()
        })
        .with_ansi(false)
        .event_format(common::log::DiagnosticFormat {
            color: cli.output.diagnostic_format().color,
        })
        .with_writer(cli.output.clone())
        .init();
    dispatch::execute(args, cli).await
}

fn finish(
    execution: common::error::CliResult<dispatch::CommandReport>,
    cli: &common::context::CommandContext,
) -> std::process::ExitCode {
    let result = execution.and_then(|report| {
        let text = report.render(cli.output.format())?;
        cli.output
            .finish(&text, common::session::FinalChannel::Result)?;
        Ok(report.exit_status())
    });
    match result {
        Ok(status) => status.code(),
        Err(error) => {
            let status = if error.is::<common::terminal::Canceled>() {
                common::session::ExitStatus::Cancelled
            } else {
                common::session::ExitStatus::Failed
            };
            if let Ok(text) = common::error::render(error.as_ref(), cli.output.diagnostic_format())
            {
                let _ = cli
                    .output
                    .finish(&text, common::session::FinalChannel::Diagnostic);
            }
            status.code()
        }
    }
}
