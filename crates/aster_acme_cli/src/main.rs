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

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = app::Args::parse();
    let json = args.json();
    let cli = common::context::CommandContext::new(json);
    tracing_subscriber::fmt()
        .with_env_filter(if json {
            tracing_subscriber::EnvFilter::new("off")
        } else {
            tracing_subscriber::EnvFilter::from_default_env()
        })
        .with_ansi(cli.output.diagnostic_format().color)
        .with_writer(cli.output.clone())
        .init();
    let result = dispatch::execute(args, &cli).await.and_then(|report| {
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
