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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    match dispatch::execute(args).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let reported = error.downcast_ref::<common::error::ReportedFailure>();
            if reported.is_none() {
                common::error::error(error.as_ref(), json);
            }
            if error.is::<common::terminal::Canceled>()
                || matches!(reported, Some(common::error::ReportedFailure::Cancelled))
            {
                std::process::ExitCode::from(130)
            } else {
                std::process::ExitCode::FAILURE
            }
        }
    }
}
