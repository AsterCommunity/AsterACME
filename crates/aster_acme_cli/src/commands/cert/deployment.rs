//! CLI-managed file deployment and bounded service reload execution.

use crate::commands::cert::{progress::Progress, report::DeploymentEvent};
use crate::common::output::MessageKind;
use std::time::Duration;

const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_RETRIES: u8 = 3;
const MAX_BACKOFF: Duration = Duration::from_secs(4);

pub(crate) mod execution;
pub(crate) mod interaction;
pub(crate) mod reload;

pub(crate) mod automatic;
pub(crate) mod command;
pub(crate) mod configuration;
pub(crate) mod publication;
pub(crate) mod reload_state;
fn event(kind: MessageKind, message: impl Into<String>) -> DeploymentEvent {
    DeploymentEvent {
        pkcs12_path: None,
        cancelled: false,
        deployment: None,
        kind,
        message: message.into(),
        at: time::OffsetDateTime::now_utc(),
    }
}

fn record_event(
    events: &mut Vec<DeploymentEvent>,
    kind: MessageKind,
    message: &str,
    progress: Option<&Progress>,
) {
    let event = event(kind, message);
    if let Some(progress) = progress {
        progress
            .output
            .context(&crate::commands::cert::render::deployment::event(
                &event,
                progress.output.diagnostic_format().color,
            ));
    }
    events.push(event);
}

#[cfg(test)]
pub(crate) mod tests;
