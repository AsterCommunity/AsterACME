//! Advisory TXT report rendering; resolver and budget are owned by the library.
use crate::commands::cert::progress::Progress;
use crate::common::output::MessageKind;
use aster_acme::{
    issuance::{IssueError, ValidationRequirement},
    precheck::Runner,
    solver::ExecutionContext,
};
use aster_acme_validation::txt::Txt;

pub(in crate::commands::cert) async fn run(
    requirements: &[ValidationRequirement],
    execution: &ExecutionContext,
    progress: &Progress,
) -> Result<(), IssueError> {
    execution.check().map_err(|_| IssueError::Interrupted)?;
    progress.output.progress(
        MessageKind::Info,
        &format!(
            "Checking local DNS visibility (advisory, up to {} seconds)",
            Runner::default().timeout().as_secs()
        ),
    );
    let Ok(check) = Txt::system() else {
        progress.output.progress(
            MessageKind::Warning,
            "Local DNS resolver is unavailable; continuing to CA validation",
        );
        return Ok(());
    };
    let report = Runner::default()
        .run(&check, requirements, execution)
        .await
        .map_err(|_| IssueError::Interrupted)?;
    if report
        .observations
        .iter()
        .all(|item| matches!(item.result, Ok(true)))
    {
        progress.output.progress(
            MessageKind::Success,
            "Required TXT values are visible through the local DNS resolver",
        );
    } else {
        progress.output.progress(MessageKind::Warning, "Local DNS precheck did not confirm all TXT values (missing, resolver error or timeout); continuing to CA validation");
    }
    Ok(())
}
