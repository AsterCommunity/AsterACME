//! Advisory TXT report rendering; resolver and budget are owned by the library.
use crate::commands::cert::progress::Progress;
use crate::common::output::MessageKind;
use aster_acme::{
    issuance::{IssueError, ValidationRequirement},
    precheck::Runner,
    solver::ExecutionContext,
};
use aster_acme_validation::{resolver::InitializationError, txt::Txt};

pub(in crate::commands::cert) async fn run(
    requirements: &[ValidationRequirement],
    execution: &ExecutionContext,
    progress: &Progress,
) -> Result<(), IssueError> {
    execution.check().map_err(IssueError::from)?;
    progress.output.progress(
        MessageKind::Info,
        &format!(
            "Checking local DNS visibility (advisory, up to {} seconds)",
            Runner::default().timeout().as_secs()
        ),
    );
    observe(Txt::system(), requirements, execution, progress).await
}

// Accept a constructed checker so initialization-failure policy is independently testable.
async fn observe(
    check: Result<Txt, InitializationError>,
    requirements: &[ValidationRequirement],
    execution: &ExecutionContext,
    progress: &Progress,
) -> Result<(), IssueError> {
    execution.check().map_err(IssueError::from)?;
    let check = match check {
        Ok(check) => check,
        Err(error) => {
            progress.output.progress(
                MessageKind::Warning,
                &format!(
                    "Local DNS precheck unavailable: {}; continuing to CA validation",
                    crate::common::output::safe(&error.to_string()),
                ),
            );
            return Ok(());
        }
    };
    let report = Runner::default()
        .run(&check, requirements, execution)
        .await
        .map_err(|error| match error {
            aster_acme::precheck::Error::Interrupted => execution
                .check()
                .map_or_else(IssueError::from, |()| IssueError::Cancelled),
            aster_acme::precheck::Error::InvalidBudget => {
                IssueError::InvalidInput("invalid DNS precheck budget")
            }
        })?;
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

#[cfg(test)]
mod tests {
    use crate::commands::cert::precheck::dns::*;
    use std::time::{Duration, Instant};
    use tokio_util::sync::CancellationToken;

    fn execution() -> ExecutionContext {
        ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }

    fn configuration_error() -> InitializationError {
        InitializationError::SystemConfiguration(
            "failed to parse nameserver address: invalid IP address syntax".into(),
        )
    }

    #[tokio::test]
    async fn initialization_failure_warns_with_actual_cause_and_remains_advisory() {
        let (output, stdout, diagnostics) = crate::common::session::tests::session(false);
        let progress = Progress::new(output);
        observe(Err(configuration_error()), &[], &execution(), &progress)
            .await
            .unwrap();
        assert_eq!(stdout.text(), "");
        let text = diagnostics.text();
        assert!(text.contains("[WARN]"));
        assert!(text.contains("cannot load system DNS configuration: failed to parse nameserver address: invalid IP address syntax"));
        assert!(text.contains("continuing to CA validation"));
        assert!(!text.contains("caaIdentities"));
    }

    #[tokio::test]
    async fn run_rejects_expired_execution_before_resolver_initialization() {
        let (output, stdout, diagnostics) = crate::common::session::tests::session(false);
        let progress = Progress::new(output);
        let expired = ExecutionContext {
            deadline: Instant::now(),
            ..execution()
        };
        assert!(matches!(
            run(&[], &expired, &progress).await,
            Err(IssueError::TimedOut)
        ));
        assert_eq!(stdout.text(), "");
        assert_eq!(diagnostics.text(), "");
    }

    #[tokio::test]
    async fn observe_reports_resolver_initialization_failure_and_continues_advisory() {
        let (output, stdout, diagnostics) = crate::common::session::tests::session(false);
        let progress = Progress::new(output);
        observe(Err(configuration_error()), &[], &execution(), &progress)
            .await
            .unwrap();
        assert_eq!(stdout.text(), "");
        let text = diagnostics.text();
        assert!(!text.contains("Checking local DNS visibility"));
        assert!(text.contains("failed to parse nameserver address"));
        assert!(text.contains("continuing to CA validation"));
    }

    #[tokio::test]
    async fn diagnostics_escape_control_characters_and_json_stays_silent() {
        for json in [false, true] {
            let (output, stdout, diagnostics) = crate::common::session::tests::session(json);
            let progress = Progress::new(output);
            observe(
                Err(InitializationError::Build("bad\nresolver\u{1b}[31m".into())),
                &[],
                &execution(),
                &progress,
            )
            .await
            .unwrap();
            assert_eq!(stdout.text(), "");
            let text = diagnostics.text();
            if json {
                assert_eq!(text, "");
            } else {
                assert!(text.contains("cannot build local DNS resolver"));
                assert!(!text.contains("bad\nresolver"));
                assert!(!text.contains('\u{1b}'));
            }
        }
    }

    #[tokio::test]
    async fn initialization_failure_never_overrides_cancellation_or_overall_deadline() {
        for cancelled in [false, true] {
            let mut execution = execution();
            if cancelled {
                execution.cancellation.cancel();
            } else {
                execution.deadline = Instant::now();
            }
            let (output, _, diagnostics) = crate::common::session::tests::session(false);
            let result = observe(
                Err(configuration_error()),
                &[],
                &execution,
                &Progress::new(output),
            )
            .await;
            assert!(matches!(
                (cancelled, result),
                (true, Err(IssueError::Cancelled)) | (false, Err(IssueError::TimedOut))
            ));
            assert_eq!(diagnostics.text(), "");
        }
    }
}
