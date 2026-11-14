//! Cooperative cancellation waits for publication and bounds reload observation.

/// Manual deployments have cancellation but no overall issuance deadline.
/// Both entry points use the same boundary checks and reload interruption path.
pub(super) struct Execution {
    pub(super) cancellation: tokio_util::sync::CancellationToken,
    pub(super) deadline: Option<std::time::Instant>,
}
impl Execution {
    pub(super) fn check(&self) -> Result<(), &'static str> {
        if self.cancellation.is_cancelled()
            || self
                .deadline
                .is_some_and(|deadline| deadline <= std::time::Instant::now())
        {
            // Prompt cancellation says "not submitted", which is false once
            // file publication or reload has started. Keep that error separate.
            Err(
                "Deployment cancelled or execution deadline exceeded; saved state retained. Inspect cert deploy list/show before retrying.",
            )
        } else {
            Ok(())
        }
    }
}
impl From<&aster_acme::solver::ExecutionContext> for Execution {
    fn from(context: &aster_acme::solver::ExecutionContext) -> Self {
        Self {
            cancellation: context.cancellation.clone(),
            deadline: Some(context.deadline),
        }
    }
}
