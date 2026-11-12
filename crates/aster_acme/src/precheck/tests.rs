//! Runner contracts are independent of DNS/HTTP implementations and CA state.
use crate::precheck::*;
struct Fake;
#[async_trait]
impl Check for Fake {
    type Input = u8;
    type Output = bool;
    async fn observe(&self, input: &u8, _: &ExecutionContext) -> Result<bool, Failure> {
        match input {
            0 => Ok(true),
            1 => Ok(false),
            2 => Err(Failure::LookupFailed),
            _ => std::future::pending().await,
        }
    }
}
fn context() -> ExecutionContext {
    ExecutionContext {
        cancellation: tokio_util::sync::CancellationToken::new(),
        deadline: Instant::now() + Duration::from_secs(5),
    }
}
#[tokio::test]
async fn failed_and_negative_observations_do_not_stop_remaining_inputs() {
    let report = Runner::default()
        .run(&Fake, &[0, 1, 2, 0], &context())
        .await
        .unwrap();
    let results = report
        .observations
        .iter()
        .map(|item| item.result)
        .collect::<Vec<_>>();
    assert_eq!(
        results,
        [Ok(true), Ok(false), Err(Failure::LookupFailed), Ok(true)]
    );
    assert_eq!(Runner::default().timeout(), Duration::from_secs(5));
}
#[tokio::test]
async fn shared_budget_retains_completed_entries_and_marks_every_unchecked_input() {
    let report = Runner::new(Duration::from_millis(30))
        .unwrap()
        .run(&Fake, &[0, 3, 0], &context())
        .await
        .unwrap();
    assert_eq!(
        report
            .observations
            .iter()
            .map(|item| item.index)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(report.observations[0].result, Ok(true));
    assert_eq!(report.observations[1].result, Err(Failure::TimedOut));
    assert_eq!(report.observations[2].result, Err(Failure::NotChecked));
}
#[tokio::test]
async fn cancellation_before_and_during_observation_and_overall_expiry_interrupt() {
    let ctx = context();
    ctx.cancellation.cancel();
    assert!(matches!(
        Runner::default().run(&Fake, &[0], &ctx).await,
        Err(Error::Interrupted)
    ));
    let ctx = context();
    let runner = Runner::default();
    let mut running = Box::pin(runner.run(&Fake, &[3], &ctx));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut running)
            .await
            .is_err()
    );
    ctx.cancellation.cancel();
    assert!(matches!(running.await, Err(Error::Interrupted)));
    let ctx = ExecutionContext {
        deadline: Instant::now() + Duration::from_millis(20),
        ..context()
    };
    assert!(matches!(
        runner.run(&Fake, &[3], &ctx).await,
        Err(Error::Interrupted)
    ));
}
#[tokio::test]
async fn invalid_budgets_and_empty_inputs_have_explicit_behavior() {
    assert_eq!(
        Runner::new(Duration::ZERO).unwrap_err(),
        Error::InvalidBudget
    );
    assert_eq!(
        Runner::new(Duration::MAX).unwrap_err(),
        Error::InvalidBudget
    );
    assert_eq!(
        Runner::default()
            .run(&Fake, &[], &context())
            .await
            .unwrap()
            .observations
            .len(),
        0
    );
}
