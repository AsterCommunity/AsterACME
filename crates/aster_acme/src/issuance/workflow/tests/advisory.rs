//! Typed prechecks cannot turn negative evidence into a protocol refusal.
use crate::issuance::workflow::tests::*;
use crate::precheck::{
    self, Failure, Observation, Report,
    order::{BeforeOrder, Stage},
};
struct Advice<'a> {
    f: &'a MockServer,
    calls: AtomicUsize,
    result: u8,
}
#[async_trait]
impl BeforeOrder for Advice<'_> {
    type Output = bool;
    async fn check(
        &self,
        directory: &Directory,
        _: &IssueRecord,
        execution: &ExecutionContext,
    ) -> Result<Report<bool>, precheck::Error> {
        assert_eq!(directory.meta.caa_identities, ["ca.example"]);
        assert_eq!(
            self.f
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path() == "/create")
                .count(),
            0
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.result == 3 {
            execution.cancellation.cancel();
            return Err(precheck::Error::Interrupted);
        }
        Ok(Report {
            observations: vec![Observation {
                index: 0,
                result: match self.result {
                    0 => Ok(false),
                    1 => Err(Failure::LookupFailed),
                    _ => Err(Failure::TimedOut),
                },
            }],
        })
    }
}
#[derive(Default)]
struct Reports(AtomicUsize);
impl crate::precheck::order::Observer<bool> for Reports {
    fn observed(&self, report: &Report<bool>) {
        assert_eq!(report.observations.len(), 1);
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[tokio::test]
async fn mismatch_lookup_failure_and_local_timeout_continue_and_resume_skips_the_stage() {
    for result in [0, 1, 2] {
        let mut f = Fixture::new().await;
        let solver = Solver::default();
        let reports = Reports::default();
        let advice = Advice {
            f: &f.server,
            calls: AtomicUsize::new(0),
            result,
        };
        let stage = Stage::new(&advice).with_observer(&reports);
        assert!(
            f.workflow()
                .run_with_precheck(f.identity(), &mut f.session, &solver, &execution(), &stage)
                .await
                .is_ok()
        );
        assert!(
            f.workflow()
                .run_with_precheck(f.identity(), &mut f.session, &solver, &execution(), &stage)
                .await
                .is_ok()
        );
        assert_eq!(advice.calls.load(Ordering::SeqCst), 1);
        assert_eq!(reports.0.load(Ordering::SeqCst), 1);
        assert_eq!(f.count("/create").await, 1);
        assert_eq!(solver.0.load(Ordering::SeqCst), 2);
    }
}
#[tokio::test]
async fn cancellation_in_optional_check_stops_before_order_and_shutdown_is_awaited() {
    let mut f = Fixture::new().await;
    let solver = Solver::default();
    let advice = Advice {
        f: &f.server,
        calls: AtomicUsize::new(0),
        result: 3,
    };
    let result = f
        .workflow()
        .run_with_precheck(
            f.identity(),
            &mut f.session,
            &solver,
            &execution(),
            &Stage::new(&advice),
        )
        .await;
    assert!(matches!(result, Err(IssueError::Interrupted)));
    assert_eq!(f.count("/create").await, 0);
    assert!(!f.session.record().await.unwrap().new_order_intent_saved);
    assert_eq!(solver.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_identity_or_execution_never_runs_advice_or_new_order() {
    for wrong_identity in [false, true] {
        let mut f = Fixture::new().await;
        let solver = Solver::default();
        let advice = Advice {
            f: &f.server,
            calls: AtomicUsize::new(0),
            result: 0,
        };
        let mut identity = f.identity();
        let mut execution = execution();
        if wrong_identity {
            identity.account.account_id = "different".into();
        } else {
            execution.max_polls = 0;
        }
        assert!(
            f.workflow()
                .run_with_precheck(
                    identity,
                    &mut f.session,
                    &solver,
                    &execution,
                    &Stage::new(&advice)
                )
                .await
                .is_err()
        );
        assert_eq!(advice.calls.load(Ordering::SeqCst), 0);
        assert_eq!(f.count("/create").await, 0);
        assert_eq!(solver.0.load(Ordering::SeqCst), 1);
    }
}
