//! CLI rendering and scheduling for the optional library precheck API.
use crate::commands::cert::progress::Progress;
use aster_acme::{challenge::ChallengeKind, solver::ChallengeSolver, transport::HttpPool};
use std::sync::Arc;

pub(super) mod caa;
pub(super) mod dns;
mod validation;

pub(super) fn with_validation(
    solver: Box<dyn ChallengeSolver>,
    pool: HttpPool,
    progress: Arc<Progress>,
) -> Box<dyn ChallengeSolver> {
    if matches!(
        solver.kind(),
        ChallengeKind::Http01 | ChallengeKind::Dns01 | ChallengeKind::DnsPersist01
    ) {
        Box::new(validation::Checked {
            inner: solver,
            pool,
            progress,
        })
    } else {
        solver
    }
}
