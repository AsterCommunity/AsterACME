//! CLI rendering and scheduling for the optional library precheck API.
use crate::commands::cert::progress::Progress;
use aster_acme::{challenge::ChallengeKind, solver::ChallengeSolver, transport::HttpPool};
use std::sync::Arc;

pub(super) mod caa;
pub(super) mod dns;
mod http;

pub(super) fn with_http(
    solver: Box<dyn ChallengeSolver>,
    pool: HttpPool,
    progress: Arc<Progress>,
) -> Box<dyn ChallengeSolver> {
    if solver.kind() == ChallengeKind::Http01 {
        Box::new(http::Checked {
            inner: solver,
            pool,
            progress,
        })
    } else {
        solver
    }
}
