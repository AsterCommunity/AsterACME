//! Certificate foreground execution.
use crate::commands::cert::execute::RunMode;
use crate::commands::cert::progress::Progress;
use crate::{
    commands::account::args::AccountArgs,
    common::{context::CliContext, error::CliResult, terminal},
};
use aster_acme::storage::issuance::IssueSession;
use aster_acme::{
    issuance::{IssueError, IssueExecution, IssueIdentity, IssueOutcome},
    solver::ExecutionContext,
};
use std::{sync::Arc, time::Duration};

pub(super) struct Foreground<'a> {
    pub(super) context: &'a CliContext,
    pub(super) options: &'a AccountArgs,
    pub(super) args: &'a crate::commands::cert::args::RunArgs,
    pub(super) mode: RunMode,
    pub(super) cli: &'a crate::common::context::CommandContext,
    pub(super) progress: Arc<Progress>,
    pub(super) execution: ExecutionContext,
}

impl Foreground<'_> {
    pub(super) async fn run(
        &self,
        identity: IssueIdentity,
        session: &mut dyn IssueSession,
    ) -> CliResult<IssueOutcome> {
        let saved = session.record().await?;
        let solver = if crate::commands::cert::validation::ValidationMethod::from_record(&saved)?
            == crate::commands::cert::validation::ValidationMethod::DnsProvider
        {
            crate::commands::cert::validation::provider_adapter(
                &saved,
                self.context
                    .config_path
                    .parent()
                    .ok_or("Missing provider profile root.")?,
                self.progress.clone(),
                self.cli.dns_http.clone(),
            )
            .await?
        } else {
            crate::commands::cert::validation::adapter(
                &saved,
                matches!(self.mode, RunMode::Single(_)) && terminal::interactive(self.options.json),
                self.args.yes,
                self.progress.clone(),
            )?
        };
        #[cfg(feature = "precheck")]
        let solver = crate::commands::cert::precheck::with_validation(
            solver,
            self.cli.http.clone(),
            self.progress.clone(),
        );
        let workflow = aster_acme::issuance::workflow::Workflow::new(
            self.cli.http.clone(),
            self.context.directory.clone(),
            self.context.transport_options(self.options)?,
        )?
        .with_observer(self.progress.clone());
        let (_, max_polls, poll_interval) = self.args.limits(&self.context.config);
        let execution = IssueExecution {
            max_polls,
            context: self.execution.clone(),
            poll_interval: Duration::from_secs(poll_interval),
        };
        #[cfg(feature = "precheck")]
        let result = {
            let check = aster_acme_validation::caa::order::OrderCaa::default();
            let observer =
                crate::commands::cert::precheck::caa::Display::new(&saved, &self.progress);
            let stage = aster_acme::precheck::order::Stage::new(&check).with_observer(&observer);
            workflow
                .run_with_precheck(identity, session, solver.as_ref(), &execution, &stage)
                .await
        };
        #[cfg(not(feature = "precheck"))]
        let result = workflow
            .run(identity, session, solver.as_ref(), &execution)
            .await;
        if matches!(result, Err(IssueError::Interrupted))
            && self.execution.cancellation.is_cancelled()
        {
            return Err(Box::new(terminal::Canceled));
        }
        Ok(result?)
    }
}
