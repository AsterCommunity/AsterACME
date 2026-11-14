//! ADPP solver: frozen routes, checkpointed receipts, separate propagation policy.
use crate::commands::cert::progress::Progress;
use aster_acme::{
    challenge::ChallengeKind,
    issuance::{IssueError, ValidationRequirement},
    solver::{
        ChallengePublication, ChallengeSolver, CleanupResult, ExecutionContext,
        PublicationPlanUpdate, PublicationReceiptUpdate, ReadyResult, RestoreResult,
    },
};
use aster_acme_dns::{
    CleanupRequest, DnsProvider, ProviderContext, ProviderExecution, RecordOwnership,
    propagation::PropagationPolicy,
    routing::{DnsLookup, absolute_name, resolve, validate_chain},
};
use async_trait::async_trait;
use std::sync::Arc;

pub(super) struct ExternalDns {
    pub(super) context: ProviderContext,
    pub(super) provider: Arc<dyn DnsProvider>,
    pub(super) lookup: Arc<dyn DnsLookup>,
    pub(super) allowed_zones: Vec<String>,
    pub(super) propagation: PropagationPolicy,
    pub(super) progress: Arc<Progress>,
}
fn scope(execution: &ExecutionContext) -> ProviderExecution {
    ProviderExecution {
        cancellation: execution.cancellation.clone(),
        deadline: execution.deadline,
    }
}
impl ExternalDns {
    async fn present(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<ReadyResult, IssueError> {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        let mut records = Vec::new();
        for publication in publications {
            let plan = publication.plan.as_ref().ok_or(IssueError::InvalidInput(
                "missing saved DNS publication route",
            ))?;
            validate_chain(
                &plan.challenge_name,
                &plan.name,
                &plan.cname_chain,
                &self.allowed_zones,
            )
            .map_err(IssueError::from)?;
            if publication.receipt.is_none() {
                records.push(plan.clone());
            }
        }
        let mut outcome = ReadyResult {
            ready: true,
            ..ReadyResult::default()
        };
        if records.is_empty() {
            return Ok(outcome);
        }
        let results = match self
            .provider
            .present(&self.context, &records, &scope(execution))
            .await
        {
            Ok(results) => results,
            Err(error) => {
                outcome.ready = false;
                if let aster_acme_dns::ProviderFailure::Provider(provider) = &error {
                    outcome.retry_at = retry_at(provider);
                }
                outcome.failure = Some(match error {
                    aster_acme_dns::ProviderFailure::Host {
                        code: aster_acme_dns::HostErrorCode::ProcessCancelled,
                        ..
                    } => IssueError::Interrupted,
                    error => IssueError::DnsProvider(error),
                });
                return Ok(outcome);
            }
        };
        for item in results {
            match item.result {
                Ok(receipt) => outcome.receipts.push(PublicationReceiptUpdate {
                    publication_id: item.publication_id,
                    receipt,
                }),
                Err(error) => {
                    outcome.retry_at = outcome.retry_at.max(retry_at(&error));
                    outcome.ready = false;
                    if outcome.failure.is_none() {
                        outcome.failure = Some(IssueError::DnsProvider(error.into()));
                    }
                }
            }
        }
        Ok(outcome)
    }
}
#[async_trait]
impl ChallengeSolver for ExternalDns {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::Dns01
    }
    fn requires_receipt(&self) -> bool {
        true
    }
    async fn prepare(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<Vec<PublicationPlanUpdate>, IssueError> {
        let mut updates = Vec::new();
        for publication in publications {
            if publication.plan.is_some() {
                continue;
            }
            let ValidationRequirement::Dns01 { name, value } = &publication.requirement else {
                return Err(IssueError::InvalidInput(
                    "external DNS solver received non-DNS material",
                ));
            };
            let chain = resolve(
                self.lookup.as_ref(),
                name,
                &self.allowed_zones,
                &scope(execution),
            )
            .await
            .map_err(|error| match error {
                aster_acme_dns::routing::RouteError::Interrupted => IssueError::Interrupted,
                error => IssueError::DnsRouting(error),
            })?;
            let target = chain
                .last()
                .cloned()
                .ok_or(IssueError::InvalidInput("empty DNS route"))?;
            updates.push(PublicationPlanUpdate {
                publication_id: publication.publication_id.clone(),
                plan: aster_acme_dns::DnsRecord {
                    publication_id: publication.publication_id.clone(),
                    challenge_name: absolute_name(name).map_err(IssueError::from)?,
                    cname_chain: chain,
                    name: target,
                    value: value.clone(),
                    ttl_seconds: Some(120),
                },
            });
        }
        Ok(updates)
    }
    async fn ready(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<ReadyResult, IssueError> {
        self.present(publications, execution).await
    }
    async fn wait_ready(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<(), IssueError> {
        let records = publications
            .iter()
            .map(|publication| {
                publication
                    .plan
                    .clone()
                    .ok_or(IssueError::InvalidInput("missing propagation route"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.propagation
            .wait(self.lookup.as_ref(), &records, &scope(execution))
            .await
            .map_err(|error| match error {
                aster_acme_dns::propagation::PropagationError::Interrupted => {
                    IssueError::Interrupted
                }
                error => IssueError::DnsPropagation(error),
            })?;
        self.progress.output.progress(
            crate::common::output::MessageKind::Success,
            "DNS provider records are published and expected TXT values are visible locally",
        );
        Ok(())
    }
    async fn restore(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<RestoreResult, IssueError> {
        let result = self.present(publications, execution).await?;
        Ok(RestoreResult {
            receipts: result.receipts,
            failure: result.failure,
            retry_at: result.retry_at,
        })
    }
    async fn cleanup(
        &self,
        publications: &[ChallengePublication],
        execution: &ExecutionContext,
    ) -> Result<CleanupResult, IssueError> {
        execution.check().map_err(|_| IssueError::Interrupted)?;
        let mut outcome = CleanupResult::default();
        let mut records = Vec::new();
        for publication in publications {
            let Some(receipt) = &publication.receipt else {
                if publication.plan.is_none() {
                    outcome.completed.push(publication.publication_id.clone());
                    continue;
                }
                outcome.failure = Some(IssueError::InvalidInput(
                    "DNS publication has no recovered cleanup receipt",
                ));
                continue;
            };
            if receipt.ownership == RecordOwnership::Preexisting {
                outcome.completed.push(publication.publication_id.clone());
                continue;
            }
            let Some(plan) = publication.plan.clone() else {
                if outcome.failure.is_none() {
                    outcome.failure = Some(IssueError::InvalidInput("missing saved cleanup route"));
                }
                continue;
            };
            if let Err(error) = validate_chain(
                &plan.challenge_name,
                &plan.name,
                &plan.cname_chain,
                &self.allowed_zones,
            ) {
                if outcome.failure.is_none() {
                    outcome.failure = Some(IssueError::from(error));
                }
                continue;
            }
            records.push(CleanupRequest {
                publication_id: publication.publication_id.clone(),
                receipt: receipt.clone(),
                record: plan,
            });
        }
        if !records.is_empty() {
            match self
                .provider
                .cleanup(&self.context, &records, &scope(execution))
                .await
            {
                Err(error) => {
                    if let aster_acme_dns::ProviderFailure::Provider(provider) = &error {
                        outcome.retry_at = retry_at(provider);
                    }
                    outcome.failure = Some(IssueError::DnsProvider(error));
                }
                Ok(results) => {
                    for item in results {
                        match item.result {
                            Ok(
                                aster_acme_dns::CleanupStatus::Removed
                                | aster_acme_dns::CleanupStatus::AlreadyAbsent,
                            ) => outcome.completed.push(item.publication_id),
                            Ok(aster_acme_dns::CleanupStatus::Retained) => {
                                outcome.failure = Some(IssueError::DnsProvider(aster_acme_dns::ProviderError {
                                    code: aster_acme_dns::ProviderErrorCode::RecordNotOwned,
                                    message: "provider retained an owned record; cleanup remains pending".into(),
                                    side_effect: aster_acme_dns::SideEffect::None, retry_after_seconds:None, provider_code:None,
                                }.into()));
                            }
                            Err(error) => {
                                outcome.retry_at = outcome.retry_at.max(retry_at(&error));
                                if outcome.failure.is_none() {
                                    outcome.failure = Some(IssueError::DnsProvider(error.into()));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(outcome)
    }
}

fn retry_at(error: &aster_acme_dns::ProviderError) -> Option<time::OffsetDateTime> {
    error
        .retry_after_seconds
        .and_then(|seconds| i64::try_from(seconds).ok())
        .and_then(|seconds| {
            time::OffsetDateTime::now_utc().checked_add(time::Duration::seconds(seconds))
        })
}
