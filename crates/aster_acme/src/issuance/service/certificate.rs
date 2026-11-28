//! Issuance certificate stage: download, alternate-chain selection
//! ([RFC 8555 §7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)),
//! validation and promotion as one workflow stage, then ARI enrichment.
//! No renewal query occurs before certificate commitment.

use crate::issuance::chain::{self, ChainCandidate, ChainDecision, ChainName, ChainPreference};
use crate::issuance::progress::IssueEvent;
use crate::issuance::service::{IssueService, execution::bounded};
use crate::issuance::{IssueError, IssueExecution, IssueRecord};
use crate::storage::issuance::IssueSession;
use aster_acme_core::workflow::IssuancePhase;
use aster_acme_protocol::url::AcmeUrl;

impl IssueService {
    pub(super) async fn download(
        &self,
        session: &mut dyn IssueSession,
        record: &mut IssueRecord,
        url: &AcmeUrl,
        execution: &IssueExecution,
    ) -> Result<IssueRecord, IssueError> {
        self.observe(&IssueEvent::Downloading);
        record.phase = IssuancePhase::Downloading;
        session.save(record).await?;
        let response = bounded(execution, self.post(url, b"")).await?;
        if !Self::is_chain_response(&response) {
            return Err(IssueError::InvalidInput(
                "CA returned an invalid certificate media type or status",
            ));
        }
        let key = session.certificate_key().await?;
        // The CA's default chain is the issuance baseline; a broken default
        // response fails the stage instead of quietly falling back to a
        // candidate the CA did not offer as the primary artifact.
        crate::issuance::certificate::validate(&response.body, &key, &record.identifiers)?;
        let default_identity = chain::chain_identity(&response.body)?;
        let alternates = chain::parse_alternate_links(&response.headers, url)?;

        let (chain, identity, writeback) = match record.preferred_chain.clone() {
            // Explicit keep-the-default statements never fetch alternates.
            Some(ChainPreference::CaDefault) => (response.body, default_identity, None),
            // An explicit name must match one of the fully validated candidates;
            // interaction is a last-resort override, never a silent fallback.
            // The default chain needs no fetch: its identity is already known.
            Some(ChainPreference::Named(ref name)) if default_identity.matches(name) => {
                (response.body, default_identity, None)
            }
            Some(ChainPreference::Named(name)) => {
                let mut candidates = self
                    .fetch_candidates(
                        &key,
                        record,
                        &alternates,
                        default_identity,
                        response.body,
                        execution,
                    )
                    .await?;
                if let Some(index) = candidates
                    .iter()
                    .position(|(candidate, _)| candidate.identity.matches(&name))
                {
                    let (candidate, chain) = candidates.remove(index);
                    (chain, candidate.identity, None)
                } else {
                    self.observe_candidates(&candidates);
                    let (index, writeback) = self.decide_chain(Some(&name), &candidates)?;
                    let (candidate, chain) = candidates.remove(index);
                    (chain, candidate.identity, writeback)
                }
            }
            // Without a selector nothing else is discovered or fetched.
            None if self.chain_selector.is_none() => (response.body, default_identity, None),
            // Interactive discovery: only ask when a real choice exists, and keep
            // the CA default when every offered candidate failed validation.
            None => {
                let mut candidates = self
                    .fetch_candidates(
                        &key,
                        record,
                        &alternates,
                        default_identity,
                        response.body,
                        execution,
                    )
                    .await?;
                if candidates.len() == 1 {
                    let (candidate, chain) = candidates.remove(0);
                    (chain, candidate.identity, None)
                } else {
                    self.observe_candidates(&candidates);
                    let (index, writeback) = self.decide_chain(None, &candidates)?;
                    let (candidate, chain) = candidates.remove(index);
                    (chain, candidate.identity, writeback)
                }
            }
        };

        self.observe(&IssueEvent::ChainSelected {
            chain: identity.dn.clone(),
        });
        record.phase = IssuancePhase::Completed;
        record.selected_chain = Some(identity);
        // An interactive decision becomes the definition the renewal inherits;
        // explicit preferences were already fixed and only change by re-deciding.
        if let Some(preference) = writeback {
            record.preferred_chain = Some(preference);
        }
        session.save(record).await?;
        session.complete(record, &chain).await?;
        self.plan_renewal_after_download(session, &execution.context)
            .await
    }

    /// Fetch and validate every advertised alternate chain. A candidate that is
    /// unavailable or fails validation is dropped, never fatal: the default
    /// chain remains usable. Cancellation and the execution deadline still
    /// abort the stage, and the certificate URL itself is never re-fetched.
    async fn fetch_candidates(
        &self,
        key: &[u8],
        record: &IssueRecord,
        alternates: &[AcmeUrl],
        default_identity: chain::ChainIdentity,
        default_chain: Vec<u8>,
        execution: &IssueExecution,
    ) -> Result<Vec<(ChainCandidate, Vec<u8>)>, IssueError> {
        let mut candidates = vec![(
            ChainCandidate {
                is_default: true,
                identity: default_identity,
            },
            default_chain,
        )];
        for url in alternates {
            match bounded(execution, self.post(url, b"")).await {
                Ok(response) if Self::is_chain_response(&response) => {
                    let validated = crate::issuance::certificate::validate(
                        &response.body,
                        key,
                        &record.identifiers,
                    )
                    .and_then(|_| chain::chain_identity(&response.body));
                    match validated {
                        Ok(identity) => candidates.push((
                            ChainCandidate {
                                is_default: false,
                                identity,
                            },
                            response.body,
                        )),
                        Err(_) => {
                            tracing::warn!(url = %url.as_str(), "rejected invalid alternate certificate chain");
                        }
                    }
                }
                Ok(_) => {
                    tracing::warn!(url = %url.as_str(), "alternate chain URL returned no certificate chain");
                }
                Err(error @ (IssueError::Cancelled | IssueError::TimedOut)) => return Err(error),
                Err(error) => {
                    tracing::warn!(url = %url.as_str(), error = %error, "alternate chain fetch failed");
                }
            }
        }
        Ok(candidates)
    }

    /// Surface validated candidates and defer to the product selector.
    /// `requested` is set only after an explicit preference failed to match.
    fn decide_chain(
        &self,
        requested: Option<&ChainName>,
        candidates: &[(ChainCandidate, Vec<u8>)],
    ) -> Result<(usize, Option<ChainPreference>), IssueError> {
        let Some(selector) = &self.chain_selector else {
            let Some(name) = requested else {
                return Ok((0, None));
            };
            return Err(IssueError::ChainUnavailable {
                requested: name.as_str().to_owned(),
                available: candidate_names(candidates).join(", "),
            });
        };
        let offered = candidates
            .iter()
            .map(|(candidate, _)| candidate.clone())
            .collect::<Vec<_>>();
        let index = match selector.select(requested, &offered) {
            ChainDecision::DefaultChain => 0,
            ChainDecision::Selected(index) if index < candidates.len() => index,
            ChainDecision::Selected(_) => {
                return Err(IssueError::InvalidInput(
                    "chain selector returned an out-of-range candidate index",
                ));
            }
            ChainDecision::Abandon => return Err(IssueError::Cancelled),
        };
        if index == 0 && candidates[0].0.is_default {
            // The operator explicitly kept (or accepted) the CA default chain;
            // record it so renewals inherit the decision instead of re-asking.
            return Ok((0, Some(ChainPreference::CaDefault)));
        }
        let dn = candidates[index].0.identity.dn.clone();
        Ok((index, Some(ChainPreference::Named(ChainName::new(&dn)?))))
    }

    fn observe_candidates(&self, candidates: &[(ChainCandidate, Vec<u8>)]) {
        self.observe(&IssueEvent::ChainCandidatesObserved {
            available: candidate_names(candidates),
        });
    }

    fn is_chain_response(response: &crate::transport::AcmeResponse) -> bool {
        response.status == reqwest::StatusCode::OK
            && response
                .headers
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| {
                    value.split(';').next().is_some_and(|essence| {
                        essence
                            .trim()
                            .eq_ignore_ascii_case("application/pem-certificate-chain")
                    })
                })
    }

    // A cancelled ARI lookup must not turn an already committed issuance into failure.
    // Its six-hour query deadline is saved before GET; expose the latest durable plan.
    pub(super) async fn plan_renewal(
        &self,
        session: &mut dyn IssueSession,
        execution: &crate::solver::ExecutionContext,
    ) -> Result<IssueRecord, IssueError> {
        crate::renewal::RenewalService::new(self.client.clone())
            .refresh(session, execution)
            .await
    }

    async fn plan_renewal_after_download(
        &self,
        session: &mut dyn IssueSession,
        execution: &crate::solver::ExecutionContext,
    ) -> Result<IssueRecord, IssueError> {
        match self.plan_renewal(session, execution).await {
            Err(IssueError::Cancelled | IssueError::TimedOut) => session.record().await,
            result => result,
        }
    }
}

fn candidate_names(candidates: &[(ChainCandidate, Vec<u8>)]) -> Vec<String> {
    candidates
        .iter()
        .map(|(candidate, _)| candidate.identity.dn.clone())
        .collect()
}
