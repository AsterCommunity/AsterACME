//! Issuance certificate stage: download, alternate-chain selection
//! ([RFC 8555 §7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)),
//! validation and promotion as one workflow stage, then ARI enrichment.
//! No renewal query occurs before certificate commitment.

use crate::issuance::chain::{self, ChainCandidate, ChainDecision, ChainName, ChainSelection};
use crate::issuance::progress::IssueEvent;
use crate::issuance::service::{
    IssueService,
    execution::{bounded, check},
};
use crate::issuance::{IssueError, IssueExecution, IssueRecord};
use crate::storage::issuance::IssueSession;
use aster_acme_core::workflow::IssuancePhase;
use aster_acme_protocol::url::AcmeUrl;

struct DownloadedChain {
    candidate: ChainCandidate,
    pem: Vec<u8>,
}

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
        let key = zeroize::Zeroizing::new(session.certificate_key().await?);
        // The CA's default chain is the issuance baseline; a broken default
        // response fails the stage instead of quietly falling back to a
        // candidate the CA did not offer as the primary artifact.
        crate::issuance::certificate::validate(&response.body, &key, &record.identifiers)?;
        let default_identity = chain::chain_identity(&response.body)?;
        let default = DownloadedChain {
            candidate: ChainCandidate {
                is_default: true,
                identity: default_identity,
            },
            pem: response.body,
        };
        let selection = record.chain_selection.as_ref();
        let requested = match selection {
            Some(ChainSelection::Named { chain, .. })
                if !default.candidate.identity.matches(chain) =>
            {
                Some(chain)
            }
            _ => None,
        };
        let discover =
            requested.is_some() || (selection.is_none() && self.chain_selector.is_some());
        let (selected, selection) = if discover {
            let alternates = chain::parse_alternate_links(&response.headers, url)?;
            let candidates = self
                .fetch_candidates(&key, record, &alternates, default, execution)
                .await?;
            self.select_candidate(requested, selection, candidates, &execution.context)?
        } else {
            (default, record.chain_selection.clone())
        };
        check(execution)?;
        drop(key);

        record.phase = IssuancePhase::Completed;
        record.selected_chain = Some(selected.candidate.identity);
        record.chain_selection = selection;
        // Completion owns the durable transition. A failed or interrupted write
        // must leave the existing Downloading checkpoint available for recovery.
        let committed = session.complete(record, &selected.pem).await?;
        if let Some(identity) = &committed.selected_chain {
            self.observe(&IssueEvent::ChainSelected {
                chain: identity.dn.clone(),
            });
        }
        self.observe(&IssueEvent::CertificateSaved {
            name: committed.name,
        });
        self.plan_renewal_after_download(session, &execution.context)
            .await
    }

    fn select_candidate(
        &self,
        requested: Option<&ChainName>,
        selection: Option<&ChainSelection>,
        mut candidates: Vec<DownloadedChain>,
        execution: &crate::solver::ExecutionContext,
    ) -> Result<(DownloadedChain, Option<ChainSelection>), IssueError> {
        let (index, selection) = if let Some((_name, index)) = requested.and_then(|name| {
            candidates
                .iter()
                .position(|chain| chain.candidate.identity.matches(name))
                .map(|index| (name, index))
        }) {
            (index, selection.cloned())
        } else if let Some(name) = requested {
            match selection {
                Some(ChainSelection::Named { remember: true, .. }) => {
                    self.observe(&IssueEvent::ChainSelectionUnavailable {
                        requested: name.as_str().to_owned(),
                        using: candidates[0].candidate.identity.dn.clone(),
                    });
                    (0, selection.cloned())
                }
                _ if self.chain_selector.is_some() => {
                    self.observe(&IssueEvent::ChainCandidatesObserved {
                        available: candidate_names(&candidates),
                    });
                    self.decide_chain(requested, &candidates, execution)?
                }
                _ => {
                    return Err(IssueError::ChainUnavailable {
                        requested: name.as_str().to_owned(),
                        available: candidate_names(&candidates),
                    });
                }
            }
        } else if candidates.len() > 1 {
            self.observe(&IssueEvent::ChainCandidatesObserved {
                available: candidate_names(&candidates),
            });
            self.decide_chain(requested, &candidates, execution)?
        } else if requested.is_none() && candidates.len() == 1 {
            (0, selection.cloned())
        } else {
            return Err(IssueError::InvalidInput(
                "chain candidate selection has no available decision",
            ));
        };
        Ok((candidates.swap_remove(index), selection))
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
        default: DownloadedChain,
        execution: &IssueExecution,
    ) -> Result<Vec<DownloadedChain>, IssueError> {
        let leaf = chain::leaf_der(&default.pem)?;
        let mut candidates = vec![default];
        for url in alternates {
            match bounded(execution, self.post(url, b"")).await {
                Ok(response) if Self::is_chain_response(&response) => {
                    let validated = crate::issuance::certificate::validate(
                        &response.body,
                        key,
                        &record.identifiers,
                    )
                    .and_then(|_| {
                        if chain::leaf_der(&response.body)? != leaf {
                            return Err(IssueError::InvalidInput(
                                "alternate chain has a different leaf",
                            ));
                        }
                        chain::chain_identity(&response.body)
                    });
                    match validated {
                        Ok(identity)
                            if identity.dn.len() <= 512 || identity.common_name.is_some() =>
                        {
                            candidates.push(DownloadedChain {
                                candidate: ChainCandidate {
                                    is_default: false,
                                    identity,
                                },
                                pem: response.body,
                            });
                        }
                        Ok(_) => {
                            tracing::warn!(
                                "rejected alternate certificate chain with an unaddressable top-level identity"
                            );
                        }
                        Err(_) => {
                            tracing::warn!("rejected invalid alternate certificate chain");
                        }
                    }
                }
                Ok(_) => {
                    tracing::warn!("alternate chain URL returned no certificate chain");
                }
                Err(error @ (IssueError::Cancelled | IssueError::TimedOut)) => return Err(error),
                Err(_) => {
                    tracing::warn!("alternate chain fetch failed");
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
        candidates: &[DownloadedChain],
        execution: &crate::solver::ExecutionContext,
    ) -> Result<(usize, Option<ChainSelection>), IssueError> {
        let Some(selector) = &self.chain_selector else {
            let Some(name) = requested else {
                return Ok((0, None));
            };
            return Err(IssueError::ChainUnavailable {
                requested: name.as_str().to_owned(),
                available: candidate_names(candidates),
            });
        };
        let offered = candidates
            .iter()
            .map(|chain| chain.candidate.clone())
            .collect::<Vec<_>>();
        let decision = selector.select(requested, &offered, execution)?;
        match decision {
            ChainDecision::DefaultChain => Ok((0, Some(ChainSelection::Default))),
            ChainDecision::Selected { index, remember } if index < candidates.len() => {
                let identity = &candidates[index].candidate.identity;
                let name = ChainName::new(&identity.dn).or_else(|error| {
                    identity
                        .common_name
                        .as_deref()
                        .map(ChainName::new)
                        .transpose()?
                        .ok_or(error)
                })?;
                Ok((
                    index,
                    Some(ChainSelection::Named {
                        chain: name,
                        remember,
                    }),
                ))
            }
            ChainDecision::Selected { .. } => Err(IssueError::InvalidInput(
                "chain selector returned an out-of-range candidate index",
            )),
            ChainDecision::Abandon => Err(IssueError::Cancelled),
        }
    }

    fn is_chain_response(response: &crate::transport::AcmeResponse) -> bool {
        response.status == reqwest::StatusCode::OK
            && response
                .headers
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| {
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

fn candidate_names(candidates: &[DownloadedChain]) -> Vec<String> {
    candidates
        .iter()
        .map(|chain| chain.candidate.identity.dn.clone())
        .collect()
}
