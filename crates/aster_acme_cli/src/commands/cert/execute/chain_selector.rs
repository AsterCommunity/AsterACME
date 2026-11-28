//! Interactive alternate-chain selection during the download stage.
//! CA-provided names are untrusted terminal text; labels are escaped and the
//! decision stays index-based so duplicate names cannot collide.
use crate::common::{context::CommandContext, session::OutputSession, terminal};
use aster_acme::issuance::{ChainCandidate, ChainDecision, ChainName, ChainSelector};
use aster_acme::{issuance::IssueError, solver::ExecutionContext};

pub(super) struct InteractiveChainSelector {
    output: OutputSession,
}

impl InteractiveChainSelector {
    pub(super) fn new(cli: &CommandContext) -> Self {
        Self {
            output: cli.output.clone(),
        }
    }
}

impl ChainSelector for InteractiveChainSelector {
    fn select(
        &self,
        requested: Option<&ChainName>,
        candidates: &[ChainCandidate],
        execution: &ExecutionContext,
    ) -> Result<ChainDecision, IssueError> {
        execution.check()?;
        let decision = select_chain(requested, candidates, |labels| {
            terminal::select_index_or_back_bounded(
                "Certificate chain:",
                labels,
                0,
                &self.output,
                execution,
            )
        })?;
        execution.check()?;
        let decision = confirm_preference(decision, || {
            terminal::confirm_bounded(
                "Prefer this chain for future renewals?",
                false,
                &self.output,
                execution,
            )
        })?;
        execution.check()?;
        Ok(decision)
    }
}

fn confirm_preference(
    decision: ChainDecision,
    confirm: impl FnOnce() -> Result<bool, IssueError>,
) -> Result<ChainDecision, IssueError> {
    let ChainDecision::Selected {
        index,
        remember: false,
    } = decision
    else {
        return Ok(decision);
    };
    Ok(ChainDecision::Selected {
        index,
        remember: confirm()?,
    })
}

fn select_chain(
    requested: Option<&ChainName>,
    candidates: &[ChainCandidate],
    prompt: impl FnOnce(&[String]) -> Result<Option<usize>, IssueError>,
) -> Result<ChainDecision, IssueError> {
    let labels = candidates
        .iter()
        .map(|candidate| {
            let identity = &candidate.identity;
            let fingerprint = &identity.fingerprint_sha256;
            let fingerprint = fingerprint.get(..16).unwrap_or(fingerprint);
            let name = crate::common::output::safe(&identity.dn);
            let label = format!("{name} — sha256:{fingerprint}…");
            if candidate.is_default {
                if requested.is_some_and(|name| !candidate.identity.matches(name)) {
                    format!("Use CA default chain ({label}); requested chain unavailable")
                } else {
                    format!("Use CA default chain ({label})")
                }
            } else {
                label
            }
        })
        .collect::<Vec<_>>();
    Ok(match prompt(&labels)? {
        Some(0) => ChainDecision::DefaultChain,
        Some(index) => match candidates.get(index) {
            Some(_) => ChainDecision::Selected {
                index,
                remember: false,
            },
            None => ChainDecision::Abandon,
        },
        None => ChainDecision::Abandon,
    })
}

#[cfg(test)]
mod tests {
    use crate::commands::cert::execute::chain_selector::{confirm_preference, select_chain};
    use aster_acme::issuance::{ChainCandidate, ChainDecision, ChainIdentity, ChainName};

    #[cfg(unix)]
    #[test]
    #[ignore = "native chain selection deadline PTY fixture"]
    fn bounded_chain_prompt_child() {
        use crate::common::session::OutputSession;
        use aster_acme::{issuance::IssueError, solver::ExecutionContext};
        use std::time::{Duration, Instant};
        use tokio_util::sync::CancellationToken;

        let output = OutputSession::new(false);
        let execution = ExecutionContext {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_millis(300),
        };
        let result = crate::common::terminal::select_index_or_back_bounded(
            "Certificate chain:",
            &["Use CA default chain".to_owned(), "Alternate".to_owned()],
            0,
            &output,
            &execution,
        );
        assert!(matches!(result, Err(IssueError::TimedOut)));
        println!("CHAIN_TERMINAL_TIMEOUT_DONE");
    }

    #[test]
    fn menu_rows_select_the_candidates_they_display() {
        let candidates = ["Default", "Yucca", "Bulgur"].map(|name| ChainCandidate {
            is_default: name == "Default",
            identity: ChainIdentity {
                dn: format!("CN={name}"),
                common_name: Some(name.to_owned()),
                fingerprint_sha256: "0123456789abcdef".to_owned(),
            },
        });
        let missing = ChainName::new("Missing").unwrap();
        assert!(matches!(
            select_chain(Some(&missing), &candidates, |labels| {
                assert!(labels[0].contains("requested chain unavailable"));
                Err(aster_acme::issuance::IssueError::TimedOut)
            }),
            Err(aster_acme::issuance::IssueError::TimedOut)
        ));
        for (input, expected) in [
            (Some(0), ChainDecision::DefaultChain),
            (
                Some(1),
                ChainDecision::Selected {
                    index: 1,
                    remember: false,
                },
            ),
            (
                Some(2),
                ChainDecision::Selected {
                    index: 2,
                    remember: false,
                },
            ),
            (Some(3), ChainDecision::Abandon),
            (None, ChainDecision::Abandon),
        ] {
            let actual = select_chain(None, &candidates, |labels| {
                assert_eq!(
                    labels,
                    [
                        "Use CA default chain (CN=Default — sha256:0123456789abcdef…)",
                        "CN=Yucca — sha256:0123456789abcdef…",
                        "CN=Bulgur — sha256:0123456789abcdef…",
                    ]
                );
                Ok(input)
            });
            assert_eq!(actual.unwrap(), expected);
        }
    }

    #[test]
    fn default_selection_skips_soft_preference_confirmation() {
        for decision in [ChainDecision::DefaultChain, ChainDecision::Abandon] {
            let actual = confirm_preference(decision.clone(), || {
                panic!("default and cancel do not ask to save a preference")
            });
            assert_eq!(actual.unwrap(), decision);
        }
    }

    #[test]
    fn concrete_selection_uses_the_second_answer_for_preference_policy() {
        for (answer, expected) in [(false, false), (true, true)] {
            let actual = confirm_preference(
                ChainDecision::Selected {
                    index: 2,
                    remember: false,
                },
                || Ok(answer),
            )
            .unwrap();
            assert_eq!(
                actual,
                ChainDecision::Selected {
                    index: 2,
                    remember: expected,
                }
            );
        }
    }
}
