//! Interactive alternate-chain selection during the download stage.
//! CA-provided names are untrusted terminal text; labels are escaped and the
//! decision stays index-based so duplicate names cannot collide.
use crate::common::{context::CommandContext, session::OutputSession, terminal};
use aster_acme::issuance::{ChainCandidate, ChainDecision, ChainName, ChainSelector};

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
    ) -> ChainDecision {
        // The default chain is always offered first and preselected, so keeping
        // the CA default costs one Enter; Esc abandons instead of re-deciding.
        let mut labels = vec![match requested {
            Some(name) => format!(
                "Use the CA default chain (no candidate matches {})",
                crate::common::output::safe(name.as_str())
            ),
            None => "Use the CA default chain".to_owned(),
        }];
        labels.extend(candidates.iter().map(|candidate| {
            let fingerprint = &candidate.identity.fingerprint_sha256;
            let fingerprint = fingerprint.get(..16).unwrap_or(fingerprint);
            format!(
                "{}{} — sha256:{}…",
                if candidate.is_default {
                    "[default] "
                } else {
                    ""
                },
                crate::common::output::safe(&candidate.identity.dn),
                fingerprint,
            )
        }));
        match terminal::select_index_or_back("Certificate chain:", &labels, 0, &self.output) {
            Ok(Some(index)) if index > 0 && index < candidates.len() => {
                ChainDecision::Selected(index)
            }
            Ok(Some(_)) => ChainDecision::DefaultChain,
            // A declined prompt or any terminal failure abandons the issuance;
            // the durable checkpoint keeps the operation resumable.
            _ => ChainDecision::Abandon,
        }
    }
}
