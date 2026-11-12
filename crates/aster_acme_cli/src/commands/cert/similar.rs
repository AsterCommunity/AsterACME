//! New-request selection policy. Matching eligibility belongs to the ACME record.
use crate::common::{error::CliResult, session::OutputSession, terminal};
use aster_acme::issuance::IssueRecord;

pub(super) fn choose(
    mut candidates: Vec<IssueRecord>,
    automatic: bool,
    output: &OutputSession,
) -> CliResult<Option<IssueRecord>> {
    candidates.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then(left.operation_id.cmp(&right.operation_id))
    });
    match (
        candidates.len(),
        automatic,
        terminal::interactive(output.is_json()),
    ) {
        (0, _, _) => Ok(None),
        (1, true, _) => Ok(candidates.pop()),
        (_, true, _) | (_, false, false) => {
            let commands = candidates
                .iter()
                .map(|record| {
                    format!(
                        "aster-acme cert issue --resume '{}' --operation {}",
                        record.name.as_str(),
                        record.operation_id
                    )
                })
                .collect::<Vec<_>>()
                .join("\n  ");
            Err(format!("{} matching unfinished request(s) already exist. Resume an explicit request:\n  {commands}\nUse --if-similar-order to resume a unique match, or --name <NEW_NAME> for an independent request. No key or order was created.", candidates.len()).into())
        }
        (_, false, true) => {
            let mut choices = candidates
                .iter()
                .map(|record| {
                    crate::common::selection::ChoiceLabel {
                        name: record.name.as_str(),
                        summary: None,
                        at: Some(record.created_at),
                        status: Some(if record.creation_submitted && record.order_url.is_none() {
                            "creating order (result unconfirmed)"
                        } else {
                            super::render::request_status(record, time::OffsetDateTime::now_utc())
                        }),
                        marker: None,
                    }
                    .to_string()
                })
                .collect::<Vec<_>>();
            choices.push("Create a new independent request".into());
            let index = terminal::select_index(
                "A matching unfinished request exists. Resume or create new?",
                &choices,
                0,
                output,
            )?;
            if index == candidates.len() {
                Ok(None)
            } else {
                candidates
                    .into_iter()
                    .nth(index)
                    .map(Some)
                    .ok_or_else(|| "Invalid request selection.".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::commands::cert::similar::*;
    #[test]
    fn no_match_remains_new_and_similar_flag_is_explicitly_parsed() {
        use clap::Parser;
        for automatic in [false, true] {
            assert!(
                choose(vec![], automatic, &OutputSession::new(true))
                    .unwrap()
                    .is_none()
            );
        }
        let parsed = crate::app::Args::try_parse_from([
            "aster-acme",
            "cert",
            "issue",
            "-d",
            "example.com",
            "-c",
            "manual_http",
            "--if-similar-order",
        ]);
        assert!(parsed.is_ok());
        for extra in [vec!["--resume", "web"], vec!["--name", "independent"]] {
            let mut args = vec![
                "aster-acme",
                "cert",
                "issue",
                "-c",
                "manual_http",
                "--if-similar-order",
            ];
            args.extend(extra);
            assert!(crate::app::Args::try_parse_from(args).is_err());
        }
    }

    fn record(letter: char) -> IssueRecord {
        serde_json::from_value(serde_json::json!({
            "challenge":"http-01","solver_id":"manual_http","solver_config":{},"key_algorithm":"ecdsa-p256",
            "operation_id":letter.to_string().repeat(43),"name":format!("web-{letter}"),"created_at":"2026-01-01T00:00:00Z",
            "account_name":"default","account_id":"id","account_thumbprint":"key","directory":"https://ca.example/directory",
            "account_url":"https://ca.example/account","identifiers":["example.com"],"phase":"authorizing",
            "creation_submitted":true,"order_url":"https://ca.example/order/1","order":null,"authorizations":[],"finalize_submitted":"not_submitted"
        })).unwrap()
    }

    #[test]
    fn unique_opt_in_resumes_but_ambiguity_and_implicit_automation_never_pick_a_request() {
        let output = OutputSession::new(true);
        let first = record('a');
        let second = record('b');
        assert_eq!(
            choose(vec![first.clone()], true, &output)
                .unwrap()
                .unwrap()
                .operation_id,
            first.operation_id
        );
        let error = choose(vec![first.clone()], false, &output)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("--resume 'web-a' --operation "));
        assert!(error.contains("No key or order was created"));
        let error = choose(vec![first, second], true, &output)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("2 matching") && error.contains("web-a") && error.contains("web-b"));
    }
}
