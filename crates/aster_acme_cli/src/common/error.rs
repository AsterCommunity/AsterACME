//! Structured library errors translated at the process boundary.

use super::output::{safe, styled};
use crate::common::output::Style;
use aster_acme::{
    account::AccountError,
    transport::{RetryAfter, TransportError},
};
use aster_acme_cli_storage::StorageError;

pub(crate) mod problem;

pub(crate) type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Missing local identity, distinct from a CA rejecting an existing signing key.
#[derive(Debug)]
pub(crate) struct MissingLocalAccount {
    pub(crate) name: String,
}
impl std::fmt::Display for MissingLocalAccount {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "No local account named '{}'.", self.name)
    }
}
impl std::error::Error for MissingLocalAccount {}

/// Convert structured library failures at the CLI boundary; embedded callers retain
/// the original problem document and retry metadata for their own policy decisions.
pub(crate) fn diagnostic(error: &(dyn std::error::Error + 'static)) -> (String, Option<String>) {
    if let Some(missing) = error.downcast_ref::<MissingLocalAccount>() {
        return (
            missing.to_string(),
            Some(format!(
                "Check --name and --data-dir, or run account list --data-dir <PATH> to inspect saved accounts. Create one with account register --name '{}' --data-dir <PATH>.",
                missing.name
            )),
        );
    }
    if let Some(issue) = error.downcast_ref::<aster_acme::issuance::IssueError>() {
        use aster_acme::issuance::IssueError;
        return match issue {
            IssueError::AuthorizationFailed { status, problem } => self::problem::authorization_failed(status, problem.as_deref()),
            IssueError::Publication(_) => (issue.to_string(), Some("Check the challenge listener address, port availability and bind permissions, then resume the saved request. The CA must reach public port 80 for HTTP-01; a custom local port requires forwarding.".into())),
            IssueError::NameAlreadyExists(name)=>(issue.to_string(),Some(format!("Choose another --name, or inspect cert show '{}'. To continue its unfinished request use cert issue --resume '{}'.",name.as_str(),name.as_str()))),
            IssueError::RevocationUncertain(error)=>(format!("Certificate revocation outcome is unconfirmed. {}", transport_diagnostic(error).0),Some("Inspect cert show <NAME>. Rerun cert revoke <NAME> --yes with the same reason to request revocation again; local files are retained.".into())),
            IssueError::Transport(error)=>transport_diagnostic(error),
            IssueError::Store(error)=>(format!("Could not access certificate storage: {}", error.message),Some("Check --data-dir, managed files and permissions. Retain any .removing marker and remaining files for inspection.".into())),
            IssueError::PollLimit { .. } => (issue.to_string(), Some("Resume the saved request, or increase --max-polls. Retry-After and the overall --operation-timeout still apply; no new order is created.".into())),
            IssueError::InvalidOrder { problem } => self::problem::invalid_order(problem.as_deref()),
            IssueError::Expired=>(issue.to_string(),Some("Use cert show <CERTIFICATE> --verify to inspect the saved request. Start a new cert issue explicitly; local readiness cannot bypass CA expiry.".into())),
            IssueError::CreationUncertain=>(issue.to_string(),Some("Use cert list to inspect the retained request. Keep its key/CSR; a missing Location cannot be reconstructed safely and no new order will be created automatically.".into())),
            IssueError::Interrupted | IssueError::MutationUncertain(_)=>(issue.to_string(),Some("Use cert issue --resume <CERTIFICATE>; for several requests add --operation <ID>. Saved validation files and records remain under your control.".into())),
            IssueError::InvalidInput(_) | IssueError::Identifier(_) | IssueError::State(_) | IssueError::Challenge(_) | IssueError::Crypto(_)=>(issue.to_string(),Some("Inspect cert show <CERTIFICATE> for saved status and saved validation requirements. Retain the certificate key and CSR.".into())),
        };
    }
    if let Some(account) = error.downcast_ref::<AccountError>() {
        return match account {
            AccountError::KeyRotationUncertain => (
                "Account key rotation has an unfinished or uncertain result.".into(),
                Some("Retain both keys and rerun account rotate-key to reconcile the saved rotation.".into()),
            ),
            AccountError::KeyChangeUnavailable => (
                "This CA does not advertise account key rotation.".into(),
                None,
            ),
            AccountError::DeactivationUncertain => (
                "A previous deactivation request has an uncertain remote result.".into(),
                Some("Use account show --verify to attempt reconciliation. A 401 does not prove deactivation; consult your CA if it cannot confirm the result. The saved key is retained.".into()),
            ),
            AccountError::AccountNotActive => (
                "This account is deactivated, revoked, or has an unsupported CA status.".into(),
                Some("Choose another account name. ACME does not provide account reactivation.".into()),
            ),
            AccountError::Transport(transport) => transport_diagnostic(transport),
            AccountError::TermsRequired(url) => (
                "The CA requires your agreement to its current terms.".into(),
                Some(format!(
                    "Review {} and rerun account register with --accept-terms.",
                    url.as_str()
                )),
            ),
            AccountError::ExternalAccountRequired => (
                "This CA requires External Account Binding (EAB).".into(),
                Some(
                    "Supply --eab-kid <ID> --eab-key-file <PATH> with credentials from your CA."
                        .into(),
                ),
            ),
            AccountError::AccountDoesNotExist => missing_account(),
            AccountError::InvalidContact => (
                "The account contact is not a valid email address.".into(),
                Some(
                    "Use --contact you@example.com. Repeat --contact for multiple addresses."
                        .into(),
                ),
            ),
            AccountError::IdentityMismatch => (
                "Saved account metadata does not match this CA and key.".into(),
                Some(
                    "Check --ca-directory, --name and --data-dir; retain the original account key."
                        .into(),
                ),
            ),
            AccountError::ExternalAccountNotConfirmed => (
                "The CA did not confirm the supplied EAB binding.".into(),
                Some("Check the EAB credentials. The saved key is retained for recovery.".into()),
            ),
            AccountError::InvalidResponse => (
                "The CA returned an incomplete or unexpected account response.".into(),
                Some("Retry account recover with the same data directory and account name.".into()),
            ),
            AccountError::Store(store) => storage_message(&store.message),
            AccountError::Crypto(_) => (
                "The account signing key could not be read or used.".into(),
                Some("Keep the original key and check its format and storage permissions.".into()),
            ),
        };
    }
    if let Some(transport) = error.downcast_ref::<TransportError>() {
        return transport_diagnostic(transport);
    }
    if let Some(storage) = error.downcast_ref::<aster_acme::account::AccountStoreError>() {
        return storage_message(&storage.message);
    }
    if let Some(storage) = error.downcast_ref::<StorageError>() {
        return (storage.to_string(),Some("Check the account name, selected CA and data directory. Switching requires an already registered account.".into()));
    }
    (error.to_string(), None)
}

fn storage_message(message: &str) -> (String, Option<String>) {
    if message == "account key not found" {
        ("No local key exists for the selected account and CA.".into(),Some("Check --name / --ca-directory / --data-dir, or create an account with account register --accept-terms.".into()))
    } else {
        (format!("Could not access account storage: {message}"),Some("Check the data directory and permissions; do not delete or replace the saved account key.".into()))
    }
}

fn missing_account() -> (String, Option<String>) {
    ("This account key is not registered with the selected CA.".into(),Some("Run account register with the same --data-dir and --name, adding --accept-terms. Check --ca-directory if you expected an existing account.".into()))
}

/// Describe server retry guidance without implying mutations are automatically replayed.
fn retry_hint(retry_after: Option<&RetryAfter>) -> String {
    match retry_after {
        Some(RetryAfter::Delay(delay)) => format!("Wait at least {} seconds before retrying.", delay.as_secs()),
        Some(RetryAfter::At(time)) => format!("Retry after {}.", crate::common::time::timestamp(Some(time::OffsetDateTime::from(*time)))),
        None => "The CA has rate limited this request. Wait before retrying; consult its rate limit policy.".into(),
    }
}

fn transport_diagnostic(error: &TransportError) -> (String, Option<String>) {
    match error {
        TransportError::Problem {status,problem,retry_after} => self::problem::diagnostic(*status, problem, retry_after.as_ref()),
        TransportError::Network(network) if network.is_timeout() => ("The CA request timed out.".into(),Some("The remote result may be unknown. Retry with the same account and data directory; its saved key is retained.".into())),
        TransportError::Network(_) => ("Could not connect to the CA securely.".into(),Some("Check the directory URL, network and TLS trust. The saved account key is retained.".into())),
        TransportError::HttpStatus {status,..} => (format!("The CA returned HTTP {status} without a usable ACME response."),Some("Check the directory URL and retry later with the same account.".into())),
        other => (other.to_string(),None),
    }
}

/// One structured failure contract for ordinary errors and panic diagnostics.
#[derive(serde::Serialize)]
pub(crate) struct Diagnostic<'a> {
    pub(crate) message: &'a str,
    pub(crate) hint: Option<&'a str>,
}
#[derive(serde::Serialize)]
pub(crate) struct ErrorOutput<'a> {
    pub(crate) error: Diagnostic<'a>,
}

pub(crate) fn render(
    error: &(dyn std::error::Error + 'static),
    format: super::session::Format,
) -> CliResult<String> {
    let (message, hint) = diagnostic(error);
    if format.json {
        Ok(serde_json::to_string(&ErrorOutput {
            error: Diagnostic {
                message: &message,
                hint: hint.as_deref(),
            },
        })?)
    } else {
        let mut text = format!(
            "{} {}",
            crate::common::output::MessageKind::Error.badge(format.color),
            safe(&message)
        );
        if let Some(hint) = hint {
            text.push('\n');
            text.push_str(&styled("  Hint:", Style::Yellow, format.color));
            text.push(' ');
            text.push_str(&safe(&hint));
        }
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_acme_protocol::problem::ProblemKind;
    #[test]
    fn missing_account_is_actionable_and_not_a_debug_dump() {
        let error = TransportError::Problem {
            status: 400,
            problem: Box::new(aster_acme_protocol::problem::Problem {
                kind: ProblemKind::AccountDoesNotExist,
                detail: Some("No account exists with the provided key".into()),
                instance: None,
                subproblems: vec![],
                extensions: serde_json::Map::new(),
            }),
            retry_after: None,
        };
        let (message, hint) = diagnostic(&AccountError::Transport(error));
        assert!(message.contains("not registered"));
        assert!(hint.unwrap().contains("--accept-terms"));
        assert!(!message.contains("Problem {"));
    }
    #[test]
    fn terminal_controls_are_escaped_and_plain_output_has_no_ansi() {
        assert_eq!(safe("bad\x1b[2J\n"), "bad\\u{1b}[2J\\n");
        assert_eq!(styled("error", Style::Red, false), "error");
        assert!(styled("error", Style::Red, true).starts_with('\x1b'));
    }

    #[test]
    fn rate_limit_guidance_formats_delays_dates_and_missing_headers() {
        assert!(
            retry_hint(Some(&RetryAfter::Delay(std::time::Duration::from_secs(60))))
                .contains("60 seconds")
        );
        assert!(
            retry_hint(Some(&RetryAfter::At(std::time::UNIX_EPOCH)))
                .contains("1970-01-01 00:00:00 UTC")
        );
        assert!(!retry_hint(None).contains("None"));
    }
    #[test]
    fn missing_local_account_points_to_name_and_data_directory_in_a_separate_hint() {
        let error = MissingLocalAccount {
            name: "work".into(),
        };
        let (message, hint) = diagnostic(&error);
        assert_eq!(message, "No local account named 'work'.");
        let hint = hint.unwrap();
        assert!(hint.contains("--data-dir"));
        assert!(hint.contains("--name"));
        assert!(hint.contains("account list"));
        assert!(!hint.contains("--ca-directory"));
    }

    #[test]
    fn invalid_resource_problem_is_not_reported_as_http_failure_or_a_resume_action() {
        let problem = serde_json::from_value(serde_json::json!({"type":"urn:ietf:params:acme:error:unauthorized","detail":"HTTP returned 404","subproblems":[{"type":"urn:ietf:params:acme:error:connection","detail":"Connection refused","identifier":{"type":"dns","value":"example.com"}}]})).unwrap();
        let error = aster_acme::issuance::IssueError::InvalidOrder {
            problem: Some(Box::new(problem)),
        };
        let (message, hint) = diagnostic(&error);
        assert!(
            message.contains("HTTP returned 404")
                && message.contains("example.com")
                && message.contains("Connection refused")
        );
        assert!(!message.contains("HTTP 400"));
        assert!(hint.unwrap().contains("cannot be resumed"));
        let (message, _) =
            diagnostic(&aster_acme::issuance::IssueError::InvalidOrder { problem: None });
        assert!(message.contains("did not provide problem details"));
    }
}
