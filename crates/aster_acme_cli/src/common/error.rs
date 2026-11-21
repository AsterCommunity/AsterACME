//! Structured library errors translated at the process boundary.

use crate::common::output::Style;
use crate::common::output::{safe, styled};
use aster_acme::{
    account::AccountError,
    transport::{RetryAfter, TransportError},
};
use aster_acme_cli_storage::account::StorageError;
use std::fmt::Write as _;

pub(crate) mod problem;

pub(crate) type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Operation context retains the source for diagnostics and process disposition.
#[derive(Debug)]
pub(crate) struct ContextError {
    pub(crate) context: String,
    pub(crate) source: Box<dyn std::error::Error>,
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.context)
    }
}

impl std::error::Error for ContextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Cancellation remains cancellation when an operation adds partial-result context.
pub(crate) fn exit_status(
    mut error: &(dyn std::error::Error + 'static),
) -> crate::common::session::ExitStatus {
    loop {
        if error.is::<crate::common::terminal::Canceled>() {
            return crate::common::session::ExitStatus::Cancelled;
        }
        match error.source() {
            Some(source) => error = source,
            None => return crate::common::session::ExitStatus::Failed,
        }
    }
}

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
    if let Some(context) = error.downcast_ref::<ContextError>() {
        let (message, hint) = diagnostic(context.source.as_ref());
        return (format!("{context}: {message}"), hint);
    }
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
        return issue_diagnostic(issue);
    }
    if let Some(account) = error.downcast_ref::<AccountError>() {
        return match account {
            AccountError::KeyRotationUncertain => (
                "Account key rotation has an unfinished or uncertain result.".into(),
                Some("Retain both keys and rerun account rotate-key to reconcile the saved rotation.".into()),
            ),
            AccountError::DeactivationUncertain => (
                "A previous deactivation request has an uncertain remote result.".into(),
                Some("Use account show --verify to attempt reconciliation. A 401 does not prove deactivation; consult your CA if it cannot confirm the result. The saved key is retained.".into()),
            ),
            AccountError::AccountNotActive => (
                "This account is deactivated, revoked, or has an unsupported CA status.".into(),
                Some("Choose another account name. ACME does not provide account reactivation.".into()),
            ),
            AccountError::KeyChangeUnavailable => (
                "This CA does not advertise account key rotation.".into(),
                None,
            ),
            AccountError::Transport(transport) => transport_diagnostic(transport),
            AccountError::TermsRequired(url) => (
                "The CA requires your agreement to its current terms.".into(),
                Some(format!(
                    "Review {} and rerun account register with --accept-terms; an existing account can delegate future updates with account update --auto-accept-new-terms.",
                    safe(url)
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
    if let Some(storage) = error.downcast_ref::<aster_acme::storage::account::AccountStoreError>() {
        return storage_message(&storage.message);
    }
    if let Some(storage) = error.downcast_ref::<StorageError>() {
        return (storage.to_string(),Some("Check the account name, selected CA and data directory. Switching requires an already registered account.".into()));
    }
    (error.to_string(), None)
}

fn issue_diagnostic(issue: &aster_acme::issuance::IssueError) -> (String, Option<String>) {
    use aster_acme::issuance::IssueError;
    match issue {
        IssueError::MaintenanceReadback { .. } => (issue.to_string(), Some("Inspect certificate storage and permissions. The latest saved renewal state is unavailable; other certificates are processed independently.".into())),
        IssueError::LeaseUnavailable(..) => (issue.to_string(), Some("Let the running operation finish, then check the saved certificate state and lock permissions. Lock contention does not advance renewal backoff.".into())),
        IssueError::AuthorizationFailed { status, problem } => self::problem::authorization_failed(status, problem.as_deref()),
        IssueError::DnsProvider(failure) => dns_provider_diagnostic(issue, failure),
        IssueError::DnsRouting(_) | IssueError::DnsPropagation(_) | IssueError::DnsRetryAt(_) => (issue.to_string(), Some("Inspect provider show <PROFILE> and its private TOML configuration, allowed DNS zones, resolver diagnostic and provider error code. Retain the saved request and publication receipts; resume the same request after correcting the cause or waiting for the saved retry time. For a terminal request use provider cleanup <PROFILE>.".into())),
        IssueError::Publication(_) if issue.to_string().contains("webroot") || issue.to_string().contains("HTTP") || issue.to_string().contains("isolated") => (issue.to_string(), Some("Inspect the webroot file state and the exact path reported in the error. Retain any isolated cleanup entry until ownership can be verified, then correct the webroot state and retry/resume.".into())),
        IssueError::Publication(_) => (issue.to_string(), Some("Check the selected validation implementation and its saved configuration. For DNS use provider show <PROFILE> and inspect private profile permissions; for HTTP/TLS listeners check the address, port forwarding and bind permissions. Retain saved publication material before retrying.".into())),
        IssueError::NameAlreadyExists(name)=>(issue.to_string(),Some(format!("Choose another --name, or inspect cert show '{}'. To continue its unfinished request use cert issue --resume '{}'.",name.as_str(),name.as_str()))),
        IssueError::RevocationInput(_)=>(issue.to_string(),Some("Inspect cert show <NAME>, the target certificate and explicit --sign-with selection. Certificate-key mode requires its matching private key, but no ACME account or CSR.".into())),
        IssueError::RevocationInterrupted=>(issue.to_string(),Some("Inspect cert show <NAME>. Retry cert revoke explicitly with the same certificate and reason, selecting --sign-with certificate-key when applicable; local files are retained.".into())),
        IssueError::RevocationUncertain(error)=>(format!("Certificate revocation outcome is unconfirmed. {}", transport_diagnostic(error).0),Some("Inspect cert show <NAME>. Rerun cert revoke <NAME> --yes with the same reason; select --sign-with certificate-key when applicable. Local files are retained.".into())),
        IssueError::Transport(error)=>transport_diagnostic(error),
        IssueError::Store(error)=>(format!("Could not access certificate storage: {}", error.message),Some("Check --data-dir, managed files and permissions. Retain any .removing marker and remaining files for inspection.".into())),
        IssueError::InvalidProfile(_) => (issue.to_string(), Some("Run account show --profiles to list the profiles this CA advertises, then pass the exact name with cert issue --profile or account update --profile. Let's Encrypt IP identifiers require the shortlived profile. No order was created.".into())),
        IssueError::PollLimit { .. } => (issue.to_string(), Some("Resume the saved request, or increase --max-polls. Retry-After and the overall --operation-timeout still apply; no new order is created.".into())),
        IssueError::InvalidOrder { problem } => self::problem::invalid_order(problem.as_deref()),
        IssueError::Expired=>(issue.to_string(),Some("Use cert show <CERTIFICATE> --verify to inspect the saved request. Start a new cert issue explicitly; local readiness cannot bypass CA expiry.".into())),
        IssueError::CreationUncertain=>(issue.to_string(),Some("Use cert list to inspect the retained request. Keep its key/CSR; a missing Location cannot be reconstructed safely and no new order will be created automatically.".into())),
        IssueError::Cancelled | IssueError::TimedOut | IssueError::MutationUncertain(_)=>(issue.to_string(),Some("Use cert issue --resume <CERTIFICATE>; for several requests add --operation <ID>. Saved validation files and records remain under your control.".into())),
        IssueError::RenewalAdmission(_) | IssueError::InvalidInput(_) | IssueError::Identifier(_) | IssueError::State(_) | IssueError::Challenge(_) | IssueError::Crypto(_)=>(issue.to_string(),Some("Inspect cert show <CERTIFICATE> for saved status and saved validation requirements. Retain the certificate key and CSR.".into())),
    }
}

fn dns_provider_diagnostic(
    issue: &aster_acme::issuance::IssueError,
    failure: &aster_acme_dns::ProviderFailure,
) -> (String, Option<String>) {
    let mut message = issue.to_string();
    if let aster_acme_dns::ProviderFailure::Provider(provider) = failure
        && let Some(code) = provider
            .provider_code
            .as_deref()
            .filter(|code| safe_provider_code(code))
        && !message.contains(code)
    {
        let _ = write!(message, " (provider code: {code})");
    }
    (
        message,
        Some("Inspect provider show <PROFILE> and its private TOML configuration and allowed DNS zones. The error includes the API request, HTTP status and safe provider code when available. Retain the saved request and publication receipts; resume the same request after correcting the cause or waiting for the saved retry time. For a terminal request use provider cleanup <PROFILE>.".into()),
    )
}

fn safe_provider_code(code: &str) -> bool {
    (1..=128).contains(&code.len())
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
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
    format: crate::common::session::Format,
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
    use crate::common::error::*;
    use aster_acme_protocol::problem::ProblemKind;

    #[test]
    fn contextual_errors_retain_cancellation_and_typed_recovery_hints() {
        let cancelled = ContextError {
            context: "the terms delegation was not saved".into(),
            source: Box::new(crate::common::terminal::Canceled),
        };
        let nested = ContextError {
            context: "Contacts were updated at the CA".into(),
            source: Box::new(cancelled),
        };
        assert_eq!(
            exit_status(&nested),
            crate::common::session::ExitStatus::Cancelled
        );
        let (message, _) = diagnostic(&nested);
        assert!(message.contains("Contacts were updated at the CA"));
        assert_eq!(message.matches("Canceled;").count(), 1);

        let failed = ContextError {
            context: "the terms delegation was not saved".into(),
            source: Box::new(AccountError::IdentityMismatch),
        };
        assert_eq!(
            exit_status(&failed),
            crate::common::session::ExitStatus::Failed
        );
        let json = render(&failed, crate::common::session::Format::plain(true)).unwrap();
        let json: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("does not match")
        );
        assert!(
            json["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("original account key")
        );
    }

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
    fn terms_required_hint_offers_explicit_consent_and_delegation() {
        let url = "https://ca.example/terms".to_owned();
        let (message, hint) = diagnostic(&AccountError::TermsRequired(url));
        assert!(message.contains("agreement"), "{message}");
        let hint = hint.unwrap();
        assert!(hint.contains("--accept-terms"), "{hint}");
        assert!(
            hint.contains("account update --auto-accept-new-terms"),
            "{hint}"
        );
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
    fn dns_provider_diagnostics_keep_safe_provider_codes_and_hide_raw_messages() {
        let error = aster_acme::issuance::IssueError::DnsProvider(
            aster_acme_dns::ProviderFailure::Provider(aster_acme_dns::ProviderError {
                code: aster_acme_dns::ProviderErrorCode::InvalidRequest,
                message: "DNS API rejected (API request: DescribeRecordList)".into(),
                side_effect: aster_acme_dns::SideEffect::None,
                retry_after_seconds: None,
                provider_code: Some("InvalidParameterValue.DomainId".into()),
            }),
        );
        let (message, hint) = diagnostic(&error);
        assert!(message.contains("InvalidParameterValue.DomainId"));
        assert!(hint.unwrap().contains("API request"));
        assert!(!message.contains("secret"));
        let unsafe_provider = aster_acme::issuance::IssueError::DnsProvider(
            aster_acme_dns::ProviderFailure::Provider(aster_acme_dns::ProviderError {
                code: aster_acme_dns::ProviderErrorCode::InvalidRequest,
                message: "DNS API rejected".into(),
                side_effect: aster_acme_dns::SideEffect::None,
                retry_after_seconds: None,
                provider_code: Some("bad code\nsecret".into()),
            }),
        );
        let (message, _) = diagnostic(&unsafe_provider);
        assert!(!message.contains("bad code"));
        assert!(!message.contains("secret"));
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

    #[test]
    fn cancellation_timeout_and_uncertain_mutations_share_recovery_guidance() {
        for error in [
            aster_acme::issuance::IssueError::Cancelled,
            aster_acme::issuance::IssueError::TimedOut,
            aster_acme::issuance::IssueError::MutationUncertain("finalize"),
        ] {
            let (message, hint) = diagnostic(&error);
            assert_ne!(message, "");
            let hint = hint.unwrap();
            assert!(hint.contains("cert issue --resume"));
            assert!(hint.contains("--operation"));
            assert!(hint.contains("Saved validation files"));
        }
    }
}
