//! One CLI mapping for typed ACME problems across account, issuance and revocation.
use aster_acme::transport::RetryAfter;
use aster_acme_protocol::problem::{Problem, ProblemKind};
use std::fmt::Write as _;

/// Format a problem embedded in an invalid resource, whose HTTP query succeeded.
/// Do not invent HTTP 400: the resource status and problem are separate evidence.
pub(crate) fn invalid_order(problem: Option<&Problem>) -> (String, Option<String>) {
    let Some(problem) = problem else {
        return ("CA order is invalid; the CA did not provide problem details.".into(), Some("Correct validation and start a new cert issue. The retained invalid order cannot be resumed.".into()));
    };
    let mut message = format!(
        "CA order is invalid: {} ({})",
        problem
            .detail
            .as_deref()
            .unwrap_or("no explanation provided"),
        problem.kind
    );
    for sub in problem.subproblems.iter().take(8) {
        let identifier = sub
            .extensions
            .get("identifier")
            .and_then(|value| value.get("value"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("identifier not provided");
        let _ = write!(
            message,
            "; {identifier}: {} ({})",
            sub.detail.as_deref().unwrap_or("no detail"),
            sub.kind
        );
    }
    (message, Some("Correct validation and start a new cert issue. This invalid order cannot be resumed; retain its files for inspection.".into()))
}

pub(super) fn authorization_failed(
    status: &aster_acme_core::protocol::AuthorizationStatus,
    problem: Option<&Problem>,
) -> (String, Option<String>) {
    let detail = problem.map_or_else(
        || "the CA did not provide problem details".into(),
        |problem| {
            let mut text = format!(
                "{} ({})",
                problem
                    .detail
                    .as_deref()
                    .unwrap_or("no explanation provided"),
                problem.kind
            );
            for sub in problem.subproblems.iter().take(8) {
                let _ = write!(
                    text,
                    "; {} ({})",
                    sub.detail.as_deref().unwrap_or("no detail"),
                    sub.kind
                );
            }
            text
        },
    );
    (format!("CA authorization/challenge failed ({status:?}): {detail}"), Some("Inspect cert show <CERTIFICATE> for the saved CA problem. Correct validation and start a new cert issue; this failed authorization cannot be resumed.".into()))
}

pub(super) fn diagnostic(
    status: u16,
    problem: &Problem,
    retry: Option<&RetryAfter>,
) -> (String, Option<String>) {
    let (message, mut hint) = match &problem.kind {
        ProblemKind::AccountDoesNotExist => super::missing_account(),
        kind => {
            let detail = problem
                .detail
                .as_deref()
                .unwrap_or("The CA did not provide an explanation.");
            (
                format!("CA request failed (HTTP {status}): {detail}"),
                Some(guidance(kind, problem.instance.as_deref(), retry)),
            )
        }
    };
    if !problem.subproblems.is_empty() {
        let details = problem
            .subproblems
            .iter()
            .take(8)
            .map(|sub| {
                let identifier = sub
                    .extensions
                    .get("identifier")
                    .and_then(|value| value.get("value"))
                    .and_then(serde_json::Value::as_str);
                let detail = sub.detail.as_deref().unwrap_or("no detail");
                match identifier {
                    Some(identifier) => format!("{identifier}: {detail} ({})", sub.kind),
                    None => format!("{detail} ({})", sub.kind),
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        let prefix = hint.get_or_insert_with(String::new);
        prefix.push_str(" Subproblems: ");
        prefix.push_str(&details);
        if problem.subproblems.len() > 8 {
            prefix.push_str("; additional subproblems are retained in the protocol response");
        }
    }
    (message, hint)
}

fn guidance(kind: &ProblemKind, instance: Option<&str>, retry: Option<&RetryAfter>) -> String {
    match kind {
        ProblemKind::AutoRenewalCanceled | ProblemKind::AutoRenewalExpired => "The CA reports that its short-term certificate auto-renewal order is unavailable. Inspect the saved CA problem and request a replacement certificate explicitly.".into(),
        ProblemKind::AutoRenewalCancellationInvalid | ProblemKind::AutoRenewalRevocationNotSupported => "This CA auto-renewal operation is not supported by this client. Inspect the saved CA problem and use the CA's documented workflow.".into(),
        ProblemKind::BadAttestationStatement => "The CA rejected the device attestation statement. This client does not implement the device-attestation extension; retain the problem and use a supported identifier/workflow.".into(),
        ProblemKind::UnknownDelegation => "The CA rejected the order's delegation configuration. Check the delegation names and the CA's RFC 9115 configuration.".into(),
        ProblemKind::OnionCaaRequired => "The CA requires in-band CAA data for this onion identifier. This client does not implement the RFC 9799 onion CSR extension.".into(),
        ProblemKind::AccountDoesNotExist=>"Recover or register the same account key before continuing.".into(),
        ProblemKind::BadCsr=>"This fixed CSR was rejected. Start a new cert issue with a CA-supported --key-type; resume does not replace the saved CSR or key.".into(),
        ProblemKind::BadNonce=>"The bounded nonce retry budget was exhausted or a usable replacement nonce was missing. Keep the saved operation; do not assume the mutation succeeded.".into(),
        ProblemKind::BadPublicKey|ProblemKind::BadSignatureAlgorithm=>"Check the CA's supported account signing algorithms and key requirements; retain the saved account identity.".into(),
        ProblemKind::BadRevocationReason=>"Choose a revocation --reason accepted by this CA, or omit it for a new request. An unconfirmed prior revocation must retain its original reason.".into(),
        ProblemKind::AlreadyReplaced=>"The predecessor already has another replacement order. Inspect the saved renewal and existing replacement; do not resume a rejected newOrder, silently drop replaces or create another order.".into(),
        ProblemKind::AlreadyRevoked=>"The CA reports that this certificate has already been revoked; this does not reactivate it or revoke its account.".into(),
        ProblemKind::RateLimited=>super::retry_hint(retry),
        ProblemKind::UserActionRequired=>format!("The CA requires user action: {}",instance.unwrap_or("see your CA account portal")),
        ProblemKind::ExternalAccountRequired=>"Supply the EAB credentials issued by this CA.".into(),
        ProblemKind::Caa=>"Check the domain's CAA records and the CA's issuer identity before starting another request.".into(),
        ProblemKind::Dns|ProblemKind::IncorrectResponse=>"Check the saved validation requirements and published records. Local DNS readiness does not replace CA validation.".into(),
        ProblemKind::Connection|ProblemKind::Tls=>"Check that the CA can reach the challenge endpoint with the expected protocol and TLS configuration.".into(),
        ProblemKind::InvalidContact|ProblemKind::UnsupportedContact=>"Check the account contact addresses and the CA's accepted contact URI schemes.".into(),
        ProblemKind::UnsupportedIdentifier|ProblemKind::RejectedIdentifier=>"Check the requested identifiers and this CA's issuance policy before creating another request.".into(),
        ProblemKind::OrderNotReady=>"Query the order using cert show --verify. An explicit orderNotReady rejection permits another finalize only after the CA reports ready; an uncertain finalize must not be replayed.".into(),
        ProblemKind::Unauthorized=>"Check the bound account and its authorization for this resource. An authorization error does not prove revocation or deactivation succeeded.".into(),
        ProblemKind::ServerInternal=>"The CA reported an internal failure. Retain the saved operation and inspect it before explicitly retrying; mutations are not automatically replayed.".into(),
        ProblemKind::Compound=>"Review the CA's per-identifier subproblems and retain the saved request.".into(),
        ProblemKind::Malformed=>"The CA rejected the request format. Retain the saved operation and report the CA detail; do not silently create a replacement request.".into(),
        ProblemKind::Unknown(uri)=>format!("CA problem type: {uri}. Retain the operation and consult the CA documentation; no retry policy is assumed for unknown extensions."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_problems_have_specific_guidance_and_unknown_values_keep_the_uri() {
        for (kind, expected) in [
            (ProblemKind::BadCsr, "--key-type"),
            (ProblemKind::BadRevocationReason, "--reason"),
            (ProblemKind::BadNonce, "nonce"),
            (ProblemKind::Unauthorized, "does not prove"),
            (
                ProblemKind::Unknown("https://ca.example/custom".into()),
                "https://ca.example/custom",
            ),
        ] {
            let p = Problem {
                kind,
                detail: Some("CA explanation".into()),
                instance: None,
                subproblems: vec![],
                extensions: serde_json::Map::new(),
            };
            let (message, hint) = diagnostic(400, &p, None);
            assert!(message.contains("CA explanation"));
            assert!(hint.unwrap().contains(expected));
        }
    }

    #[test]
    fn nested_identifier_problems_and_retry_information_are_retained() {
        let mut extensions = serde_json::Map::new();
        extensions.insert(
            "identifier".into(),
            serde_json::json!({"type":"dns","value":"example.com"}),
        );
        let p = Problem {
            kind: ProblemKind::Compound,
            detail: None,
            instance: None,
            subproblems: vec![Problem {
                kind: ProblemKind::Dns,
                detail: Some("missing TXT".into()),
                instance: None,
                subproblems: vec![],
                extensions,
            }],
            extensions: serde_json::Map::new(),
        };
        let (_, hint) = diagnostic(400, &p, None);
        let hint = hint.unwrap();
        assert!(hint.contains("example.com: missing TXT"));
        assert!(hint.contains("urn:ietf:params:acme:error:dns"));
        assert!(
            guidance(
                &ProblemKind::RateLimited,
                None,
                Some(&RetryAfter::Delay(std::time::Duration::from_secs(120)))
            )
            .contains("120 seconds")
        );
    }
}
