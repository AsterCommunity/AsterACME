//! Details report presentation; no side effects.

use crate::commands::cert::render::inspection::{RevocationSource, local_status_style};
use crate::commands::cert::render::materials::requirement_lines;
use crate::commands::cert::render::request_status;
use crate::common::output;
use crate::common::output::Style;
use crate::common::output::field;
use crate::common::time::timestamp;
use aster_acme::issuance::IssueRecord;
use aster_acme_core::revocation::RevocationState;

pub(in crate::commands::cert::render) fn request_lines(
    record: &IssueRecord,
    now: time::OffsetDateTime,
    color: bool,
) -> Vec<String> {
    let mut lines = vec![
        output::styled(&output::safe(record.name.as_str()), Style::BoldCyan, color),
        field("Request:", &record.operation_id, color),
        field("Key type:", record.key_algorithm.name(), color),
        field(
            "Validation:",
            &output::safe(&format!(
                "{} ({})",
                record.solver_id,
                record.challenge.name()
            )),
            color,
        ),
        field("Requested:", &timestamp(Some(record.created_at)), color),
        field(
            "Identifiers:",
            &record
                .identifiers
                .iter()
                .map(aster_acme::identifier::Identifier::value)
                .collect::<Vec<_>>()
                .join(", "),
            color,
        ),
        field(
            "Status:",
            &output::styled(
                request_status(record, now),
                local_status_style(record, now),
                color,
            ),
            color,
        ),
        field("CA:", &output::safe(record.directory.as_str()), color),
    ];
    if matches!(
        crate::commands::cert::validation::ValidationMethod::from_record(record),
        Ok(crate::commands::cert::validation::ValidationMethod::Webroot)
    ) && let Ok(config) = serde_json::from_value::<
        crate::commands::cert::validation::WebrootConfig,
    >(record.solver_config.clone())
    {
        lines.push(field(
            "Webroot:",
            &output::safe(&config.root.display().to_string()),
            color,
        ));
    }
    if let Some(problem) = record.failure_problem() {
        let message = format!(
            "{} ({})",
            problem
                .detail
                .as_deref()
                .unwrap_or("no explanation provided"),
            problem.kind
        );
        lines.push(field("CA problem:", &output::safe(&message), color));
    }
    if let Ok(config) = serde_json::from_value::<crate::commands::cert::validation::StandaloneConfig>(
        record.solver_config.clone(),
    ) {
        lines.push(field(
            "Listen address:",
            &config.listen_address.to_string(),
            color,
        ));
    }
    lines
}

pub(in crate::commands::cert::render) fn revocation_lines(
    record: &IssueRecord,
    color: bool,
) -> Vec<String> {
    let mut lines = Vec::new();
    let (revocation, style) = match record.revocation.state {
        RevocationState::NotRequested => ("not requested", Style::Plain),
        RevocationState::Pending => ("pending; CA outcome unconfirmed", Style::Yellow),
        RevocationState::Confirmed => ("confirmed revoked", Style::Red),
    };
    lines.push(field(
        "Revocation:",
        &output::styled(revocation, style, color),
        color,
    ));
    lines.push(field(
        "Revocation source:",
        RevocationSource::from(record.revocation.state).label(),
        color,
    ));
    if let Some(signer) = &record.revocation.signer {
        lines.push(field("Revocation signer:", signer.method().name(), color));
    }
    if let Some(at) = record.revocation.confirmed_at {
        lines.push(field("Revoked at:", &timestamp(Some(at)), color));
    }
    if let Some(at) = record.revocation.requested_at {
        lines.push(field("Revocation requested:", &timestamp(Some(at)), color));
    }
    if let Some(reason) = record.revocation.reason {
        lines.push(field("Revocation reason:", &reason.to_string(), color));
    }
    lines
}

pub(in crate::commands::cert::render) fn renewal_lines(
    record: &IssueRecord,
    now: time::OffsetDateTime,
    color: bool,
) -> Vec<String> {
    match record.revocation.state {
        RevocationState::Confirmed => {
            return vec![field(
                "Next renewal:",
                &output::styled("disabled (revoked)", Style::Red, color),
                color,
            )];
        }
        RevocationState::Pending => {
            return vec![field(
                "Next renewal:",
                &output::styled("suspended (revocation unconfirmed)", Style::Yellow, color),
                color,
            )];
        }
        RevocationState::NotRequested => {}
    }
    let Some(plan) = &record.renewal else {
        return Vec::new();
    };
    if !record.is_in_use {
        return vec![
            field("Next renewal:", "not scheduled (historical version)", color),
            field(
                "Previous renewal plan:",
                &timestamp(Some(plan.renew_at)),
                color,
            ),
        ];
    }
    let source = match plan.source {
        aster_acme::renewal::RenewalSource::Ari => "ARI",
        aster_acme::renewal::RenewalSource::Fallback => {
            "fallback (randomized before validity threshold)"
        }
    };
    let mut lines = vec![
        field(
            "Next renewal:",
            &output::styled(
                &timestamp(Some(plan.renew_at)),
                if plan.renew_at <= now {
                    Style::Yellow
                } else {
                    Style::Green
                },
                color,
            ),
            color,
        ),
        field("Renewal source:", source, color),
        field(
            "Renewal due:",
            if plan.renew_at <= now { "yes" } else { "no" },
            color,
        ),
    ];
    if let Some(window) = &plan.suggested_window {
        lines.push(field(
            "ARI window:",
            &format!(
                "{} — {}",
                timestamp(Some(window.start)),
                timestamp(Some(window.end))
            ),
            color,
        ));
    }
    if let Some(at) = plan.next_check_at {
        lines.push(field("ARI next check:", &timestamp(Some(at)), color));
    }
    if let Some(retry) = &record.renewal_retry {
        lines.extend(renewal_retry_lines(retry, color));
    }
    if plan.last_query_failed {
        lines.push(field(
            "ARI status:",
            &output::styled(
                "query incomplete or failed; saved renewal time retained",
                Style::Yellow,
                color,
            ),
            color,
        ));
    }
    if let Some(url) = &plan.explanation_url {
        lines.push(field("ARI explanation:", &output::safe(url), color));
    }
    lines
}

pub(in crate::commands::cert::render) fn renewal_retry_lines(
    retry: &aster_acme::issuance::RenewalRetryState,
    color: bool,
) -> Vec<String> {
    let mut lines = vec![field(
        "Renewal failures:",
        &retry.failures.to_string(),
        color,
    )];
    if let Some(reason) = &retry.blocked_reason {
        lines.push(field(
            "Automatic retry:",
            &format!("blocked: {reason}"),
            color,
        ));
    } else {
        let effective_retry = retry.retry_at.into_iter().chain(retry.ca_retry_at).max();
        lines.push(field(
            "Automatic retry:",
            &timestamp(effective_retry),
            color,
        ));
        if let Some(at) = retry.ca_retry_at {
            lines.push(field("CA Retry-After:", &timestamp(Some(at)), color));
        }
    }
    lines
}

pub(in crate::commands::cert::render) fn authorization_lines(
    record: &IssueRecord,
    color: bool,
) -> Vec<String> {
    use aster_acme_core::protocol::AuthorizationStatus;
    let mut lines = Vec::new();
    for authorization in &record.authorizations {
        let domain = if authorization.resource.wildcard {
            output::safe(&format!("*.{}", authorization.resource.identifier.value))
        } else {
            output::safe(&authorization.resource.identifier.value)
        };
        let style = match &authorization.resource.status {
            AuthorizationStatus::Valid => Style::Green,
            AuthorizationStatus::Pending => Style::Yellow,
            AuthorizationStatus::Expired
            | AuthorizationStatus::Deactivated
            | AuthorizationStatus::Revoked
            | AuthorizationStatus::Invalid
            | AuthorizationStatus::Unknown(_) => Style::Red,
        };
        let status = output::safe(&String::from(authorization.resource.status.clone()));
        lines.push(field(
            "Authorization:",
            &format!(
                "{domain} | {} | expires {}",
                output::styled(&status, style, color),
                timestamp(authorization.resource.expires)
            ),
            color,
        ));
        if let Some(requirement) = &authorization.validation_requirement {
            lines.extend(
                requirement_lines(std::slice::from_ref(requirement))
                    .into_iter()
                    .map(|line| format!("    Saved validation: {line}")),
            );
        }
    }
    lines
}
