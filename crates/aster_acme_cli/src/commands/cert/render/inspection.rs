//! Inspection report presentation; no side effects.

use crate::commands::cert::render::details::{
    authorization_lines, renewal_lines, request_lines, revocation_lines,
};
use crate::commands::cert::render::{domain_summary, request_status};
use crate::common::error::CliResult;
use crate::common::output;
use crate::common::output::Style;
use crate::common::output::field;
use crate::common::session::Format;
use crate::common::time::timestamp;
use aster_acme::issuance::IssueRecord;
use aster_acme_core::revocation::RevocationState;
use serde::Serialize;

#[derive(Serialize)]
pub(in crate::commands::cert::render) struct OrderView<'a> {
    #[serde(flatten)]
    operation: &'a IssueRecord,
    expired_locally: bool,
    renewal_due: bool,
    in_use: bool,
    ca_query: CaQuery,
    revocation_source: RevocationSource,
}

/// These observations describe this invocation, not the entire saved certificate.
#[derive(Serialize)]
pub(in crate::commands::cert::render) struct CaQuery {
    order_refreshed: bool,
    authorizations_refreshed: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::commands::cert::render) enum RevocationSource {
    LocalState,
    SavedCaResponse,
}

impl From<RevocationState> for RevocationSource {
    fn from(state: RevocationState) -> Self {
        match state {
            RevocationState::NotRequested | RevocationState::Pending => Self::LocalState,
            RevocationState::Confirmed => Self::SavedCaResponse,
        }
    }
}

impl RevocationSource {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::LocalState => "local state",
            Self::SavedCaResponse => "saved CA response",
        }
    }
}

pub(in crate::commands::cert) fn list(
    records: &[IssueRecord],
    format: Format,
) -> CliResult<String> {
    if format.json {
        return show(records, format, false, DetailView::InUse);
    }
    if records.is_empty() {
        return Ok("No saved certificate requests.".into());
    }
    let now = time::OffsetDateTime::now_utc();
    let color = format.color;
    let mut rows = vec![[
        "NAME".into(),
        "IDENTIFIERS".into(),
        "KEY TYPE".into(),
        "REQUESTED (UTC)".into(),
        "STATUS".into(),
        "ORDER STATUS".into(),
        "CERT EXPIRES (UTC)".into(),
        "NEXT RENEWAL (UTC)".into(),
        "ACCOUNT".into(),
    ]];
    for record in records {
        rows.push([
            output::safe(record.name.as_str()),
            domain_summary(record),
            record.key_algorithm.name().into(),
            timestamp(Some(record.created_at)),
            request_status(record, now).into(),
            record.order.as_ref().map_or_else(
                || "not observed".into(),
                |order| String::from(order.status.clone()),
            ),
            timestamp(record.certificate_not_after()),
            timestamp(
                record
                    .renewal
                    .as_ref()
                    .filter(|_| {
                        record.is_in_use
                            && matches!(record.revocation.state, RevocationState::NotRequested)
                    })
                    .map(|plan| plan.renew_at),
            ),
            output::safe(&record.account_name),
        ]);
    }
    let mut lines =
        vec!["Local certificates (CA order status from saved observations; times in UTC):".into()];
    lines.extend(crate::common::table::listing(
        &rows,
        color,
        |row, column| match column {
            4 => local_status_style(&records[row], now),
            5 => order_status_style(records[row].order.as_ref().map(|order| &order.status)),
            _ => Style::Plain,
        },
    ));
    lines.push(output::tips(
        "Use cert show <NAME> for request IDs, CA details and saved validation requirements.",
        color,
    ));
    Ok(lines.join("\n"))
}

pub(in crate::commands::cert::render) fn local_status_style(
    record: &IssueRecord,
    now: time::OffsetDateTime,
) -> Style {
    match record.revocation.state {
        RevocationState::Confirmed => Style::Red,
        RevocationState::Pending => Style::Yellow,
        RevocationState::NotRequested
            if record.finalize_rejection.is_some()
                || record.creation_failure.is_some()
                || record.authorization_failure().is_some() =>
        {
            Style::Red
        }
        RevocationState::NotRequested if record.expired(now) || record.unfinished() => {
            Style::Yellow
        }
        RevocationState::NotRequested => Style::Green,
    }
}

pub(in crate::commands::cert::render) fn order_status_style(
    status: Option<&aster_acme_core::protocol::OrderStatus>,
) -> Style {
    use aster_acme_core::protocol::OrderStatus;
    match status {
        Some(OrderStatus::Valid) => Style::Green,
        Some(OrderStatus::Invalid | OrderStatus::Unknown(_)) => Style::Red,
        Some(OrderStatus::Ready) => Style::Blue,
        Some(OrderStatus::Pending | OrderStatus::Processing) | None => Style::Yellow,
    }
}

/// Human detail scope; `in_use` is shown only when choosing an explicit version.
#[derive(Clone, Copy)]
pub(crate) enum DetailView {
    InUse,
    Version,
}

pub(in crate::commands::cert) fn show(
    records: &[IssueRecord],
    format: Format,
    verified: bool,
    view: DetailView,
) -> CliResult<String> {
    let now = time::OffsetDateTime::now_utc();
    if format.json {
        let views = records
            .iter()
            .map(|operation| OrderView {
                operation,
                expired_locally: operation.expired(now),
                renewal_due: operation.is_in_use
                    && matches!(operation.revocation.state, RevocationState::NotRequested)
                    && operation
                        .renewal
                        .as_ref()
                        .is_some_and(|plan| plan.renew_at <= now),
                in_use: operation.is_in_use,
                ca_query: CaQuery {
                    order_refreshed: verified,
                    authorizations_refreshed: verified,
                },
                revocation_source: operation.revocation.state.into(),
            })
            .collect::<Vec<_>>();
        return Ok(serde_json::to_string_pretty(&views)?);
    }
    if records.is_empty() {
        return Ok("No saved certificate requests.".into());
    }
    let color = format.color;
    Ok(records
        .iter()
        .map(|record| {
            let mut text = show_text(record, now, color, verified);
            if let DetailView::Version = view {
                text.push('\n');
                text.push_str(&field(
                    "In use:",
                    if record.is_in_use { "yes" } else { "no" },
                    color,
                ));
            }
            text
        })
        .collect::<Vec<_>>()
        .join("\n\n"))
}

pub(in crate::commands::cert::render) fn show_text(
    record: &IssueRecord,
    now: time::OffsetDateTime,
    color: bool,
    verified: bool,
) -> String {
    let expired = record.expired(now);
    let mut lines = request_lines(record, now, color);
    let (status, status_style) = record.order.as_ref().map_or_else(
        || ("not observed".into(), Style::Yellow),
        |order| {
            let style = order_status_style(Some(&order.status));
            (String::from(order.status.clone()), style)
        },
    );
    lines.push(field(
        "Order status:",
        &output::styled(&output::safe(&status), status_style, color),
        color,
    ));
    let deadline_text = timestamp(record.order.as_ref().and_then(|order| order.expires));
    lines.push(field(
        "Order expires:",
        &output::styled(&deadline_text, Style::Yellow, color && expired),
        color,
    ));
    lines.extend(authorization_lines(record, color));
    if let Some(failure) = &record.creation_failure {
        lines.push(field("newOrder HTTP:", &failure.status.to_string(), color));
        lines.push(field("Retry after:", &timestamp(failure.retry_at), color));
    }
    if let Some(problem) = &record.finalize_rejection {
        lines.push(field(
            "CSR rejection:",
            &output::safe(&problem.problem.as_ref().map_or_else(
                || format!("HTTP {}", problem.status),
                |problem| {
                    problem
                        .detail
                        .clone()
                        .unwrap_or_else(|| problem.kind.to_string())
                },
            )),
            color,
        ));
    }
    if let Some(order) = &record.order
        && let Some(problem) = &order.error
    {
        lines.push(field(
            "CA error:",
            &output::styled(
                &output::safe(
                    &problem
                        .detail
                        .clone()
                        .unwrap_or_else(|| problem.kind.to_string()),
                ),
                Style::Red,
                color,
            ),
            color,
        ));
    }
    if let Some(at) = record.certificate_not_after() {
        let style = if at <= now { Style::Red } else { Style::Green };
        lines.push(field(
            "Certificate expires:",
            &output::styled(&timestamp(Some(at)), style, color),
            color,
        ));
    }
    lines.extend(revocation_lines(record, color));
    lines.extend(renewal_lines(record, now, color));
    lines.push(field(
        "CA query:",
        &output::styled(
            if verified {
                "order and authorizations refreshed"
            } else {
                "not performed (local data only)"
            },
            if verified {
                Style::Green
            } else {
                Style::Yellow
            },
            color,
        ),
        color,
    ));
    lines.join("\n")
}

// Immutable request identity and local progress, shared by offline and refreshed details.
