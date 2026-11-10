//! Account presentation: distinguish local lifecycle from a fresh CA response.

use super::report::{AccountReport, LocalAccountReport, deactivation_label, state_label};
use crate::common::{
    error::CliResult,
    terminal::{colors, safe, styled},
};
use aster_acme_core::account::AccountRecordState;
use unicode_width::UnicodeWidthStr;

use std::io::{self, IsTerminal};

pub(crate) fn render(report: &AccountReport, structured: bool) -> CliResult<String> {
    if structured {
        return Ok(serde_json::to_string_pretty(&super::output::Output::from(
            report,
        ))?);
    }
    let color = colors(io::stdout().is_terminal());
    Ok(match report {
        AccountReport::Removed { name, .. } => {
            success(&format!("Removed local account {}.", safe(name)), color)
        }
        AccountReport::Local(local) => local_text(local, color),
        AccountReport::Remote {
            name,
            account,
            reused,
            action,
        } => {
            use super::report::RemoteAction;
            match action {
                RemoteAction::Show => remote_lines(name, account, true, color).join("\n"),
                RemoteAction::Register | RemoteAction::Recover => {
                    let verb = match action {
                        RemoteAction::Register if *reused => "Reused",
                        RemoteAction::Register if account.recovered => "Recovered existing",
                        RemoteAction::Register => "Registered",
                        RemoteAction::Recover => "Recovered",
                        RemoteAction::Show => "Verified",
                    };
                    let status = match &account.status {
                        aster_acme_core::protocol::AccountStatus::Valid => String::new(),
                        other => format!(" Status: {}.", safe(&String::from(other.clone()))),
                    };
                    success(&format!("{verb} account {}.{status}", safe(name)), color)
                }
            }
        }
        AccountReport::List {
            accounts,
            default,
            verification,
        } => list_text(accounts, default, verification.as_deref(), color),
        AccountReport::Deactivated { name, verified, .. } => success(
            &format!(
                "{} account {}.",
                if *verified {
                    "Deactivated"
                } else {
                    "Already deactivated"
                },
                safe(name)
            ),
            color,
        ),
        AccountReport::Switched { name, .. } => {
            success(&format!("Default account: {}.", safe(name)), color)
        }
    })
}

fn success(message: &str, color: bool) -> String {
    format!("{} {message}", styled("[OK]", "1;32", color))
}

/// Pad plain cells before applying ANSI so highlighting never changes alignment.
fn list_text(
    accounts: &[aster_acme_cli_storage::LocalAccount],
    default: &str,
    verification: Option<&[super::report::AccountVerification]>,
    color: bool,
) -> String {
    if accounts.is_empty() {
        return "No local accounts. Use account register to create one.".into();
    }
    let mut rows = vec![[
        // Two columns are reserved for the default marker in every data row.
        "  NAME".into(),
        "CA".into(),
        "LOCAL STATE".into(),
        if verification.is_some() {
            "CA STATUS".into()
        } else {
            "LAST CA STATUS".into()
        },
        "DEACTIVATION".into(),
        "REGISTERED AT (UTC)".into(),
        "STATUS AT (UTC)".into(),
        "LAST USED (UTC)".into(),
    ]];
    for account in accounts {
        let status = match verification
            .and_then(|results| results.iter().find(|result| result.name == account.name))
        {
            Some(result) => result
                .status
                .clone()
                .map_or_else(|| "verification failed".into(), String::from),
            None => account
                .last_status
                .clone()
                .map_or_else(|| "not observed".into(), String::from),
        };
        rows.push([
            format!(
                "{} {}",
                if account.name == default { "*" } else { " " },
                safe(&account.name)
            ),
            safe(account.directory.as_str()),
            state_label(account.state).into(),
            safe(&status),
            deactivation_label(account.deactivation).into(),
            timestamp(account.times.registered_at, true),
            timestamp(account.times.last_status_at, true),
            timestamp(account.times.last_used_at, true),
        ]);
    }
    let widths: [usize; 8] = std::array::from_fn(|column| {
        rows.iter()
            .map(|row| row[column].width())
            .max()
            .unwrap_or(0)
    });
    let mut lines = vec![if verification.is_some() {
        "Accounts (* = configured default; per-account verification below):".into()
    } else {
        "Local accounts (* = configured default; remote status not verified):".into()
    }];
    for (index, row) in rows.iter().enumerate() {
        let line = row
            .iter()
            .enumerate()
            .map(|(column, cell)| {
                if column == widths.len() - 1 {
                    cell.clone()
                } else {
                    format!(
                        "{cell}{}",
                        " ".repeat(widths[column].saturating_sub(cell.width()))
                    )
                }
            })
            .collect::<Vec<_>>()
            .join("  ");
        lines.push(styled(
            &line,
            if index == 0 { "1;36" } else { "1;32" },
            color && (index == 0 || accounts[index - 1].name == default),
        ));
    }
    if !accounts.iter().any(|account| account.name == default) {
        lines.push(format!(
            "Configured default '{}' has no local account record.",
            safe(default)
        ));
    }
    if let Some(results) = verification {
        for result in results {
            if let Some(error) = &result.error {
                lines.push(format!("  {}: {}", safe(&result.name), safe(error)));
            }
        }
    }
    lines.join("\n")
}

#[cfg(test)]
pub(super) fn json_value(report: &AccountReport) -> serde_json::Value {
    serde_json::to_value(super::output::Output::from(report)).unwrap()
}

fn remote_lines(
    name: &str,
    account: &aster_acme::account::AcmeAccount,
    verified: bool,
    color: bool,
) -> Vec<String> {
    let mut lines = vec![
        format!("{} Account {}", styled("[OK]", "1;32", color), safe(name)),
        format!("  CA: {}", safe(account.directory_url.as_str())),
        format!("  Account: {}", safe(account.account_url.as_str())),
        format!("  Status: {}", safe(&String::from(account.status.clone()))),
        format!(
            "  Source: {}",
            if verified {
                "CA response (verified)"
            } else {
                "saved local confirmation (not verified now)"
            }
        ),
    ];
    lines.extend(time_lines(account.times));
    for contact in &account.contacts {
        lines.push(format!("  Contact: {}", safe(contact)));
    }
    lines
}

/// Lists use minute precision for scanning; detail keeps UTC RFC 3339 precision.
fn timestamp(value: Option<time::OffsetDateTime>, compact: bool) -> String {
    let Some(value) = value else {
        return "—".into();
    };
    let value = value.to_offset(time::UtcOffset::UTC);
    if compact {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            value.year(),
            u8::from(value.month()),
            value.day(),
            value.hour(),
            value.minute()
        )
    } else {
        value
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "—".into())
    }
}

fn time_lines(times: aster_acme::account::AccountTimes) -> [String; 3] {
    [
        format!(
            "  First registered locally: {}",
            timestamp(times.registered_at, false)
        ),
        format!(
            "  Last CA status at: {}",
            timestamp(times.last_status_at, false)
        ),
        format!("  Last used at: {}", timestamp(times.last_used_at, false)),
    ]
}

fn local_state(local: &LocalAccountReport) -> &'static str {
    match local.record.as_ref().map(|record| record.state) {
        Some(AccountRecordState::Registered) => "registered",
        Some(AccountRecordState::RegistrationPending) => "registration_pending",
        None => "key_only",
    }
}

fn local_text(local: &LocalAccountReport, color: bool) -> String {
    let mut lines = vec![
        format!(
            "{} Account {} (local)",
            styled("[INFO]", "1;36", color),
            safe(&local.name)
        ),
        format!("  CA: {}", safe(local.directory.as_str())),
        format!("  Key thumbprint: {}", safe(&local.key_thumbprint)),
        format!("  Local state: {}", local_state(local)),
    ];
    if let Some(record) = &local.record {
        lines.push(format!("  Account ID: {}", safe(&record.account_id)));
        lines.extend(time_lines(record.times));
        if let Some(status) = &record.last_status {
            lines.push(format!(
                "  Last CA status: {}",
                safe(&String::from(status.clone()))
            ));
        }
        lines.push(format!(
            "  Deactivation: {}",
            deactivation_label(record.deactivation)
        ));
        if let Some(url) = &record.account_url {
            lines.push(format!("  Account: {}", safe(url.as_str())));
        }
        for contact in &record.contacts {
            lines.push(format!("  Configured contact: {}", safe(contact)));
        }
        match &record.server_contacts {
            Some(contacts) if contacts.is_empty() => {
                lines.push("  CA contacts: empty in the last response".into());
            }
            Some(contacts) => {
                for contact in contacts {
                    lines.push(format!("  Last CA contact: {}", safe(contact)));
                }
            }
            None => lines.push("  CA contacts: not provided".into()),
        }
        if let Some(url) = &record.accepted_terms_url {
            lines.push(format!("  Accepted terms: {}", safe(url.as_str())));
        }
    }
    lines.push("  Remote status: not verified. Use account show --verify to query the CA.".into());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_acme_cli_storage::LocalAccount;
    use aster_acme_core::account::DeactivationState;
    use aster_acme_protocol::url::AcmeUrl;

    #[test]
    fn time_columns_are_utc_unknown_values_are_explicit_and_json_keeps_precision() {
        let at = time::OffsetDateTime::from_unix_timestamp(0)
            .unwrap()
            .to_offset(time::UtcOffset::from_hms(8, 0, 0).unwrap());
        assert_eq!(timestamp(None, true), "—");
        assert_eq!(timestamp(Some(at), true), "1970-01-01 00:00");
        assert_eq!(timestamp(Some(at), false), "1970-01-01T00:00:00Z");
        let times = aster_acme::account::AccountTimes {
            registered_at: Some(at.to_offset(time::UtcOffset::UTC)),
            last_status_at: None,
            last_used_at: None,
        };
        let report = AccountReport::List {
            accounts: vec![LocalAccount {
                times,
                name: "work".into(),
                directory: AcmeUrl::new("https://ca.example/directory").unwrap(),
                usable: true,
                state: AccountRecordState::Registered,
                last_status: None,
                deactivation: DeactivationState::NotRequested,
            }],
            default: "work".into(),
            verification: None,
        };
        let value = json_value(&report);
        assert_eq!(
            value["accounts"][0]["registered_at"],
            "1970-01-01T00:00:00Z"
        );
        assert!(value["accounts"][0]["last_status_at"].is_null());
        let output = render(&report, false).unwrap();
        assert!(output.contains("REGISTERED AT (UTC)") && output.contains("LAST USED (UTC)"));
        assert!(output.contains("1970-01-01 00:00"));
    }

    #[test]
    fn list_aligns_marker_name_and_columns_before_applying_highlight() {
        let accounts = [
            LocalAccount {
                times: aster_acme::account::AccountTimes::default(),
                name: "default".into(),
                directory: AcmeUrl::new("https://ca.example/directory").unwrap(),
                usable: true,
                state: AccountRecordState::Registered,
                last_status: None,
                deactivation: DeactivationState::NotRequested,
            },
            LocalAccount {
                times: aster_acme::account::AccountTimes::default(),
                name: "new-account".into(),
                directory: AcmeUrl::new("https://longer-ca.example/directory").unwrap(),
                usable: false,
                state: AccountRecordState::RegistrationPending,
                last_status: None,
                deactivation: DeactivationState::NotRequested,
            },
        ];
        let text = list_text(&accounts, "default", None, false);
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines[1].find("NAME"), Some(2));
        assert_eq!(lines[2].find("default"), Some(2));
        assert_eq!(lines[3].find("new-account"), Some(2));
        let ca_column = lines[1].find("CA").unwrap();
        assert_eq!(lines[2].find("https://"), Some(ca_column));
        assert_eq!(lines[3].find("https://"), Some(ca_column));
        assert!(!text.contains('\x1b'));
        let highlighted = list_text(&accounts, "default", None, true);
        assert!(highlighted.contains("\x1b[1;32m* default"));
        assert!(!highlighted.contains("\x1b[1;32m  new-account"));
    }

    #[test]
    fn write_commands_summarize_success_while_show_retains_details() {
        use super::super::report::RemoteAction;
        use aster_acme::account::AcmeAccount;
        use aster_acme_core::protocol::AccountStatus;
        let account = AcmeAccount {
            times: aster_acme::account::AccountTimes::default(),
            account_id: "local-id".into(),
            directory_url: AcmeUrl::new("https://ca.example/directory").unwrap(),
            account_url: AcmeUrl::new("https://ca.example/account/1").unwrap(),
            status: AccountStatus::Valid,
            contacts: vec![],
            recovered: false,
        };
        for (action, expected) in [
            (RemoteAction::Register, "Registered"),
            (RemoteAction::Recover, "Recovered"),
        ] {
            let report = AccountReport::Remote {
                name: "work".into(),
                account: account.clone(),
                reused: false,
                action,
            };
            let text = render(&report, false).unwrap();
            assert!(text.contains(expected));
            assert_eq!(text.lines().count(), 1);
            assert!(!text.contains("https://"));
            assert_eq!(
                json_value(&report)["account_url"],
                "https://ca.example/account/1"
            );
        }
        let report = AccountReport::Remote {
            name: "work".into(),
            account: account.clone(),
            reused: true,
            action: RemoteAction::Register,
        };
        assert!(render(&report, false).unwrap().contains("Reused account"));
        let report = AccountReport::Remote {
            name: "work".into(),
            account: account.clone(),
            reused: false,
            action: RemoteAction::Show,
        };
        assert!(
            render(&report, false)
                .unwrap()
                .contains("https://ca.example/account/1")
        );
        let mut inactive = account.clone();
        inactive.status = AccountStatus::Deactivated;
        let report = AccountReport::Remote {
            name: "work".into(),
            account: inactive,
            reused: false,
            action: RemoteAction::Recover,
        };
        assert!(
            render(&report, false)
                .unwrap()
                .contains("Status: deactivated")
        );
        let report = AccountReport::Deactivated {
            name: "work".into(),
            account,
            verified: true,
        };
        assert_eq!(render(&report, false).unwrap().lines().count(), 1);
        assert!(
            render(&report, false)
                .unwrap()
                .contains("Deactivated account work.")
        );
    }
}
