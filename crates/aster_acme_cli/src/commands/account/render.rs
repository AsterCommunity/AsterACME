//! Account presentation: distinguish local lifecycle from a fresh CA response.

use super::report::{AccountReport, LocalAccountReport, deactivation_label, state_label};
use crate::common::output::Style;
use crate::common::time::timestamp;
use crate::common::{
    error::CliResult,
    output::{field, safe, styled},
};
use aster_acme_core::account::AccountRecordState;

use crate::common::session::Format;

pub(crate) fn render(report: &AccountReport, format: Format) -> CliResult<String> {
    if format.json {
        return Ok(serde_json::to_string_pretty(&super::output::Output::from(
            report,
        ))?);
    }
    let color = format.color;
    Ok(match report {
        AccountReport::KeyRotated { name, .. } => {
            success(&format!("Rotated key for account {}.", safe(name)), color)
        }
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
                RemoteAction::Register | RemoteAction::Recover | RemoteAction::UpdateContact => {
                    let verb = match action {
                        RemoteAction::Register if *reused => "Reused",
                        RemoteAction::Register if account.recovered => "Recovered existing",
                        RemoteAction::Register => "Registered",
                        RemoteAction::Recover => "Recovered",
                        RemoteAction::UpdateContact => "Updated contacts for",
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
    format!(
        "{} {message}",
        crate::common::output::MessageKind::Success.badge(color)
    )
}

fn rotation_label(phase: aster_acme_core::account::KeyRotationPhase) -> &'static str {
    match phase {
        aster_acme_core::account::KeyRotationPhase::Pending => "key rotation pending",
        aster_acme_core::account::KeyRotationPhase::Confirmed => "key commit pending",
    }
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
        "KEY TYPE".into(),
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
            account.key_algorithm.name().into(),
            match &account.key_rotation {
                Some(rotation) => rotation_label(rotation.phase).into(),
                None => state_label(account.state).into(),
            },
            safe(&status),
            deactivation_label(account.deactivation).into(),
            timestamp(account.times.registered_at),
            timestamp(account.times.last_status_at),
            timestamp(account.times.last_used_at),
        ]);
    }
    let mut lines = vec![if verification.is_some() {
        "Accounts (* = configured default; per-account verification below):".into()
    } else {
        "Local accounts (* = configured default; remote status not verified):".into()
    }];
    for (index, line) in crate::common::table::align(&rows, None)
        .into_iter()
        .enumerate()
    {
        lines.push(styled(
            &line,
            if index == 0 {
                Style::BoldCyan
            } else {
                Style::BoldGreen
            },
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

fn time_lines(times: aster_acme::account::AccountTimes, color: bool) -> [String; 3] {
    [
        field(
            "First registered locally:",
            &timestamp(times.registered_at),
            color,
        ),
        field(
            "Last CA status at:",
            &timestamp(times.last_status_at),
            color,
        ),
        field("Last used at:", &timestamp(times.last_used_at), color),
    ]
}

fn local_state(local: &LocalAccountReport, color: bool) -> String {
    let (label, style) = match local.record.as_ref().map(|record| record.state) {
        Some(AccountRecordState::Registered) => ("registered", Style::Green),
        Some(AccountRecordState::RegistrationPending) => ("registration_pending", Style::Yellow),
        None => ("key_only", Style::Yellow),
    };
    styled(label, style, color)
}

fn local_text(local: &LocalAccountReport, color: bool) -> String {
    let mut lines = vec![
        format!(
            "{} Account {}",
            crate::common::output::MessageKind::Info.badge(color),
            safe(&local.name)
        ),
        field("CA:", &safe(local.directory.as_str()), color),
        field(
            "Key type:",
            local
                .record
                .as_ref()
                .map_or("unknown", |record| record.key_algorithm.name()),
            color,
        ),
        field("Key thumbprint:", &safe(&local.key_thumbprint), color),
        field("Local state:", &local_state(local, color), color),
    ];
    if let Some(record) = &local.record {
        if let Some(user_agent) = &record.user_agent {
            lines.push(field("User-Agent:", &safe(user_agent), color));
        }
        if let Some(rotation) = &record.key_rotation {
            lines.push(field(
                "Key rotation:",
                &styled(
                    &format!(
                        "{}. Use account rotate-key to resume.",
                        rotation_label(rotation.phase)
                    ),
                    Style::Yellow,
                    color,
                ),
                color,
            ));
        }
        lines.push(field("Account ID:", &safe(&record.account_id), color));
        lines.extend(time_lines(record.times, color));
        if let Some(status) = &record.last_status {
            lines.push(field(
                "Last CA status:",
                &account_status(status, color),
                color,
            ));
        }
        let deactivation_style = match record.deactivation {
            aster_acme_core::account::DeactivationState::NotRequested => Style::Green,
            aster_acme_core::account::DeactivationState::Pending => Style::Yellow,
            aster_acme_core::account::DeactivationState::Confirmed => Style::Red,
        };
        lines.push(field(
            "Deactivation:",
            &styled(
                deactivation_label(record.deactivation),
                deactivation_style,
                color,
            ),
            color,
        ));
        if let Some(url) = &record.account_url {
            lines.push(field("Account:", &safe(url.as_str()), color));
        }
        for contact in &record.contacts {
            lines.push(field("Configured contact:", &safe(contact), color));
        }
        match &record.server_contacts {
            Some(contacts) if contacts.is_empty() => {
                lines.push(field("CA contacts:", "empty in the last response", color));
            }
            Some(contacts) => {
                for contact in contacts {
                    lines.push(field("Last CA contact:", &safe(contact), color));
                }
            }
            None => lines.push(field("CA contacts:", "not provided", color)),
        }
        if let Some(url) = &record.accepted_terms_url {
            lines.push(field("Accepted terms:", &safe(url.as_str()), color));
        }
    }
    let (query, query_style) = if local.verified {
        ("account refreshed", Style::Green)
    } else {
        ("not performed (local data only)", Style::Yellow)
    };
    lines.push(field(
        "CA query:",
        &styled(query, query_style, color),
        color,
    ));
    lines.join("\n")
}

fn account_status(status: &aster_acme_core::protocol::AccountStatus, color: bool) -> String {
    use aster_acme_core::protocol::AccountStatus;
    let style = match status {
        AccountStatus::Valid => Style::Green,
        AccountStatus::Deactivated | AccountStatus::Revoked | AccountStatus::Unknown(_) => {
            Style::Red
        }
    };
    styled(&safe(&String::from(status.clone())), style, color)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use aster_acme_cli_storage::LocalAccount;
    use aster_acme_core::account::DeactivationState;
    use aster_acme_protocol::url::AcmeUrl;

    pub(in crate::commands::account) fn json_value(report: &AccountReport) -> serde_json::Value {
        serde_json::to_value(super::super::output::Output::from(report)).unwrap()
    }

    #[test]
    fn time_columns_are_utc_unknown_values_are_explicit_and_json_keeps_precision() {
        let at = time::OffsetDateTime::from_unix_timestamp(0)
            .unwrap()
            .to_offset(time::UtcOffset::from_hms(8, 0, 0).unwrap());
        assert_eq!(timestamp(None), "—");
        assert_eq!(timestamp(Some(at)), "1970-01-01 00:00:00 UTC");
        assert_eq!(timestamp(Some(at)), "1970-01-01 00:00:00 UTC");
        let times = aster_acme::account::AccountTimes {
            registered_at: Some(at.to_offset(time::UtcOffset::UTC)),
            last_status_at: None,
            last_used_at: None,
        };
        let report = AccountReport::List {
            accounts: vec![LocalAccount {
                key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
                key_rotation: None,
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
        let output = render(&report, crate::common::session::Format::plain(false)).unwrap();
        assert!(output.contains("REGISTERED AT (UTC)") && output.contains("LAST USED (UTC)"));
        assert!(output.contains("1970-01-01 00:00"));
    }

    #[test]
    fn list_aligns_marker_name_and_columns_before_applying_highlight() {
        let accounts = [
            LocalAccount {
                key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
                key_rotation: None,
                times: aster_acme::account::AccountTimes::default(),
                name: "default".into(),
                directory: AcmeUrl::new("https://ca.example/directory").unwrap(),
                usable: true,
                state: AccountRecordState::Registered,
                last_status: None,
                deactivation: DeactivationState::NotRequested,
            },
            LocalAccount {
                key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
                key_rotation: None,
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
            key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
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
            let text = render(&report, crate::common::session::Format::plain(false)).unwrap();
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
        assert!(
            render(&report, crate::common::session::Format::plain(false))
                .unwrap()
                .contains("Reused account")
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
            render(&report, crate::common::session::Format::plain(false))
                .unwrap()
                .contains("Status: deactivated")
        );
        let report = AccountReport::Deactivated {
            name: "work".into(),
            account,
            verified: true,
        };
        assert_eq!(
            render(&report, crate::common::session::Format::plain(false))
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert!(
            render(&report, crate::common::session::Format::plain(false))
                .unwrap()
                .contains("Deactivated account work.")
        );
    }

    #[test]
    fn account_details_use_shared_field_colors_and_explicit_unverified_state() {
        let account = LocalAccountReport {
            verified: false,
            name: "default".into(),
            directory: aster_acme_protocol::url::AcmeUrl::new("https://ca.example/directory")
                .unwrap(),
            key_thumbprint: "public-key".into(),
            record: None,
        };
        let colored = local_text(&account, true);
        assert!(colored.contains("\x1b[36mCA:\x1b[0m"));
        assert!(colored.contains("\x1b[33mkey_only\x1b[0m"));
        assert!(colored.contains("\x1b[33mnot performed"));
        let plain = local_text(&account, false);
        assert!(!plain.contains('\x1b'));
        assert!(
            plain
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains("CA: https://ca.example/directory")
        );
        assert!(
            account_status(&aster_acme_core::protocol::AccountStatus::Valid, true)
                .contains("\x1b[32mvalid")
        );
        assert!(
            account_status(&aster_acme_core::protocol::AccountStatus::Deactivated, true)
                .contains("\x1b[31mdeactivated")
        );
    }

    #[test]
    fn verified_and_offline_account_details_keep_identical_fields_and_explicit_source() {
        use aster_acme::account::{AccountRecord, AccountTimes};
        use aster_acme_core::{account::DeactivationState, protocol::AccountStatus};
        let directory =
            aster_acme_protocol::url::AcmeUrl::new("https://ca.example/directory").unwrap();
        let account = AccountRecord {
            key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
            user_agent: Some("test/1".into()),
            times: AccountTimes::default(),
            account_id: "id".into(),
            directory_url: directory.clone(),
            key_thumbprint: "thumbprint".into(),
            account_url: Some(
                aster_acme_protocol::url::AcmeUrl::new("https://ca.example/account").unwrap(),
            ),
            contacts: vec!["mailto:a@example.com".into()],
            server_contacts: None,
            last_status: Some(AccountStatus::Valid),
            deactivation: DeactivationState::NotRequested,
            key_rotation: None,
            accepted_terms_url: None,
            state: AccountRecordState::Registered,
        };
        let mut labels = Vec::new();
        for verified in [false, true] {
            let local = LocalAccountReport {
                verified,
                name: "default".into(),
                directory: directory.clone(),
                key_thumbprint: "thumbprint".into(),
                record: Some(account.clone()),
            };
            let text = local_text(&local, false);
            labels.push(
                text.lines()
                    .filter_map(|line| line.split_once(": ").map(|(label, _)| label.to_owned()))
                    .collect::<Vec<_>>(),
            );
            assert!(
                text.split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .contains(if verified {
                        "CA query: account refreshed"
                    } else {
                        "CA query: not performed (local data only)"
                    })
            );
            let report = AccountReport::Local(local);
            let json = json_value(&report);
            assert_eq!(json["ca_query"]["account_refreshed"], verified);
            assert!(json.get("verified").is_none());
            assert!(json.get("source").is_none());
            assert_eq!(json["key_thumbprint"], "thumbprint");
            assert_eq!(json["contacts"][0], "mailto:a@example.com");
        }
        assert_eq!(labels[0], labels[1]);
    }
}
