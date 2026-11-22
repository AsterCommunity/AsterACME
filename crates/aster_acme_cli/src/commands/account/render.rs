//! Account presentation: distinguish local lifecycle from a fresh CA response.

use crate::commands::account::report::{
    AccountReport, LocalAccountReport, deactivation_label, state_label,
};
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
        return Ok(serde_json::to_string_pretty(
            &crate::commands::account::output::Output::from(report),
        )?);
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
            auto_accepted_terms,
        } => {
            use crate::commands::account::report::RemoteAction;
            match action {
                RemoteAction::Register | RemoteAction::Recover => {
                    let verb = match action {
                        RemoteAction::Register if *reused => "Reused",
                        RemoteAction::Register if account.recovered => "Recovered existing",
                        RemoteAction::Register => "Registered",
                        RemoteAction::Recover => "Recovered",
                    };
                    let status = match &account.status {
                        aster_acme_core::protocol::AccountStatus::Valid => String::new(),
                        other => format!(" Status: {}.", safe(&String::from(other.clone()))),
                    };
                    let message = if *auto_accepted_terms {
                        format!(
                            "{verb} account {}.{status} Automatically accepted the updated CA terms and saved future-update consent.",
                            safe(name)
                        )
                    } else {
                        format!("{verb} account {}.{status}", safe(name))
                    };
                    success(&message, color)
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
        AccountReport::Profiles {
            directory,
            profiles,
        } => profiles_text(directory, profiles.as_ref()),
        AccountReport::Updated(outcome) => {
            let mut sections: Vec<String> = Vec::new();
            if let Some(contacts) = &outcome.contacts {
                sections.push(contacts_text(&outcome.name, &contacts.account, color));
            }
            if let Some(profile) = &outcome.profile {
                sections.push(profile_preference_text(
                    &outcome.name,
                    profile.previous.as_ref(),
                    profile.current.as_ref(),
                    color,
                ));
            }
            if let Some(terms) = &outcome.terms {
                sections.push(terms_delegation_text(
                    &outcome.name,
                    DelegationTransition::from_states(terms.previous, terms.current),
                    terms.accepted_terms_url.as_ref(),
                    terms.advertised_terms_url.as_ref(),
                    terms.directory_checked,
                    color,
                ));
            }
            sections.join("\n")
        }
    })
}

/// CA-confirmed contacts text: the echoed account state is the evidence.
fn contacts_text(name: &str, account: &aster_acme::account::AcmeAccount, color: bool) -> String {
    let status = match &account.status {
        aster_acme_core::protocol::AccountStatus::Valid => String::new(),
        other => format!(" Status: {}.", safe(&String::from(other.clone()))),
    };
    success(
        &format!("Updated contacts for account {}.{status}", safe(name)),
        color,
    )
}

/// Draft-ietf-acme-profiles listing; an empty advertisement states the CA default.
fn profiles_text(
    directory: &aster_acme_protocol::url::AcmeUrl,
    profiles: Option<&std::collections::BTreeMap<String, String>>,
) -> String {
    let Some(map) = profiles.filter(|map| !map.is_empty()) else {
        return format!(
            "Certificate profiles: the CA at {} advertises none; new orders use the CA default.",
            safe(directory.as_str())
        );
    };
    let mut text = String::from("Certificate profiles advertised by ");
    text.push_str(&safe(directory.as_str()));
    text.push(':');
    for (name, description) in map {
        let (name, description) = (name.as_str(), description.as_str());
        text.push_str("\n  ");
        text.push_str(&safe(name));
        if !description.is_empty() {
            text.push_str(" — ");
            text.push_str(&safe(description));
        }
    }
    text.push_str("\nSet an account default with account update --profile, or select per issue with cert issue --profile.");
    text
}

/// Preference change text; cleared and set states share one honest sentence.
fn profile_preference_text(
    name: &str,
    previous: Option<&String>,
    current: Option<&String>,
    color: bool,
) -> String {
    let describe = |value: Option<&String>| match value {
        Some(profile) => safe(profile),
        None => "(none; the CA default applies)".to_owned(),
    };
    if current.is_none() {
        success(
            &format!(
                "Cleared account {} default profile (was {}).",
                safe(name),
                describe(previous)
            ),
            color,
        )
    } else {
        success(
            &format!(
                "Account {} default profile: {} (was {}). Explicit cert issue --profile still wins; saved certificates keep their own selection.",
                safe(name),
                describe(current),
                describe(previous)
            ),
            color,
        )
    }
}

/// Delegation state transition being reported; each state has its own wording.
#[derive(Clone, Copy)]
enum DelegationTransition {
    Enabled,
    AlreadyEnabled,
    Disabled,
    AlreadyDisabled,
}

impl DelegationTransition {
    fn from_states(previous: bool, current: bool) -> Self {
        match (previous, current) {
            (false, true) => Self::Enabled,
            (true, true) => Self::AlreadyEnabled,
            (true, false) => Self::Disabled,
            (false, false) => Self::AlreadyDisabled,
        }
    }
}

/// Terms delegation text: consent is stored locally, so it never claims a CA sync.
fn terms_delegation_text(
    name: &str,
    transition: DelegationTransition,
    accepted: Option<&String>,
    advertised: Option<&String>,
    directory_checked: bool,
    color: bool,
) -> String {
    let accepted = accepted.map_or_else(|| "(none saved)".to_owned(), |url| safe(url));
    let notice = if directory_checked && advertised.is_none() {
        " The CA publishes no terms today; no new URL was accepted and any saved URL is retained."
    } else {
        ""
    };
    let message = match transition {
        DelegationTransition::Enabled => format!(
            "Account {} now accepts future CA terms updates automatically; accepted terms URL: {}. This is local consent only; the terms delegation itself sent no CA account request.{notice}",
            safe(name),
            accepted
        ),
        DelegationTransition::AlreadyEnabled => format!(
            "Account {} already accepts future CA terms updates automatically; accepted terms URL: {}.{notice}",
            safe(name),
            accepted
        ),
        DelegationTransition::Disabled => format!(
            "Account {} no longer accepts future CA terms updates automatically. The saved accepted terms URL ({}) is retained; future changes require explicit consent.",
            safe(name),
            accepted
        ),
        DelegationTransition::AlreadyDisabled => format!(
            "Account {} was already set to not accept future CA terms updates automatically.",
            safe(name)
        ),
    };
    success(&message, color)
}

fn success(message: &str, color: bool) -> String {
    format!(
        "{} {message}",
        crate::common::output::MessageKind::Success.badge(color)
    )
}

fn rotation_label(phase: aster_acme_core::account::KeyRotationPhase) -> &'static str {
    match phase {
        aster_acme_core::account::KeyRotationPhase::Prepared => "key rotation prepared",
        aster_acme_core::account::KeyRotationPhase::Pending => "key rotation pending",
        aster_acme_core::account::KeyRotationPhase::Confirmed => "key commit pending",
    }
}

/// Pad plain cells before applying ANSI so highlighting never changes alignment.
fn list_text(
    accounts: &[aster_acme_cli_storage::inventory::LocalAccount],
    default: &str,
    verification: Option<&[crate::commands::account::report::AccountVerification]>,
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

#[expect(
    clippy::too_many_lines,
    reason = "Account details are rendered together in display order"
)]
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
        field(
            "Default profile:",
            &local
                .record
                .as_ref()
                .and_then(|record| record.preferred_profile.as_deref())
                .map_or_else(|| "(none; the CA default applies)".into(), safe),
            color,
        ),
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
            lines.push(field("Accepted terms:", &safe(url), color));
        }
        lines.push(field(
            "Automatic terms updates:",
            if record.auto_accept_terms_updates {
                "enabled"
            } else {
                "disabled"
            },
            color,
        ));
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
    use crate::commands::account::render::*;
    use aster_acme_cli_storage::inventory::LocalAccount;
    use aster_acme_core::account::DeactivationState;
    use aster_acme_protocol::url::AcmeUrl;

    pub(in crate::commands::account) fn json_value(report: &AccountReport) -> serde_json::Value {
        serde_json::to_value(crate::commands::account::output::Output::from(report)).unwrap()
    }

    #[test]
    fn contact_updates_report_nonvalid_ca_status_and_escape_untrusted_text() {
        use aster_acme_core::protocol::AccountStatus;
        for status in [
            AccountStatus::Valid,
            AccountStatus::Deactivated,
            AccountStatus::Revoked,
            AccountStatus::Unknown("custom\x1b[2J\n".into()),
        ] {
            let account = aster_acme::account::AcmeAccount {
                key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
                times: aster_acme::account::AccountTimes::default(),
                account_id: "account-id".into(),
                directory_url: AcmeUrl::new("https://ca.example/directory").unwrap(),
                account_url: AcmeUrl::new("https://ca.example/account/1").unwrap(),
                status: status.clone(),
                contacts: vec![],
                recovered: false,
            };
            let report = AccountReport::Updated(crate::commands::account::report::UpdateOutcome {
                name: "work\n".into(),
                contacts: Some(crate::commands::account::report::ContactsUpdate { account }),
                profile: None,
                terms: None,
            });
            let text = render(&report, Format::plain(false)).unwrap();
            assert!(
                text.contains("Updated contacts for account work\\n."),
                "{text}"
            );
            assert_eq!(text.lines().count(), 1);
            assert!(!text.contains('\x1b'));
            if status == AccountStatus::Valid {
                assert!(!text.contains("Status:"));
            } else {
                assert!(
                    text.contains(&format!("Status: {}.", safe(&String::from(status.clone()))))
                );
            }
            let json = json_value(&report);
            assert_eq!(json["contacts"]["status"], String::from(status));
            assert_eq!(json["contacts"]["verified"], true);
            assert_eq!(json["contacts"]["source"], "remote");
        }
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
        use crate::commands::account::report::RemoteAction;
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
                auto_accepted_terms: false,
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
            auto_accepted_terms: true,
            reused: false,
            action: RemoteAction::Register,
        };
        let text = render(&report, crate::common::session::Format::plain(false)).unwrap();
        assert!(text.contains("Automatically accepted the updated CA terms"));
        assert_eq!(
            json_value(&report)["auto_accepted_terms"].as_bool(),
            Some(true)
        );
        let report = AccountReport::Remote {
            name: "work".into(),
            account: account.clone(),
            auto_accepted_terms: false,
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
            auto_accepted_terms: false,
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
            preferred_profile: None,
            auto_accept_terms_updates: false,
            state: AccountRecordState::Registered,
        };
        let mut labels = Vec::new();
        for profile in [None, Some("shortlived"), Some("custom\n\x1b[2J")] {
            for verified in [false, true] {
                let mut account = account.clone();
                account.preferred_profile = profile.map(str::to_owned);
                let local = LocalAccountReport {
                    verified,
                    name: "default".into(),
                    directory: directory.clone(),
                    key_thumbprint: "thumbprint".into(),
                    record: Some(account.clone()),
                };
                let text = local_text(&local, false);
                assert!(
                    text.split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .contains(&format!(
                            "Default profile: {}",
                            profile.map_or_else(|| "(none; the CA default applies)".into(), safe)
                        ))
                );
                assert!(!text.contains('\x1b'));
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
                assert_eq!(json["preferred_profile"], serde_json::json!(profile));
                assert_eq!(json["contacts"][0], "mailto:a@example.com");
            }
        }
        assert!(
            labels
                .iter()
                .all(|labels_for_case| labels_for_case == &labels[0])
        );
    }
    #[test]
    fn profiles_and_preference_reports_serialize_with_explicit_fields() {
        use aster_acme_protocol::url::AcmeUrl;
        let directory = AcmeUrl::new("https://ca.example/directory").unwrap();
        let profiles = std::collections::BTreeMap::from([
            ("classic".to_owned(), String::new()),
            (
                "shortlived".to_owned(),
                "https://ca.example/shortlived".to_owned(),
            ),
        ]);
        let json = json_value(&AccountReport::Profiles {
            directory: directory.clone(),
            profiles: Some(profiles),
        });
        assert_eq!(json["directory"], "https://ca.example/directory");
        assert_eq!(json["profiles"]["classic"], "");
        assert_eq!(
            json["profiles"]["shortlived"],
            "https://ca.example/shortlived"
        );
        let json = json_value(&AccountReport::Profiles {
            directory: directory.clone(),
            profiles: None,
        });
        assert_eq!(json["profiles"], serde_json::Value::Null);

        let json = json_value(&AccountReport::Updated(
            crate::commands::account::report::UpdateOutcome {
                name: "work".to_owned(),
                contacts: None,
                profile: Some(crate::commands::account::report::ProfileChange {
                    previous: Some("classic".to_owned()),
                    current: None,
                }),
                terms: None,
            },
        ));
        assert_eq!(json["name"], "work");
        assert_eq!(json["profile"]["previous"], "classic");
        assert_eq!(json["profile"]["current"], serde_json::Value::Null);
        assert_eq!(json["contacts"], serde_json::Value::Null);
    }
}

#[test]
fn profiles_listing_reports_advertised_names_and_descriptions() {
    use aster_acme_protocol::url::AcmeUrl;
    use std::collections::BTreeMap;
    let directory = AcmeUrl::new("https://ca.example/directory").unwrap();
    let profiles = BTreeMap::from([
        (
            "classic".to_owned(),
            "https://ca.example/docs#classic".to_owned(),
        ),
        ("shortlived".to_owned(), String::new()),
    ]);
    let text = render(
        &AccountReport::Profiles {
            directory: directory.clone(),
            profiles: Some(profiles),
        },
        Format::plain(false),
    )
    .unwrap();
    assert!(text.contains("classic — https://ca.example/docs#classic"));
    assert!(text.contains("shortlived"));
    assert!(text.contains("account update --profile") && text.contains("cert issue --profile"));
    // No advertisement: the CA default is stated explicitly, not assumed.
    let text = render(
        &AccountReport::Profiles {
            directory,
            profiles: None,
        },
        Format::plain(false),
    )
    .unwrap();
    assert!(text.contains("advertises none"));
}

#[test]
fn profile_preference_text_distinguishes_set_and_clear() {
    let report = |previous: Option<&str>, current: Option<&str>| {
        AccountReport::Updated(crate::commands::account::report::UpdateOutcome {
            name: "work".to_owned(),
            contacts: None,
            profile: Some(crate::commands::account::report::ProfileChange {
                previous: previous.map(str::to_owned),
                current: current.map(str::to_owned),
            }),
            terms: None,
        })
    };
    let text = render(
        &report(Some("classic"), Some("shortlived")),
        Format::plain(false),
    )
    .unwrap();
    assert!(text.contains("shortlived") && text.contains("(was classic)"));
    assert!(text.contains("Explicit cert issue --profile still wins"));
    let text = render(&report(Some("shortlived"), None), Format::plain(false)).unwrap();
    assert!(text.contains("Cleared account work default profile"));
}

#[test]
fn terms_delegation_reports_local_consent_without_a_ca_sync() {
    let report =
        |previous, current, accepted: Option<&str>, advertised: Option<&str>, directory_checked| {
            AccountReport::Updated(crate::commands::account::report::UpdateOutcome {
                name: "work".to_owned(),
                contacts: None,
                profile: None,
                terms: Some(crate::commands::account::report::TermsChange {
                    previous,
                    current,
                    accepted_terms_url: accepted.map(str::to_owned),
                    advertised_terms_url: advertised.map(str::to_owned),
                    directory_checked,
                }),
            })
        };
    let text = |report: &AccountReport| render(report, Format::plain(false)).unwrap();

    let enabled = report(
        false,
        true,
        Some("https://ca.example/terms/v2"),
        Some("https://ca.example/terms/v2"),
        true,
    );
    let value = tests::json_value(&enabled);
    assert_eq!(value["name"], "work");
    assert_eq!(value["terms"]["auto_accept_terms_updates"], true);
    assert_eq!(value["terms"]["previous_auto_accept_terms_updates"], false);
    assert_eq!(
        value["terms"]["accepted_terms_url"],
        "https://ca.example/terms/v2"
    );
    assert_eq!(
        value["terms"]["advertised_terms_url"],
        "https://ca.example/terms/v2"
    );
    assert_eq!(value["terms"]["directory_checked"], true);
    assert_eq!(value["terms"]["ca_account_update_sent"], false);
    assert!(!enabled.has_failures());
    let enabled_text = text(&enabled);
    assert!(
        enabled_text.contains("now accepts")
            && enabled_text.contains("the terms delegation itself sent no CA account request"),
        "{enabled_text}"
    );

    let no_terms = report(false, true, None, None, true);
    let no_terms_text = text(&no_terms);
    assert!(
        no_terms_text.contains("publishes no terms today"),
        "{no_terms_text}"
    );
    let value = tests::json_value(&no_terms);
    assert_eq!(
        value["terms"]["advertised_terms_url"],
        serde_json::Value::Null
    );
    assert_eq!(value["terms"]["directory_checked"], true);

    let disabled = report(
        true,
        false,
        Some("https://ca.example/terms/v2"),
        None,
        false,
    );
    let disabled_text = text(&disabled);
    assert!(
        disabled_text.contains("no longer accepts") && disabled_text.contains("retained"),
        "{disabled_text}"
    );
    let value = tests::json_value(&disabled);
    assert_eq!(value["terms"]["auto_accept_terms_updates"], false);
    assert_eq!(value["terms"]["previous_auto_accept_terms_updates"], true);
    assert_eq!(value["terms"]["directory_checked"], false);
    assert_eq!(
        value["terms"]["advertised_terms_url"],
        serde_json::Value::Null
    );
    assert_eq!(value["terms"]["ca_account_update_sent"], false);

    let already_enabled = report(
        true,
        true,
        Some("https://ca.example/terms/v2"),
        Some("https://ca.example/terms/v2"),
        true,
    );
    assert!(text(&already_enabled).contains("already accepts"));
    let already_disabled = report(false, false, None, None, false);
    assert!(text(&already_disabled).contains("was already set"));
}
