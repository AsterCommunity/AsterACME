//! Shared account selection for all commands; prompts only supply ordinary command arguments.

use super::args::AccountArgs;
use crate::{
    common::{error::CliResult, output::safe, terminal::prompt_result},
    config::DEFAULT_CA_DIRECTORY,
};
use aster_acme_cli_storage::{LocalAccount, valid_account_name};

#[derive(Clone, Copy)]
pub(super) enum Mode {
    Register,
    Existing,
    Registered,
}

/// Enumerate local choices only when a real terminal needs an unresolved target.
pub(super) async fn complete(
    options: &mut AccountArgs,
    settings: &crate::common::context::CliSettings,
    mode: Mode,
    cli: &crate::common::context::CommandContext,
) -> CliResult<()> {
    if crate::common::terminal::interactive(options.json) && options.name.is_none() {
        let accounts = aster_acme_cli_storage::accounts(settings.data_dir.clone()).await?;
        resolve(
            options,
            mode,
            &accounts,
            settings.config.default_account.as_deref(),
            crate::ca::resolve(settings.config.ca, settings.config.ca_directory.as_deref())?,
            true,
            &mut TerminalSelection {
                output: &cli.output,
            },
        )?;
    }
    Ok(())
}

pub(super) trait SelectionPrompts {
    fn choose(&mut self, message: &str, choices: Vec<String>, default: usize) -> CliResult<usize>;
    fn text(&mut self, message: &str, default: &str) -> CliResult<String>;
    fn invalid(&mut self, message: &str);
}

pub(super) struct TerminalSelection<'a> {
    output: &'a crate::common::session::OutputSession,
}

impl SelectionPrompts for TerminalSelection<'_> {
    fn choose(&mut self, message: &str, choices: Vec<String>, default: usize) -> CliResult<usize> {
        crate::common::terminal::select_index(message, &choices, default, self.output)
    }

    fn text(&mut self, message: &str, default: &str) -> CliResult<String> {
        self.output.interaction_started();
        prompt_result(
            inquire::Text::new(message)
                .with_default(default)
                .with_render_config(crate::common::terminal::prompt_style(
                    self.output.diagnostic_format().color,
                    false,
                ))
                .prompt(),
        )
    }

    fn invalid(&mut self, message: &str) {
        self.output.context(&safe(message));
    }
}

/// Explicit names bypass selection. Interactive selection ignores the default CA when
/// listing existing accounts: each one carries its own CA. An explicit CA filters choices.
pub(super) fn resolve(
    options: &mut AccountArgs,
    mode: Mode,
    accounts: &[LocalAccount],
    default_name: Option<&str>,
    default_ca: Option<&str>,
    interactive: bool,
    prompts: &mut impl SelectionPrompts,
) -> CliResult<()> {
    if options.name.is_some() || !interactive {
        return Ok(());
    }
    let candidates: Vec<_> = accounts
        .iter()
        .filter(|account| {
            let state_allowed = match mode {
                Mode::Registered => account.usable,
                Mode::Register | Mode::Existing => true,
            };
            state_allowed
                && options
                    .ca_directory
                    .as_deref()
                    .is_none_or(|ca| ca == account.directory.as_str())
        })
        .collect();
    if matches!(mode, Mode::Register) {
        let new_account = if candidates.is_empty() {
            true
        } else {
            match prompts.choose(
                "Register an account:",
                vec![
                    "Create a new account (new key and identity)".into(),
                    "Continue an existing account (reuse its saved key)".into(),
                ],
                0,
            )? {
                0 => true,
                1 => false,
                _ => return Err("Invalid registration action.".into()),
            }
        };
        if new_account {
            return create(options, accounts, default_name, default_ca, prompts);
        }
    }
    if candidates.is_empty() {
        return Err("No eligible local accounts. Register an account first or check --data-dir / --ca-directory.".into());
    }
    let choices = candidates
        .iter()
        .map(|account| {
            let state = match account.deactivation {
                aster_acme_core::account::DeactivationState::Pending => "deactivation pending",
                aster_acme_core::account::DeactivationState::Confirmed => "deactivated",
                aster_acme_core::account::DeactivationState::NotRequested => {
                    super::report::state_label(account.state)
                }
            };
            crate::common::selection::ChoiceLabel {
                name: &account.name,
                summary: None,
                at: account.times.registered_at,
                status: Some(state),
                marker: if Some(account.name.as_str()) == default_name {
                    Some("default")
                } else {
                    None
                },
            }
            .to_string()
        })
        .collect();
    let default = candidates
        .iter()
        .position(|account| Some(account.name.as_str()) == default_name)
        .unwrap_or(0);
    let selected = prompts.choose("Choose an existing account:", choices, default)?;
    let account = candidates
        .get(selected)
        .ok_or("Invalid account selection.")?;
    options.name = Some(account.name.clone());
    Ok(())
}

/// New registration collects a fresh name; it never defaults to an occupied identity.
fn create(
    options: &mut AccountArgs,
    accounts: &[LocalAccount],
    default_name: Option<&str>,
    default_ca: Option<&str>,
    prompts: &mut impl SelectionPrompts,
) -> CliResult<()> {
    let suggested = default_name
        .filter(|name| !accounts.iter().any(|account| account.name == *name))
        .unwrap_or({
            if accounts.is_empty() {
                "default"
            } else {
                "new-account"
            }
        });
    // Retry validation in place, rather than turning a typo into a failed command.
    loop {
        let name = prompts.text("New account name (letters, digits, - or _):", suggested)?;
        if !valid_account_name(&name) {
            prompts.invalid("Use 1–64 letters, digits, hyphens or underscores.");
            continue;
        }
        if accounts.iter().any(|account| account.name == name) {
            prompts.invalid("That name is already used. Choose another name, or cancel and select the existing account.");
            continue;
        }
        options.name = Some(name);
        break;
    }
    if options.ca_directory.is_none() {
        loop {
            let ca = prompts.text(
                "CA (letsencrypt / zerossl / google, or full ACME directory URL):",
                default_ca.unwrap_or(DEFAULT_CA_DIRECTORY),
            )?;
            if let Ok(directory) = crate::ca::input(&ca) {
                options.ca_directory = Some(directory);
                break;
            }
            prompts
                .invalid("Enter letsencrypt, zerossl, google, or a full HTTPS ACME directory URL.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::terminal::Canceled;
    use aster_acme_protocol::url::AcmeUrl;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct Prompts {
        selected: usize,
        registration_action: usize,
        messages: Vec<String>,
        answers: VecDeque<String>,
        shown: Vec<String>,
        errors: usize,
        default: usize,
    }

    impl SelectionPrompts for Prompts {
        fn choose(
            &mut self,
            message: &str,
            choices: Vec<String>,
            default: usize,
        ) -> CliResult<usize> {
            self.messages.push(message.to_owned());
            if message == "Register an account:" {
                return Ok(self.registration_action);
            }
            self.shown = choices;
            self.default = default;
            Ok(self.selected)
        }
        fn text(&mut self, _message: &str, _default: &str) -> CliResult<String> {
            self.answers
                .pop_front()
                .ok_or_else(|| Box::new(Canceled) as Box<dyn std::error::Error>)
        }
        fn invalid(&mut self, _message: &str) {
            self.errors += 1;
        }
    }

    fn accounts() -> Vec<LocalAccount> {
        vec![
            LocalAccount {
                key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
                key_rotation: None,
                times: aster_acme::account::AccountTimes::default(),
                name: "pending".into(),
                directory: AcmeUrl::new("https://first.example/directory").unwrap(),
                usable: false,
                state: aster_acme_core::account::AccountRecordState::RegistrationPending,
                last_status: None,
                deactivation: aster_acme_core::account::DeactivationState::NotRequested,
            },
            LocalAccount {
                key_algorithm: aster_acme::crypto::key_algorithm::KeyAlgorithm::EcdsaP256,
                key_rotation: None,
                times: aster_acme::account::AccountTimes::default(),
                name: "work".into(),
                directory: AcmeUrl::new("https://other.example/directory").unwrap(),
                usable: true,
                state: aster_acme_core::account::AccountRecordState::Registered,
                last_status: None,
                deactivation: aster_acme_core::account::DeactivationState::NotRequested,
            },
        ]
    }

    #[test]
    fn shared_modes_filter_choices_and_select_defaults_without_changing_ca() {
        for mode in [Mode::Register, Mode::Existing] {
            let mut options = AccountArgs::default();
            let mut prompts = Prompts {
                selected: 1,
                registration_action: 1,
                ..Prompts::default()
            };
            resolve(
                &mut options,
                mode,
                &accounts(),
                Some("work"),
                None,
                true,
                &mut prompts,
            )
            .unwrap();
            assert_eq!(options.name.as_deref(), Some("work"));
            assert_eq!(options.ca_directory, None);
            assert_eq!(prompts.default, 1);
            assert!(prompts.shown[1].contains("work"));
            assert!(!prompts.shown[1].contains("https://"));
            match mode {
                Mode::Register => assert_eq!(
                    prompts.messages,
                    ["Register an account:", "Choose an existing account:"]
                ),
                Mode::Existing => assert_eq!(prompts.messages, ["Choose an existing account:"]),
                Mode::Registered => panic!("not part of this test case"),
            }
        }
        let mut options = AccountArgs::default();
        let mut prompts = Prompts::default();
        resolve(
            &mut options,
            Mode::Registered,
            &accounts(),
            Some("pending"),
            None,
            true,
            &mut prompts,
        )
        .unwrap();
        assert_eq!(options.name.as_deref(), Some("work"));
        assert_eq!(prompts.shown.len(), 1);
        let mut options = AccountArgs {
            ca_directory: Some("https://first.example/directory".into()),
            ..AccountArgs::default()
        };
        assert!(
            resolve(
                &mut options,
                Mode::Registered,
                &accounts(),
                None,
                None,
                true,
                &mut Prompts::default()
            )
            .is_err()
        );
    }

    #[test]
    fn create_retries_bad_duplicate_names_and_bad_urls_without_overwriting_identity() {
        let mut options = AccountArgs::default();
        let mut prompts = Prompts {
            selected: 0,
            answers: [
                "../bad",
                "work",
                "new",
                "bad-url",
                "https://new.example/directory",
            ]
            .map(str::to_owned)
            .into(),
            ..Prompts::default()
        };
        resolve(
            &mut options,
            Mode::Register,
            &accounts(),
            None,
            None,
            true,
            &mut prompts,
        )
        .unwrap();
        assert_eq!(options.name.as_deref(), Some("new"));
        assert_eq!(
            options.ca_directory.as_deref(),
            Some("https://new.example/directory")
        );
        assert_eq!(prompts.errors, 3);
        assert_eq!(prompts.messages, ["Register an account:"]);
        let mut options = AccountArgs {
            ca_directory: Some("https://explicit.example/directory".into()),
            ..AccountArgs::default()
        };
        let mut prompts = Prompts {
            answers: ["new".into()].into(),
            ..Prompts::default()
        };
        resolve(
            &mut options,
            Mode::Register,
            &[],
            None,
            None,
            true,
            &mut prompts,
        )
        .unwrap();
        assert_eq!(
            options.ca_directory.as_deref(),
            Some("https://explicit.example/directory")
        );
    }

    #[test]
    fn explicit_automation_empty_lists_and_cancellation_have_no_surprise_prompts() {
        for mode in [Mode::Register, Mode::Existing, Mode::Registered] {
            let mut options = AccountArgs::default();
            resolve(
                &mut options,
                mode,
                &[],
                None,
                None,
                false,
                &mut Prompts::default(),
            )
            .unwrap();
            assert_eq!(options.name, None);
            let mut explicit = AccountArgs {
                name: Some("explicit".into()),
                ..AccountArgs::default()
            };
            resolve(
                &mut explicit,
                mode,
                &[],
                None,
                None,
                true,
                &mut Prompts::default(),
            )
            .unwrap();
            assert_eq!(explicit.name.as_deref(), Some("explicit"));
        }
        for mode in [Mode::Existing, Mode::Registered] {
            assert!(
                resolve(
                    &mut AccountArgs::default(),
                    mode,
                    &[],
                    None,
                    None,
                    true,
                    &mut Prompts::default()
                )
                .is_err()
            );
        }
        assert!(
            resolve(
                &mut AccountArgs::default(),
                Mode::Register,
                &[],
                None,
                None,
                true,
                &mut Prompts::default()
            )
            .unwrap_err()
            .is::<Canceled>()
        );
        let mut invalid = Prompts {
            selected: 9,
            ..Prompts::default()
        };
        assert!(
            resolve(
                &mut AccountArgs::default(),
                Mode::Existing,
                &accounts(),
                None,
                None,
                true,
                &mut invalid
            )
            .is_err()
        );
    }
}
