//! Interactive registration decisions. Terms consent is scoped to the discovered CA URL.
use aster_acme_protocol::url::AcmeUrl;

use crate::common::{
    error::CliResult,
    output::safe,
    terminal::{self, Canceled, prompt_result},
};
use aster_acme::account::{AccountError, RegistrationOptions};

/// Prompt boundary keeps consent and optional-contact policy deterministic in tests.
pub(super) trait RegistrationPrompts {
    fn confirm(&mut self, message: &str) -> CliResult<bool>;
    fn email(&mut self) -> CliResult<String>;
    /// Arrow-key single choice; the default index is preselected.
    fn select(&mut self, message: &str, choices: &[String], default: usize) -> CliResult<usize>;
}

pub(super) struct TerminalPrompts<'a>(pub(super) &'a crate::common::session::OutputSession);

/// Missing update input is never interpreted as permission to clear contacts.
pub(super) fn replacement_contacts(
    contacts: Vec<String>,
    clear: bool,
    interactive: bool,
    prompts: &mut impl RegistrationPrompts,
) -> CliResult<Vec<String>> {
    match (clear, contacts.is_empty(), interactive) {
        (true, true, _) => Ok(Vec::new()),
        (true, false, _) => Err("Use --contact or --clear-contacts, not both.".into()),
        (false, false, _) => Ok(crate::commands::account::contact::normalize(contacts)?),
        (false, true, false) => Err("Specify --contact <EMAIL> or --clear-contacts.".into()),
        (false, true, true) => Ok(crate::commands::account::contact::normalize(vec![
            prompts.email()?,
        ])?),
    }
}

impl RegistrationPrompts for TerminalPrompts<'_> {
    fn confirm(&mut self, message: &str) -> CliResult<bool> {
        self.0.interaction_started();
        prompt_result(
            inquire::Confirm::new(message)
                .with_default(false)
                .with_render_config(crate::common::terminal::prompt_style(
                    self.0.diagnostic_format().color,
                    false,
                ))
                .prompt(),
        )
    }

    fn email(&mut self) -> CliResult<String> {
        self.0.interaction_started();
        prompt_result(
            inquire::Text::new("Contact email:")
                .with_render_config(crate::common::terminal::prompt_style(
                    self.0.diagnostic_format().color,
                    false,
                ))
                .with_placeholder("you@example.com")
                .with_help_message("Optional CA contact; saved locally for future registrations.")
                .with_validator(|input: &str| {
                    Ok(
                        match crate::commands::account::contact::normalize(vec![input.to_owned()]) {
                            Ok(_) => inquire::validator::Validation::Valid,
                            Err(_) => inquire::validator::Validation::Invalid(
                                "Enter one email address, e.g. you@example.com.".into(),
                            ),
                        },
                    )
                })
                .prompt(),
        )
    }

    fn select(&mut self, message: &str, choices: &[String], default: usize) -> CliResult<usize> {
        terminal::select_index(message, choices, default, self.0)
    }
}

/// Explicit CLI/config/local contacts bypass the question. Declining optional contact
/// continues registration without an address; canceling the prompt stops the operation.
/// Returns whether an interactive address should be persisted as a config default.
pub(super) fn contact(
    options: &mut RegistrationOptions,
    interactive: bool,
    prompts: &mut impl RegistrationPrompts,
) -> CliResult<bool> {
    if !interactive || !options.contacts.is_empty() {
        return Ok(false);
    }
    if !prompts.confirm("Add a contact email for this account? (optional)")? {
        return Ok(false);
    }
    options.contacts = crate::commands::account::contact::normalize(vec![prompts.email()?])?;
    Ok(true)
}

/// A previous acceptance is reusable only for the exact current terms URL. `--yes`
/// is deliberately absent: account reuse confirmation must never imply terms consent.
/// Draft-ietf-acme-profiles (<https://datatracker.ietf.org/doc/html/draft-ietf-acme-profiles>):
/// interactive default-profile selection from the CA's advertised list.
/// Blank input keeps the CA default; the answer must be an advertised name.
/// Draft-ietf-acme-profiles interactive default-profile selection: one
/// arrow-key menu over the advertised names plus an explicit skip entry.
pub(super) fn profile_choice(
    advertised: Option<&std::collections::BTreeMap<String, String>>,
    prompts: &mut impl RegistrationPrompts,
) -> CliResult<Option<String>> {
    let Some(advertised) = advertised.filter(|map| !map.is_empty()) else {
        return Ok(None);
    };
    let names = advertised.keys().cloned().collect::<Vec<_>>();
    // CA-provided names/descriptions are untrusted terminal text: escape the
    // display labels, while selection still indexes the original names.
    let mut choices = names
        .iter()
        .map(
            |name| match advertised.get(name).filter(|text| !text.is_empty()) {
                Some(description) => format!(
                    "{} — {}",
                    crate::common::output::safe(name),
                    crate::common::output::safe(description)
                ),
                None => crate::common::output::safe(name),
            },
        )
        .collect::<Vec<_>>();
    choices.push("(no default; the CA default applies)".to_owned());
    let selection = prompts.select("Default certificate profile:", &choices, 0)?;
    Ok(if selection < names.len() {
        Some(names[selection].clone())
    } else {
        None
    })
}

pub(super) fn terms(
    options: &mut RegistrationOptions,
    current: Option<&AcmeUrl>,
    accepted: Option<&AcmeUrl>,
    interactive: bool,
    prompts: &mut impl RegistrationPrompts,
) -> CliResult<()> {
    let Some(current) = current else {
        return Ok(());
    };
    if options.terms_accepted || accepted == Some(current) {
        return Ok(());
    }
    if !interactive {
        return Err(AccountError::TermsRequired(current.clone()).into());
    }
    let message = format!(
        "CA terms: {}\nDo you agree to these terms?",
        safe(current.as_str())
    );
    if !prompts.confirm(&message)? {
        return Err(Box::new(Canceled));
    }
    options.terms_accepted = true;
    Ok(())
}

/// Ask for the separate durable trust delegation after current terms consent.
/// `--yes` and non-interactive output never reach this prompt.
pub(super) fn auto_accept_terms_updates(
    options: &mut RegistrationOptions,
    current: Option<&AcmeUrl>,
    already_authorized: bool,
    interactive: bool,
    yes: bool,
    prompts: &mut impl RegistrationPrompts,
) -> CliResult<()> {
    if current.is_none()
        || options.auto_accept_terms_updates
        || already_authorized
        || !interactive
        || yes
    {
        return Ok(());
    }
    if prompts.confirm("Automatically accept future CA terms updates?")? {
        options.auto_accept_terms_updates = true;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::commands::account::interaction::*;
    use std::collections::VecDeque;

    struct Prompts {
        answers: VecDeque<bool>,
        address: Option<String>,
        selections: VecDeque<usize>,
        messages: Vec<String>,
    }

    impl RegistrationPrompts for Prompts {
        fn confirm(&mut self, message: &str) -> CliResult<bool> {
            self.messages.push(message.to_owned());
            self.answers
                .pop_front()
                .ok_or_else(|| Box::new(Canceled) as Box<dyn std::error::Error>)
        }
        fn email(&mut self) -> CliResult<String> {
            self.address
                .take()
                .ok_or_else(|| Box::new(Canceled) as Box<dyn std::error::Error>)
        }
        fn select(
            &mut self,
            message: &str,
            _choices: &[String],
            _default: usize,
        ) -> CliResult<usize> {
            self.messages.push(message.to_owned());
            self.selections
                .pop_front()
                .ok_or_else(|| Box::new(Canceled) as Box<dyn std::error::Error>)
        }
    }

    fn prompts(answers: &[bool], email: Option<&str>) -> Prompts {
        Prompts {
            answers: answers.iter().copied().collect(),
            address: email.map(str::to_owned),
            selections: VecDeque::new(),
            messages: vec![],
        }
    }

    #[test]
    fn contact_replacement_requires_explicit_clear_and_noninteractive_input() {
        assert!(replacement_contacts(vec![], false, false, &mut prompts(&[], None)).is_err());
        assert!(
            replacement_contacts(
                vec!["a@example.org".into()],
                true,
                false,
                &mut prompts(&[], None)
            )
            .is_err()
        );
        assert_eq!(
            replacement_contacts(vec![], true, false, &mut prompts(&[], None)).unwrap(),
            [] as [String; 0]
        );
        assert_eq!(
            replacement_contacts(
                vec!["a@example.org".into()],
                false,
                false,
                &mut prompts(&[], None)
            )
            .unwrap(),
            ["mailto:a@example.org"]
        );
        assert_eq!(
            replacement_contacts(
                vec![],
                false,
                true,
                &mut prompts(&[], Some("b@example.org"))
            )
            .unwrap(),
            ["mailto:b@example.org"]
        );
        assert!(
            replacement_contacts(vec![], false, true, &mut prompts(&[], None))
                .unwrap_err()
                .is::<Canceled>()
        );
    }

    #[test]
    fn optional_contact_skip_accept_validate_and_cancel() {
        let mut options = RegistrationOptions::default();
        let mut no = prompts(&[false], None);
        assert!(!contact(&mut options, true, &mut no).unwrap());
        assert_eq!(options.contacts, Vec::<String>::new());
        let mut yes = prompts(&[true], Some("you@example.com"));
        assert!(contact(&mut options, true, &mut yes).unwrap());
        assert_eq!(options.contacts, ["mailto:you@example.com"]);
        assert!(!contact(&mut options, true, &mut prompts(&[], None)).unwrap());
        for email in [None, Some("invalid")] {
            assert!(
                contact(
                    &mut RegistrationOptions::default(),
                    true,
                    &mut prompts(&[true], email)
                )
                .is_err()
            );
        }
        assert!(
            contact(
                &mut RegistrationOptions::default(),
                true,
                &mut prompts(&[], None)
            )
            .unwrap_err()
            .is::<Canceled>()
        );
        assert!(
            !contact(
                &mut RegistrationOptions::default(),
                false,
                &mut prompts(&[], None)
            )
            .unwrap()
        );
    }

    #[test]
    fn terms_require_explicit_consent_for_the_current_url() {
        let current = AcmeUrl::new("https://ca.example/terms/v2").unwrap();
        let old = AcmeUrl::new("https://ca.example/terms/v1").unwrap();
        let mut options = RegistrationOptions::default();
        let mut yes = prompts(&[true], None);
        terms(&mut options, Some(&current), Some(&old), true, &mut yes).unwrap();
        assert!(options.terms_accepted);
        assert!(yes.messages[0].contains(current.as_str()));
        for accepted in [None, Some(&old)] {
            assert!(
                terms(
                    &mut RegistrationOptions::default(),
                    Some(&current),
                    accepted,
                    true,
                    &mut prompts(&[false], None)
                )
                .unwrap_err()
                .is::<Canceled>()
            );
            assert!(
                terms(
                    &mut RegistrationOptions::default(),
                    Some(&current),
                    accepted,
                    false,
                    &mut prompts(&[], None)
                )
                .unwrap_err()
                .is::<AccountError>()
            );
        }
        terms(
            &mut RegistrationOptions::default(),
            Some(&current),
            Some(&current),
            true,
            &mut prompts(&[], None),
        )
        .unwrap();
        terms(
            &mut options,
            Some(&current),
            None,
            false,
            &mut prompts(&[], None),
        )
        .unwrap();
        terms(
            &mut RegistrationOptions::default(),
            None,
            None,
            true,
            &mut prompts(&[], None),
        )
        .unwrap();
        assert!(
            terms(
                &mut RegistrationOptions::default(),
                Some(&current),
                None,
                true,
                &mut prompts(&[], None)
            )
            .unwrap_err()
            .is::<Canceled>()
        );
    }

    #[test]
    fn yes_never_prompts_or_grants_future_consent_even_on_a_terminal() {
        let current = AcmeUrl::new("https://ca.example/terms/v2").unwrap();
        for interactive in [false, true] {
            let mut options = RegistrationOptions {
                terms_accepted: true,
                ..RegistrationOptions::default()
            };
            let mut never_prompt = prompts(&[], None);
            auto_accept_terms_updates(
                &mut options,
                Some(&current),
                false,
                interactive,
                true,
                &mut never_prompt,
            )
            .unwrap();
            assert!(!options.auto_accept_terms_updates);
            assert_eq!(never_prompt.messages.len(), 0);
        }
        let mut explicit = RegistrationOptions {
            auto_accept_terms_updates: true,
            ..RegistrationOptions::default()
        };
        auto_accept_terms_updates(
            &mut explicit,
            Some(&current),
            false,
            true,
            true,
            &mut prompts(&[], None),
        )
        .unwrap();
        assert!(explicit.auto_accept_terms_updates);
    }

    #[test]
    fn auto_accept_terms_requires_explicit_interactive_yes() {
        let current = AcmeUrl::new("https://ca.example/terms/v2").unwrap();
        let mut options = RegistrationOptions::default();
        auto_accept_terms_updates(
            &mut options,
            Some(&current),
            false,
            true,
            false,
            &mut prompts(&[false], None),
        )
        .unwrap();
        assert!(!options.auto_accept_terms_updates);
        auto_accept_terms_updates(
            &mut options,
            Some(&current),
            false,
            true,
            false,
            &mut prompts(&[true], None),
        )
        .unwrap();
        assert!(options.auto_accept_terms_updates);
        auto_accept_terms_updates(
            &mut RegistrationOptions::default(),
            Some(&current),
            false,
            false,
            false,
            &mut prompts(&[], None),
        )
        .unwrap();
        let mut already = prompts(&[], None);
        auto_accept_terms_updates(
            &mut RegistrationOptions::default(),
            Some(&current),
            true,
            true,
            false,
            &mut already,
        )
        .unwrap();
    }
}

#[cfg(test)]
mod profile_choice_tests {
    use crate::commands::account::interaction::*;

    use std::collections::VecDeque;

    struct FakePrompts {
        selections: VecDeque<usize>,
        messages: Vec<String>,
    }

    impl RegistrationPrompts for FakePrompts {
        fn confirm(&mut self, message: &str) -> CliResult<bool> {
            self.messages.push(message.to_owned());
            Ok(true)
        }
        fn email(&mut self) -> CliResult<String> {
            Ok("mailto:test@example.com".into())
        }
        fn select(
            &mut self,
            _message: &str,
            _choices: &[String],
            _default: usize,
        ) -> CliResult<usize> {
            self.selections.pop_front().ok_or_else(|| {
                Box::new(crate::common::terminal::Canceled) as Box<dyn std::error::Error>
            })
        }
    }

    #[test]
    fn profile_choice_maps_arrow_selections_and_skip_entry() {
        let advertised = std::collections::BTreeMap::from([
            (
                "classic".to_owned(),
                "https://ca.example/classic".to_owned(),
            ),
            ("shortlived".to_owned(), String::new()),
        ]);
        let mut prompts = FakePrompts {
            selections: VecDeque::from([1]),
            messages: vec![],
        };
        assert_eq!(
            profile_choice(Some(&advertised), &mut prompts)
                .unwrap()
                .as_deref(),
            Some("shortlived")
        );
        let mut prompts = FakePrompts {
            selections: VecDeque::from([2]),
            messages: vec![],
        };
        assert_eq!(
            profile_choice(Some(&advertised), &mut prompts).unwrap(),
            None
        );
        let mut prompts = FakePrompts {
            selections: VecDeque::new(),
            messages: vec![],
        };
        assert_eq!(profile_choice(None, &mut prompts).unwrap(), None);
        assert!(
            prompts.messages.is_empty(),
            "no prompt without advertisement"
        );
    }
}
