//! Interactive registration decisions. Terms consent is scoped to the discovered CA URL.
use aster_acme_protocol::url::AcmeUrl;

use crate::common::{
    error::CliResult,
    output::safe,
    terminal::{Canceled, prompt_result},
};
use aster_acme::account::{AccountError, RegistrationOptions};

/// Prompt boundary keeps consent and optional-contact policy deterministic in tests.
pub(super) trait RegistrationPrompts {
    fn confirm(&mut self, message: &str) -> CliResult<bool>;
    fn email(&mut self) -> CliResult<String>;
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
        (false, false, _) => Ok(super::contact::normalize(contacts)?),
        (false, true, false) => Err("Specify --contact <EMAIL> or --clear-contacts.".into()),
        (false, true, true) => Ok(super::contact::normalize(vec![prompts.email()?])?),
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
                    Ok(match super::contact::normalize(vec![input.to_owned()]) {
                        Ok(_) => inquire::validator::Validation::Valid,
                        Err(_) => inquire::validator::Validation::Invalid(
                            "Enter one email address, e.g. you@example.com.".into(),
                        ),
                    })
                })
                .prompt(),
        )
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
    options.contacts = super::contact::normalize(vec![prompts.email()?])?;
    Ok(true)
}

/// A previous acceptance is reusable only for the exact current terms URL. `--yes`
/// is deliberately absent: account reuse confirmation must never imply terms consent.
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

#[cfg(test)]
mod tests {
    use crate::commands::account::interaction::*;
    use std::collections::VecDeque;

    struct Prompts {
        answers: VecDeque<bool>,
        address: Option<String>,
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
    }

    fn prompts(answers: &[bool], email: Option<&str>) -> Prompts {
        Prompts {
            answers: answers.iter().copied().collect(),
            address: email.map(str::to_owned),
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
}
