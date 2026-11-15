//! Draft editing, exact argv, zone boundaries and cancellation before commit.
use crate::commands::provider::interaction::{Prompts, update::edit};
use crate::common::{error::CliResult, terminal::Canceled};
use aster_acme_cli_storage::provider::ProviderProfile;
use std::{collections::VecDeque, path::Path};

#[derive(Default)]
struct Inputs {
    choices: VecDeque<usize>,
    answers: VecDeque<String>,
    invalid: Vec<String>,
    reviews: Vec<ProviderProfile>,
}
impl Prompts for Inputs {
    fn text(&mut self, _: &str, _: bool) -> CliResult<String> {
        match self.answers.pop_front() {
            Some(value) if value == "<ESC>" => {
                Err(Box::new(crate::commands::provider::interaction::Back))
            }
            Some(value) => Ok(value),
            None => Err(Box::new(Canceled)),
        }
    }
    fn invalid(&mut self, message: &str) {
        self.invalid.push(message.into());
    }
    fn select(&mut self, _: &str, _: &[String]) -> CliResult<usize> {
        match self.choices.pop_front() {
            Some(usize::MAX) => Err(Box::new(crate::commands::provider::interaction::Back)),
            Some(index) => Ok(index),
            None => Err(Box::new(Canceled)),
        }
    }
    fn review(&mut self, _: &str, _: &Path, profile: &ProviderProfile) -> CliResult<()> {
        self.reviews.push(profile.clone());
        Ok(())
    }
}
fn profile() -> ProviderProfile {
    let mut profile = ProviderProfile::new(
        std::env::current_exe().unwrap(),
        vec!["old".into(), "keep".into()],
        vec!["old.example".into()],
    )
    .unwrap();
    profile
        .provider_custom
        .insert("token".into(), serde_json::json!("secret-sentinel"));
    profile
}
fn inputs(choices: &[usize], answers: &[&str]) -> Inputs {
    Inputs {
        choices: choices.iter().copied().collect(),
        answers: answers.iter().map(|s| (*s).into()).collect(),
        ..Inputs::default()
    }
}

#[test]
fn editor_preserves_exact_arguments_and_custom_values_until_save() {
    let original = profile();
    // Open args, add a spaced argument and an empty argument, remove the old
    // first argument by its index, finish the list and save the draft.
    let mut prompts = inputs(&[1, 0, 0, 1, 0, 3, 3], &["--label=hello world", ""]);
    let edited = edit("prod", Path::new("profile.toml"), &original, &mut prompts).unwrap();
    assert_eq!(edited.args, ["keep", "--label=hello world", ""]);
    assert_eq!(edited.provider_custom, original.provider_custom);
    assert_eq!(edited.allowed_zones, original.allowed_zones);
    assert_eq!(original.args, ["old", "keep"]);
    assert_eq!(prompts.reviews.last().unwrap(), &edited);
    let mut prompts = inputs(&[1, 0, 3, 3], &["bad\0argument"]);
    let edited = edit("prod", Path::new("profile.toml"), &original, &mut prompts).unwrap();
    assert_eq!(edited, original);
    assert_eq!(prompts.invalid.len(), 1);
}

#[test]
fn editor_validates_zone_labels_duplicates_and_explicitly_clears_restrictions() {
    let original = profile();
    let mut prompts = inputs(
        &[2, 0, 0, 0, 3, 3],
        &["bad zone", "OLD.EXAMPLE.", "new.example"],
    );
    let edited = edit("prod", Path::new("profile.toml"), &original, &mut prompts).unwrap();
    assert_eq!(edited.allowed_zones, ["old.example", "new.example"]);
    assert_eq!(prompts.invalid.len(), 2);
    let mut prompts = inputs(&[2, 2, 1, 3, 1, 2, 3, 3], &[]);
    let edited = edit("prod", Path::new("profile.toml"), &original, &mut prompts).unwrap();
    assert_eq!(edited.allowed_zones, Vec::<String>::new());
    assert_eq!(edited.args, Vec::<String>::new());
    assert_eq!(prompts.invalid.len(), 1); // removing from an empty list
}

#[test]
fn editor_validates_executable_and_cancel_never_changes_the_original() {
    let original = profile();
    let executable = std::env::current_exe().unwrap();
    let mut prompts = inputs(&[0, 0, 3], &["relative", executable.to_str().unwrap()]);
    assert_eq!(
        edit("prod", Path::new("profile.toml"), &original, &mut prompts).unwrap(),
        original
    );
    assert_eq!(prompts.invalid.len(), 1);
    for choices in [&[][..], &[4], &[0], &[1], &[2], &[1, 2, 3, 4]] {
        let mut prompts = inputs(choices, &[]);
        assert!(
            edit("prod", Path::new("profile.toml"), &original, &mut prompts)
                .unwrap_err()
                .is::<Canceled>()
        );
        assert_eq!(original, profile());
    }
    for choices in [&[99][..], &[1, 99], &[1, 1, 99]] {
        assert!(
            edit(
                "prod",
                Path::new("profile.toml"),
                &original,
                &mut inputs(choices, &[])
            )
            .is_err()
        );
    }
}

#[test]
fn back_navigation_preserves_the_draft_and_returns_only_one_level() {
    let original = profile();
    for back in [1, usize::MAX] {
        // Clear args in the draft, return to profile, open zones -> remove,
        // go back without deleting, return to profile and save.
        let mut prompts = inputs(&[1, 2, 3, 2, 1, back, 3, 3], &[]);
        let mut expected = original.clone();
        expected.args.clear();
        assert_eq!(
            edit("prod", Path::new("profile.toml"), &original, &mut prompts).unwrap(),
            expected
        );
    }
    let mut prompts = inputs(&[0, 1, 0, usize::MAX, 3], &["<ESC>", "<ESC>"]);
    assert_eq!(
        edit("prod", Path::new("profile.toml"), &original, &mut prompts).unwrap(),
        original
    );
    assert!(
        edit(
            "prod",
            Path::new("profile.toml"),
            &original,
            &mut inputs(&[usize::MAX], &[])
        )
        .unwrap_err()
        .is::<Canceled>()
    );
}
