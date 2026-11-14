//! Missing-input completion, retries and cancellation before persistence.
use crate::commands::cert::{
    args::{
        CertCommand,
        deployment::{DeployAddArgs, DeployCommand},
    },
    deployment::interaction::*,
};
use aster_acme::deployment::DeploymentPhase;
use aster_acme_cli_storage::issuance::{DeploymentBinding, DeploymentTarget};
use clap::Parser as _;
use std::collections::VecDeque;

#[derive(Default)]
struct Inputs {
    answers: VecDeque<String>,
    asked: Vec<String>,
    errors: Vec<String>,
    defaults: Vec<Option<String>>,
}

impl Prompts for Inputs {
    fn text(&mut self, message: &str, default: Option<&str>) -> CliResult<String> {
        self.asked.push(message.into());
        self.defaults.push(default.map(str::to_owned));
        let answer = self.answers.pop_front().ok_or_else(|| {
            Box::new(crate::common::terminal::Canceled) as Box<dyn std::error::Error>
        })?;
        Ok(if answer.is_empty() {
            default.unwrap_or(&answer).to_owned()
        } else {
            answer
        })
    }
    fn invalid(&mut self, message: &str) {
        self.errors.push(message.into());
    }
}

fn args() -> DeployAddArgs {
    let parsed = crate::app::Args::try_parse_from(["aster-acme", "cert", "deploy", "add"]).unwrap();
    let crate::app::Command::Cert {
        command: CertCommand::Deploy(args),
    } = parsed.command
    else {
        panic!("expected deploy");
    };
    let DeployCommand::Add(args) = args.command else {
        panic!("expected add");
    };
    args
}

#[test]
fn bare_add_offers_default_name_then_directory_and_optional_reload() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target with spaces");
    std::fs::create_dir(&target).unwrap();
    let mut args = args();
    let mut prompts = Inputs {
        answers: [
            String::new(),
            target.to_string_lossy().into_owned(),
            String::new(),
        ]
        .into(),
        ..Inputs::default()
    };
    complete(&mut args, &[], true, &mut prompts).unwrap();
    assert_eq!(args.id.as_deref(), Some("default"));
    assert_eq!(args.target, Some(target.canonicalize().unwrap()));
    assert_eq!(args.reload_cmd, None);
    assert_eq!(prompts.asked.len(), 3);
    assert!(prompts.asked[1].contains("Target directory"));
    assert!(prompts.asked[2].contains("optional"));
    assert_eq!(prompts.defaults[0].as_deref(), Some("default"));
    assert_eq!(std::fs::read_dir(target).unwrap().count(), 0);
}

#[test]
fn invalid_directories_and_reload_quoting_retry_but_explicit_duplicate_names_fail() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("file");
    std::fs::write(&file, "untouched").unwrap();
    let existing = DeploymentBinding {
        permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
        id: "nginx".into(),
        target: DeploymentTarget::Directory {
            path: root.path().into(),
        },
        reload_command: Vec::new(),
        timeout_seconds: 30,
        max_retries: 3,
        generation: None,
        phase: DeploymentPhase::Configured,
        attempts: 0,
        retry_failures: 0,
        retry_at: None,
        last_error: None,
    };
    let mut prompts = Inputs {
        answers: [
            root.path().join("missing").to_string_lossy().into_owned(),
            file.to_string_lossy().into_owned(),
            root.path().to_string_lossy().into_owned(),
            "program 'unbalanced".into(),
            "program 'two words'".into(),
        ]
        .into(),
        ..Inputs::default()
    };
    let mut args = args();
    args.id = Some("service".into());
    complete(
        &mut args,
        std::slice::from_ref(&existing),
        true,
        &mut prompts,
    )
    .unwrap();
    assert_eq!(args.id.as_deref(), Some("service"));
    assert_eq!(args.reload_cmd.as_deref(), Some("program 'two words'"));
    assert_eq!(prompts.errors.len(), 3);
    for id in ["nginx", "bad name"] {
        let mut duplicate = self::args();
        duplicate.id = Some(id.into());
        let mut prompts = Inputs::default();
        assert!(
            complete(
                &mut duplicate,
                std::slice::from_ref(&existing),
                true,
                &mut prompts
            )
            .is_err()
        );
        assert_eq!(prompts.asked, [] as [&str; 0]);
    }
    assert_eq!(std::fs::read_to_string(file).unwrap(), "untouched");
}

#[test]
fn explicit_directory_or_file_paths_skip_path_prompts_and_automation_never_prompts() {
    let root = tempfile::tempdir().unwrap();
    for exact in [false, true] {
        let mut args = args();
        args.id = Some("service".into());
        args.reload_cmd = Some("program arg".into());
        if exact {
            args.cert_path = Some(root.path().join("cert.pem"));
            args.key_path = Some(root.path().join("key.pem"));
        } else {
            args.target = Some(root.path().into());
        }
        let mut prompts = Inputs::default();
        complete(&mut args, &[], true, &mut prompts).unwrap();
        assert_eq!(prompts.asked, [] as [&str; 0]);
    }
    let mut args = args();
    args.id = Some("service".into());
    let mut prompts = Inputs::default();
    assert!(
        complete(&mut args, &[], false, &mut prompts)
            .unwrap_err()
            .to_string()
            .contains("--target")
    );
    args.target = Some(root.path().into());
    complete(&mut args, &[], false, &mut prompts).unwrap();
    assert_eq!(args.reload_cmd, None);
    assert_eq!(prompts.asked, [] as [&str; 0]);
}

#[test]
fn cancellation_at_each_prompt_returns_cancelled_without_creating_files() {
    let root = tempfile::tempdir().unwrap();
    for answers in [
        Vec::new(),
        vec![String::new()],
        vec![String::new(), root.path().to_string_lossy().into_owned()],
    ] {
        let mut prompts = Inputs {
            answers: answers.into(),
            ..Inputs::default()
        };
        let error = complete(&mut args(), &[], true, &mut prompts).unwrap_err();
        assert!(error.is::<crate::common::terminal::Canceled>());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn suggested_name_avoids_existing_default_and_can_be_changed_or_retried() {
    let root = tempfile::tempdir().unwrap();
    let existing = DeploymentBinding {
        permissions: aster_acme_cli_storage::issuance::DeploymentPermissions::default(),
        id: "default".into(),
        target: DeploymentTarget::Directory {
            path: root.path().into(),
        },
        reload_command: Vec::new(),
        timeout_seconds: 30,
        max_retries: 3,
        generation: None,
        phase: DeploymentPhase::Configured,
        attempts: 0,
        retry_failures: 0,
        retry_at: None,
        last_error: None,
    };
    for (answers, expected, errors) in [
        (vec![String::new()], "deploy-1", 0),
        (
            vec!["bad name".into(), "default".into(), "my-service".into()],
            "my-service",
            2,
        ),
    ] {
        let mut args = args();
        args.target = Some(root.path().into());
        args.reload_cmd = Some("program".into());
        let mut prompts = Inputs {
            answers: answers.into(),
            ..Inputs::default()
        };
        complete(
            &mut args,
            std::slice::from_ref(&existing),
            true,
            &mut prompts,
        )
        .unwrap();
        assert_eq!(args.id.as_deref(), Some(expected));
        assert_eq!(prompts.errors.len(), errors);
        assert!(
            prompts
                .defaults
                .iter()
                .all(|default| default.as_deref() == Some("deploy-1"))
        );
    }
}
