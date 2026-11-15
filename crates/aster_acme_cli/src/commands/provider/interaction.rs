//! Fill missing provider registration fields without changing the execution path.
use crate::commands::provider::{AddArgs, validate_executable};
use crate::common::{error::CliResult, output, session::OutputSession, terminal};

pub(super) mod update;

#[derive(Debug)]
pub(super) struct Back;

impl std::fmt::Display for Back {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Return to the previous menu")
    }
}

impl std::error::Error for Back {}

pub(super) trait Prompts {
    fn text(&mut self, message: &str, allow_back: bool) -> CliResult<String>;
    fn invalid(&mut self, message: &str);
    fn select(&mut self, message: &str, choices: &[String]) -> CliResult<usize>;
    fn review(
        &mut self,
        name: &str,
        path: &std::path::Path,
        profile: &aster_acme_cli_storage::provider::ProviderProfile,
    ) -> CliResult<()>;
}

pub(super) struct TerminalPrompts<'a>(pub(super) &'a OutputSession);
impl Prompts for TerminalPrompts<'_> {
    fn select(&mut self, message: &str, choices: &[String]) -> CliResult<usize> {
        terminal::select_index_or_back(message, choices, 0, self.0)?
            .ok_or_else(|| Box::new(Back) as Box<dyn std::error::Error>)
    }
    fn review(
        &mut self,
        name: &str,
        path: &std::path::Path,
        profile: &aster_acme_cli_storage::provider::ProviderProfile,
    ) -> CliResult<()> {
        let view = crate::commands::provider::view(name.into(), path.into(), profile.clone());
        self.0.context(
            &crate::commands::provider::detail_lines(&view, self.0.diagnostic_format().color)?
                .join("\n"),
        );
        Ok(())
    }
    fn text(&mut self, message: &str, allow_back: bool) -> CliResult<String> {
        self.0.interaction_started();
        let result = inquire::Text::new(message)
            .with_render_config(terminal::prompt_style(
                self.0.diagnostic_format().color,
                false,
            ))
            .prompt();
        match result {
            Err(inquire::InquireError::OperationCanceled) if allow_back => Err(Box::new(Back)),
            result => terminal::prompt_result(result),
        }
    }
    fn invalid(&mut self, message: &str) {
        self.0.context(&output::safe(message));
    }
}

pub(super) fn complete_add(
    args: &mut AddArgs,
    names: &[String],
    interactive: bool,
    prompts: &mut dyn Prompts,
) -> CliResult<()> {
    // Explicit invalid input fails before prompting for unrelated missing fields.
    if let Some(name) = &args.name {
        validate_name(name, names)?;
    }
    if let Some(executable) = &args.exec {
        validate_executable(executable)?;
    }
    if !interactive && (args.name.is_none() || args.exec.is_none()) {
        return Err("Specify provider add <NAME> --exec <PATH>; missing fields can only be entered on a terminal.".into());
    }
    if args.name.is_none() {
        args.name = Some(loop {
            let name = prompts.text("DNS provider profile name:", false)?;
            match validate_name(&name, names) {
                Ok(()) => break name,
                Err(error) => prompts.invalid(&error.to_string()),
            }
        });
    }
    if args.exec.is_none() {
        args.exec = Some(loop {
            let executable =
                std::path::PathBuf::from(prompts.text("Provider executable path:", false)?);
            match validate_executable(&executable) {
                Ok(()) => break executable,
                Err(error) => prompts.invalid(&error.to_string()),
            }
        });
    }
    Ok(())
}

fn validate_name(name: &str, names: &[String]) -> CliResult<()> {
    crate::common::args::parse_account_name(name)?;
    if names.iter().any(|saved| saved == name) {
        return Err(
            "Provider profile already exists; choose another name or use provider update.".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::commands::provider::{
        AddArgs,
        interaction::{Prompts, complete_add},
    };
    use crate::common::{args::LocalArgs, error::CliResult, terminal::Canceled};
    use std::collections::VecDeque;

    #[derive(Default)]
    struct Inputs {
        answers: VecDeque<String>,
        asked: Vec<String>,
        invalid: Vec<String>,
    }
    impl Prompts for Inputs {
        fn select(&mut self, _: &str, _: &[String]) -> CliResult<usize> {
            panic!("add must not select editor actions");
        }
        fn review(
            &mut self,
            _: &str,
            _: &std::path::Path,
            _: &aster_acme_cli_storage::provider::ProviderProfile,
        ) -> CliResult<()> {
            panic!("add must not open the editor");
        }
        fn text(&mut self, message: &str, _: bool) -> CliResult<String> {
            self.asked.push(message.into());
            self.answers
                .pop_front()
                .ok_or_else(|| Box::new(Canceled) as Box<dyn std::error::Error>)
        }
        fn invalid(&mut self, message: &str) {
            self.invalid.push(message.into());
        }
    }
    fn args() -> AddArgs {
        AddArgs {
            name: None,
            exec: None,
            args: vec!["script.py".into()],
            allowed_zones: vec!["example.com".into()],
            local: LocalArgs::default(),
        }
    }
    #[test]
    fn add_collects_missing_fields_retries_invalid_inputs_and_preserves_options() {
        let executable = std::env::current_exe().unwrap();
        let mut args = args();
        let mut inputs = Inputs {
            answers: [
                String::new(),
                "../bad".into(),
                "taken".into(),
                "new".into(),
                "relative/path".into(),
                executable.to_string_lossy().into_owned(),
            ]
            .into(),
            ..Inputs::default()
        };
        complete_add(&mut args, &["taken".into()], true, &mut inputs).unwrap();
        assert_eq!(args.name.as_deref(), Some("new"));
        assert_eq!(args.exec, Some(executable));
        assert_eq!(inputs.invalid.len(), 4);
        assert_eq!(args.args, ["script.py"]);
        assert_eq!(args.allowed_zones, ["example.com"]);
        for interactive in [false, true] {
            complete_add(&mut args, &[], interactive, &mut Inputs::default()).unwrap();
        }
    }
    #[test]
    fn add_requires_missing_fields_in_automation_and_cancellation_has_no_writes() {
        for name in [None, Some("new".into())] {
            let mut args = args();
            args.name = name;
            let mut inputs = Inputs::default();
            assert!(complete_add(&mut args, &[], false, &mut inputs).is_err());
            assert_eq!(inputs.asked, Vec::<String>::new());
            assert!(
                complete_add(&mut args, &[], true, &mut inputs)
                    .unwrap_err()
                    .is::<Canceled>()
            );
        }
        let mut args = args();
        args.name = Some("taken".into());
        let mut inputs = Inputs::default();
        assert!(complete_add(&mut args, &["taken".into()], true, &mut inputs).is_err());
        assert_eq!(inputs.asked, Vec::<String>::new());
        args.name = None;
        args.exec = Some("relative".into());
        assert!(complete_add(&mut args, &[], true, &mut inputs).is_err());
        assert_eq!(inputs.asked, Vec::<String>::new());
    }

    #[test]
    fn executable_validation_rejects_missing_files_directories_and_unix_nonexecutables() {
        let root = tempfile::tempdir().unwrap();
        assert!(crate::commands::provider::validate_executable(root.path()).is_err());
        assert!(
            crate::commands::provider::validate_executable(&root.path().join("missing")).is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let file = root.path().join("not-executable");
            std::fs::write(&file, "fixture").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(crate::commands::provider::validate_executable(&file).is_err());
        }
    }
}
