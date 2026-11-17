//! New issuance completion: explicit inputs, each method, invalid input, scripts and cancellation.
use crate::commands::cert::{
    args::{CertCommand, ResumeTarget},
    interaction::*,
};
use clap::Parser as _;
use std::collections::VecDeque;

#[derive(Default)]
struct Inputs {
    answers: VecDeque<String>,
    selected: Option<ValidationMethod>,
    choices: Vec<ValidationMethod>,
    asked: Vec<String>,
    invalid: Vec<String>,
}
#[async_trait::async_trait(?Send)]
impl Prompts for Inputs {
    async fn provider(&mut self, _: Option<&std::path::Path>) -> CliResult<String> {
        self.asked.push("provider selection".into());
        self.answers
            .pop_front()
            .ok_or_else(|| Box::new(terminal::Canceled) as Box<dyn std::error::Error>)
    }
    fn text(&mut self, message: &str, default: Option<&str>) -> CliResult<String> {
        self.asked.push(message.into());
        let value = self
            .answers
            .pop_front()
            .ok_or_else(|| Box::new(terminal::Canceled) as Box<dyn std::error::Error>)?;
        Ok(if value.is_empty() {
            default.unwrap_or(&value).into()
        } else {
            value
        })
    }
    fn method(&mut self, choices: &[ValidationMethod]) -> CliResult<ValidationMethod> {
        self.choices = choices.to_vec();
        self.selected
            .filter(|value| choices.contains(value))
            .ok_or_else(|| Box::new(terminal::Canceled) as Box<dyn std::error::Error>)
    }
    fn invalid(&mut self, message: &str) {
        self.invalid.push(message.into());
    }
}
fn args(words: &[&str]) -> IssueArgs {
    let parsed = crate::app::Args::try_parse_from(
        ["aster-acme", "cert", "issue"]
            .into_iter()
            .chain(words.iter().copied()),
    )
    .unwrap();
    let crate::app::Command::Cert {
        command: CertCommand::Issue(args),
    } = parsed.command
    else {
        panic!("expected issue");
    };
    args
}

#[tokio::test]
async fn external_dns_selects_a_profile_only_when_missing_and_interactive() {
    let mut options = args(&["-c", "dns_provider", "-d", "example.com"]);
    let mut prompts = Inputs {
        answers: ["cloudflare".into()].into(),
        ..Inputs::default()
    };
    complete(&mut options, true, &mut prompts).await.unwrap();
    assert_eq!(options.provider.as_deref(), Some("cloudflare"));
    assert_eq!(prompts.asked, ["provider selection"]);
    let mut prompts = Inputs::default();
    complete(&mut options, true, &mut prompts).await.unwrap();
    assert_eq!(prompts.asked, Vec::<String>::new());
    let mut options = args(&["-c", "dns_provider", "-d", "example.com"]);
    assert!(complete(&mut options, false, &mut prompts).await.is_err());
    assert_eq!(prompts.asked, Vec::<String>::new());
    assert!(
        complete(&mut options, true, &mut prompts)
            .await
            .unwrap_err()
            .is::<terminal::Canceled>()
    );
}

#[tokio::test]
async fn bare_issue_collects_domains_and_each_methods_required_inputs() {
    let root = tempfile::tempdir().unwrap();
    for method in ValidationMethod::value_variants()
        .iter()
        .filter(|method| **method != ValidationMethod::DnsProvider)
    {
        let mut args = args(&[]);
        let mut inputs = Inputs {
            selected: Some(*method),
            answers: ["Example.com, www.example.com".into()].into(),
            ..Inputs::default()
        };
        match method {
            ValidationMethod::Webroot => inputs
                .answers
                .push_back(root.path().to_string_lossy().into_owned()),
            ValidationMethod::Standalone | ValidationMethod::TlsAlpn => {
                inputs.answers.push_back(String::new());
            }
            ValidationMethod::DnsProvider
            | ValidationMethod::ManualDns
            | ValidationMethod::DnsPersist
            | ValidationMethod::ManualHttp => {}
        }
        complete(&mut args, true, &mut inputs).await.unwrap();
        assert_eq!(args.challenge, Some(*method));
        assert_eq!(
            args.domain
                .iter()
                .map(DnsIdentifier::value)
                .collect::<Vec<_>>(),
            ["example.com", "www.example.com"]
        );
        configuration(*method, args.webroot.as_deref(), args.listen_address).unwrap();
        match method {
            ValidationMethod::Standalone => {
                assert_eq!(args.listen_address.unwrap().to_string(), "0.0.0.0:80");
            }
            ValidationMethod::TlsAlpn => {
                assert_eq!(args.listen_address.unwrap().to_string(), "0.0.0.0:443");
            }
            ValidationMethod::Webroot => assert_eq!(args.webroot.as_deref(), Some(root.path())),
            ValidationMethod::DnsProvider
            | ValidationMethod::ManualDns
            | ValidationMethod::DnsPersist
            | ValidationMethod::ManualHttp => {
                assert_eq!(inputs.asked.len(), 1);
            }
        }
        assert_eq!(inputs.choices.len(), 7);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn explicit_input_skips_every_prompt_and_resume_never_asks() {
    let root = tempfile::tempdir().unwrap();
    for method in ValidationMethod::value_variants()
        .iter()
        .filter(|method| **method != ValidationMethod::DnsProvider)
    {
        let mut words = vec!["-c", method.id(), "-d", "example.com"];
        if *method == ValidationMethod::Webroot {
            words.extend(["-w", root.path().to_str().unwrap()]);
        }
        if matches!(
            method,
            ValidationMethod::Standalone | ValidationMethod::TlsAlpn
        ) {
            words.extend(["--listen-address", "[::1]:8443"]);
        }
        for interactive in [false, true] {
            let mut args = args(&words);
            let mut prompts = Inputs::default();
            complete(&mut args, interactive, &mut prompts)
                .await
                .unwrap();
            assert_eq!(prompts.asked, [] as [&str; 0]);
            assert_eq!(prompts.choices, [] as [ValidationMethod; 0]);
        }
    }
    for interactive in [false, true] {
        let mut args = args(&["--resume"]);
        assert_eq!(args.resume, Some(ResumeTarget::Choose));
        complete(&mut args, interactive, &mut Inputs::default())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn method_choices_respect_wildcards_and_supplied_configuration() {
    let root = tempfile::tempdir().unwrap();
    for (words, expected) in [
        (
            vec!["-d", "*.example.com"],
            vec![
                ValidationMethod::DnsProvider,
                ValidationMethod::ManualDns,
                ValidationMethod::DnsPersist,
            ],
        ),
        (
            vec!["-d", "example.com", "-w", root.path().to_str().unwrap()],
            vec![ValidationMethod::Webroot],
        ),
        (
            vec!["-d", "example.com", "--listen-address", "[::1]:443"],
            vec![ValidationMethod::Standalone, ValidationMethod::TlsAlpn],
        ),
    ] {
        let mut args = args(&words);
        let mut prompts = Inputs {
            selected: Some(expected[0]),
            answers: ["cloudflare".into()].into(),
            ..Inputs::default()
        };
        complete(&mut args, true, &mut prompts).await.unwrap();
        assert_eq!(prompts.choices, expected);
    }
    for words in [
        vec!["-d", "*.example.com", "-c", "standalone"],
        vec!["-d", "*.example.com", "-w", root.path().to_str().unwrap()],
        vec![
            "-d",
            "example.com",
            "-c",
            "manual_dns",
            "--listen-address",
            "127.0.0.1:80",
        ],
    ] {
        let mut prompts = Inputs::default();
        assert!(
            complete(&mut args(&words), true, &mut prompts)
                .await
                .is_err()
        );
        assert_eq!(prompts.asked, [] as [&str; 0]);
    }
}

#[tokio::test]
async fn invalid_domains_directories_and_addresses_retry_with_no_publication() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("file");
    std::fs::write(&file, "keep").unwrap();
    let mut webroot = args(&["-c", "webroot"]);
    let mut prompts = Inputs {
        answers: [
            String::new(),
            "example.com EXAMPLE.com".into(),
            "example.com".into(),
            String::new(),
            root.path().join("missing").to_string_lossy().into_owned(),
            file.to_string_lossy().into_owned(),
            root.path().to_string_lossy().into_owned(),
        ]
        .into(),
        ..Inputs::default()
    };
    complete(&mut webroot, true, &mut prompts).await.unwrap();
    assert_eq!(prompts.invalid.len(), 5);
    let mut standalone = args(&["-c", "standalone", "-d", "example.com"]);
    let mut prompts = Inputs {
        answers: ["invalid".into(), "127.0.0.1:0".into(), "[::]:8080".into()].into(),
        ..Inputs::default()
    };
    complete(&mut standalone, true, &mut prompts).await.unwrap();
    assert_eq!(prompts.invalid.len(), 2);
    assert_eq!(standalone.listen_address.unwrap().to_string(), "[::]:8080");
    assert_eq!(std::fs::read_to_string(file).unwrap(), "keep");
}

#[tokio::test]
async fn scripts_reject_missing_inputs_without_asking_and_listener_defaults_still_apply() {
    for words in [
        vec![],
        vec!["-d", "example.com", "--yes"],
        vec!["-c", "manual_dns"],
        vec!["-c", "webroot", "-d", "example.com"],
    ] {
        let mut prompts = Inputs::default();
        assert!(
            complete(&mut args(&words), false, &mut prompts)
                .await
                .is_err()
        );
        assert_eq!(prompts.asked, [] as [&str; 0]);
        assert_eq!(prompts.choices, [] as [ValidationMethod; 0]);
    }
    for method in ["standalone", "tls_alpn"] {
        complete(
            &mut args(&["-c", method, "-d", "example.com"]),
            false,
            &mut Inputs::default(),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn cancellation_at_domains_method_or_method_configuration_is_preserved() {
    for (words, prompts) in [
        (vec![], Inputs::default()),
        (vec!["-d", "example.com"], Inputs::default()),
        (
            vec!["-c", "webroot", "-d", "example.com"],
            Inputs::default(),
        ),
        (
            vec!["-c", "standalone", "-d", "example.com"],
            Inputs::default(),
        ),
        (
            vec!["-c", "tls_alpn", "-d", "example.com"],
            Inputs::default(),
        ),
    ] {
        let mut prompts = prompts;
        let error = complete(&mut args(&words), true, &mut prompts)
            .await
            .unwrap_err();
        assert!(error.is::<terminal::Canceled>());
    }
    for value in [
        "",
        "bad name/",
        "example.com EXAMPLE.com",
        &vec!["x.example"; 101].join(" "),
    ] {
        assert!(parse_domains(value).is_err());
    }
}

#[test]
fn complete_rejects_noninteractive_missing_inputs_before_initializing_the_data_directory() {
    use crate::common::context::CommandContext;
    let root = tempfile::tempdir().unwrap();
    for words in [
        vec![],
        vec!["-d", "example.com"],
        vec!["-c", "webroot", "-d", "example.com"],
    ] {
        let mut options = args(&words);
        let data_dir = root.path().join("never-created");
        options.run.local.data_dir = Some(data_dir.clone());
        options.run.local.json = true;
        let context = CommandContext::new(true);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(crate::commands::cert::execute::execute(
            CertCommand::Issue(options),
            &context,
        ));
        assert!(result.is_err());
        assert!(!data_dir.exists());
    }
}

#[tokio::test]
async fn dns_target_mappings_validate_multi_domain_and_reject_conflicts() {
    let good = [
        "-d",
        "example.com",
        "-d",
        "*.example.com",
        "-d",
        "other.net",
        "-c",
        "dns_provider",
        "--provider",
        "cf",
        "--dns-target",
        "example.com=verify.validation.net",
        "--dns-target",
        "*.example.com=verify.validation.net",
        "--dns-target",
        "other.net=verify.validation.net",
    ];
    let mut options = args(&good);
    complete(&mut options, false, &mut Inputs::default())
        .await
        .unwrap();
    let parsed =
        crate::commands::cert::validation::parse_dns_targets(&options.dns_targets).unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed["example.com"], "verify.validation.net.");
    assert_eq!(parsed["*.example.com"], "verify.validation.net.");
    for values in [
        vec![
            "example.com=verify.validation.net",
            "EXAMPLE.COM.=other.net",
        ],
        vec![
            "example.com=verify.validation.net",
            "*.example.com=other.net",
        ],
        vec!["bad..name=verify.validation.net"],
        vec!["example.com=bad..name"],
        vec!["example.com"],
        vec!["_acme-challenge.example.com=target.net"],
        vec!["foo.*.example.com=target.net"],
    ] {
        assert!(
            crate::commands::cert::validation::parse_dns_targets(
                &values.into_iter().map(str::to_owned).collect::<Vec<_>>()
            )
            .is_err()
        );
    }
    let mut bad = args(&[
        "-d",
        "example.com",
        "-c",
        "dns_provider",
        "--provider",
        "cf",
        "--dns-target",
        "*.example.com=verify.validation.net",
    ]);
    assert!(
        complete(&mut bad, false, &mut Inputs::default())
            .await
            .is_err()
    );
    let mut wrong_method = args(&[
        "-d",
        "example.com",
        "-c",
        "manual_dns",
        "--dns-target",
        "example.com=verify.validation.net",
    ]);
    assert!(
        complete(&mut wrong_method, false, &mut Inputs::default())
            .await
            .is_err()
    );
}
