//! Complete omitted certificate input only on an interactive terminal.
use super::args::IssueArgs;
use crate::common::{error::CliResult, terminal::prompt_result};
use aster_acme::identifier::DnsIdentifier;

pub(super) trait DomainPrompts {
    fn domains(&mut self) -> CliResult<String>;
}
pub(super) struct TerminalDomains<'a>(pub(super) &'a crate::common::session::OutputSession);
impl DomainPrompts for TerminalDomains<'_> {
    fn domains(&mut self) -> CliResult<String> {
        self.0.interaction_started();
        prompt_result(
            inquire::Text::new("Domain names:")
                .with_render_config(crate::common::terminal::prompt_style(
                    self.0.diagnostic_format().color,
                    false,
                ))
                .with_placeholder("example.com *.example.com")
                .with_help_message(
                    "Separate domains with spaces or commas; the first is the primary domain.",
                )
                .with_validator(|value: &str| {
                    Ok(match parse_domains(value) {
                        Ok(_) => inquire::validator::Validation::Valid,
                        Err(error) => {
                            inquire::validator::Validation::Invalid(error.to_string().into())
                        }
                    })
                })
                .prompt(),
        )
    }
}

fn parse_domains(value: &str) -> CliResult<Vec<DnsIdentifier>> {
    let domains = value
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|value| !value.is_empty())
        .map(DnsIdentifier::new)
        .collect::<Result<Vec<_>, _>>()?;
    if domains.is_empty()
        || domains.len() > 100
        || domains
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != domains.len()
    {
        return Err("Enter 1–100 distinct DNS names; the first is the primary domain.".into());
    }
    Ok(domains)
}

pub(super) fn complete(
    args: &mut IssueArgs,
    interactive: bool,
    prompts: &mut dyn DomainPrompts,
) -> CliResult<()> {
    if args.resume.is_some() || !args.domain.is_empty() {
        return Ok(());
    }
    if !interactive {
        return Err("Specify -d/--domain <DOMAIN> (repeat for SANs), or --resume <CERTIFICATE>. Domain input is interactive only on a terminal.".into());
    }
    args.domain = parse_domains(&prompts.domains()?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    struct Prompts(Option<&'static str>);
    impl DomainPrompts for Prompts {
        fn domains(&mut self) -> CliResult<String> {
            self.0.take().map(str::to_owned).ok_or_else(|| {
                Box::new(crate::common::terminal::Canceled) as Box<dyn std::error::Error>
            })
        }
    }
    fn arguments() -> IssueArgs {
        let parsed =
            crate::app::Args::parse_from(["aster-acme", "cert", "issue", "-c", "manual_dns"]);
        let crate::app::Command::Cert { command } = parsed.command else {
            panic!("expected cert");
        };
        let super::super::args::CertCommand::Issue(args) = command else {
            panic!("expected issue");
        };
        args
    }
    #[test]
    fn omitted_domains_prompt_only_on_terminal_and_keep_primary_order() {
        let mut args = arguments();
        assert!(complete(&mut args, false, &mut Prompts(Some("must-not-be-used"))).is_err());
        complete(
            &mut args,
            true,
            &mut Prompts(Some("Example.com, *.example.com")),
        )
        .unwrap();
        assert_eq!(
            args.domain
                .iter()
                .map(DnsIdentifier::value)
                .collect::<Vec<_>>(),
            ["example.com", "*.example.com"]
        );
        complete(&mut args, true, &mut Prompts(None)).unwrap();
        for value in ["", "bad name/", "example.com EXAMPLE.com"] {
            assert!(parse_domains(value).is_err());
        }
        assert!(
            complete(&mut arguments(), true, &mut Prompts(None))
                .unwrap_err()
                .is::<crate::common::terminal::Canceled>()
        );
        let mut resume = arguments();
        resume.resume = Some(super::super::args::ResumeTarget::Named(
            "example.com".into(),
        ));
        complete(&mut resume, false, &mut Prompts(None)).unwrap();
    }
}
