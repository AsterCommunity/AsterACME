//! Complete new-issuance inputs before account, storage or network side effects.
use crate::commands::cert::{
    args::IssueArgs,
    validation::{ValidationMethod, configuration},
};
use crate::common::{error::CliResult, session::OutputSession, terminal};
use aster_acme::identifier::DnsIdentifier;
use clap::ValueEnum as _;
use std::{net::SocketAddr, path::PathBuf};

pub(super) trait Prompts {
    fn text(&mut self, message: &str, default: Option<&str>) -> CliResult<String>;
    fn method(&mut self, choices: &[ValidationMethod]) -> CliResult<ValidationMethod>;
    fn invalid(&mut self, message: &str);
}

pub(super) struct TerminalPrompts<'a>(pub(super) &'a OutputSession);

impl Prompts for TerminalPrompts<'_> {
    fn text(&mut self, message: &str, default: Option<&str>) -> CliResult<String> {
        self.0.interaction_started();
        let prompt = inquire::Text::new(message).with_render_config(terminal::prompt_style(
            self.0.diagnostic_format().color,
            false,
        ));
        let prompt = if let Some(default) = default {
            prompt.with_default(default)
        } else {
            prompt
        };
        terminal::prompt_result(prompt.prompt())
    }

    fn method(&mut self, choices: &[ValidationMethod]) -> CliResult<ValidationMethod> {
        let labels = choices
            .iter()
            .map(|method| {
                let description = method
                    .to_possible_value()
                    .and_then(|value| value.get_help().map(ToString::to_string))
                    .unwrap_or_default();
                format!("{} — {description}", method.id())
            })
            .collect::<Vec<_>>();
        let index = terminal::select_index("Validation method:", &labels, 0, self.0)?;
        choices
            .get(index)
            .copied()
            .ok_or_else(|| "Invalid validation method selection.".into())
    }

    fn invalid(&mut self, message: &str) {
        self.0.context(&crate::common::output::safe(message));
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
    prompts: &mut dyn Prompts,
) -> CliResult<()> {
    if args.resume.is_some() {
        return Ok(());
    }
    if !interactive {
        let method = args.challenge.ok_or("Specify -c/--challenge <METHOD>; validation selection is interactive only on a terminal.")?;
        if args.domain.is_empty() {
            return Err(
                "Specify -d/--domain <DOMAIN> (repeat for SANs), or --resume <CERTIFICATE>.".into(),
            );
        }
        if method == ValidationMethod::DnsExternal {
            if args.webroot.is_some() || args.listen_address.is_some() {
                return Err("DNS external does not use --webroot or --listen-address.".into());
            }
            super::validation::external_configuration(args.provider.as_deref())?;
        } else {
            if args.provider.is_some() {
                return Err("--provider is only valid with -c dns_external.".into());
            }
            configuration(method, args.webroot.as_deref(), args.listen_address)?;
        }
        validate_domains(args, method)?;
        return Ok(());
    }
    if args.domain.is_empty() {
        args.domain = loop {
            let value = prompts.text("Domain names (space or comma separated):", None)?;
            match parse_domains(&value) {
                Ok(domains) => break domains,
                Err(error) => prompts.invalid(&error.to_string()),
            }
        };
    }
    let choices = ValidationMethod::value_variants()
        .iter()
        .copied()
        .filter(|method| {
            (args.provider.is_none() || *method == ValidationMethod::DnsExternal)
                && (args.webroot.is_none() || *method == ValidationMethod::Webroot)
                && (args.listen_address.is_none()
                    || matches!(
                        method,
                        ValidationMethod::Standalone | ValidationMethod::TlsAlpn
                    ))
                && (!args.domain.iter().any(DnsIdentifier::is_wildcard)
                    || method.kind().supports_wildcards())
        })
        .collect::<Vec<_>>();
    if args.challenge.is_none() {
        if choices.is_empty() {
            return Err("No validation method supports the supplied domains and method-specific parameters.".into());
        }
        args.challenge = Some(prompts.method(&choices)?);
    }
    let method = args.challenge.ok_or("Missing validation method.")?;
    validate_domains(args, method)?;
    if method == ValidationMethod::DnsExternal && args.provider.is_none() {
        args.provider = Some(prompts.text("DNS provider profile:", None)?);
    }
    if method == ValidationMethod::DnsExternal {
        super::validation::external_configuration(args.provider.as_deref())?;
    } else if args.provider.is_some() {
        return Err("--provider is only valid with -c dns_external.".into());
    }
    // Reject conflicting explicit options before asking for unrelated missing input.
    if args.webroot.is_some() || args.listen_address.is_some() {
        configuration(method, args.webroot.as_deref(), args.listen_address)?;
    }
    complete_method(args, method, prompts)?;
    if method == ValidationMethod::DnsExternal {
        super::validation::external_configuration(args.provider.as_deref())?;
    } else {
        configuration(method, args.webroot.as_deref(), args.listen_address)?;
    }
    Ok(())
}

fn validate_domains(args: &IssueArgs, method: ValidationMethod) -> CliResult<()> {
    if args.domain.iter().any(DnsIdentifier::is_wildcard) && !method.kind().supports_wildcards() {
        return Err(
            "Wildcard domains require DNS-01 or DNS-PERSIST-01; choose manual_dns, dns_external or dns_persist."
                .into(),
        );
    }
    Ok(())
}

fn complete_method(
    args: &mut IssueArgs,
    method: ValidationMethod,
    prompts: &mut dyn Prompts,
) -> CliResult<()> {
    match method {
        ValidationMethod::Webroot if args.webroot.is_none() => {
            args.webroot = Some(loop {
                let value = prompts.text("Webroot directory (existing):", None)?;
                let path = PathBuf::from(&value);
                if value.is_empty() {
                    prompts.invalid("Enter an existing webroot directory.");
                    continue;
                }
                match configuration(method, Some(&path), None) {
                    Ok(_) => break path,
                    Err(error) => prompts.invalid(&error.to_string()),
                }
            });
        }
        ValidationMethod::Standalone | ValidationMethod::TlsAlpn
            if args.listen_address.is_none() =>
        {
            let default = if method == ValidationMethod::Standalone {
                "0.0.0.0:80"
            } else {
                "0.0.0.0:443"
            };
            args.listen_address = Some(loop {
                let value = prompts.text("Validation listen address (IP:PORT):", Some(default))?;
                match value.parse::<SocketAddr>() {
                    Ok(address) if address.port() != 0 => break address,
                    _ => prompts.invalid("Enter an IPv4/IPv6 socket address with a nonzero port."),
                }
            });
        }
        ValidationMethod::ManualDns
        | ValidationMethod::DnsPersist
        | ValidationMethod::DnsExternal
        | ValidationMethod::ManualHttp
        | ValidationMethod::Webroot
        | ValidationMethod::Standalone
        | ValidationMethod::TlsAlpn => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests;
