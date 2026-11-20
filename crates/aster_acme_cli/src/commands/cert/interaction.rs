//! Complete new-issuance inputs before account, storage or network side effects.
use crate::commands::cert::{
    args::IssueArgs,
    validation::{ValidationMethod, configuration},
};
use crate::common::{error::CliResult, session::OutputSession, terminal};
use aster_acme::identifier::{DnsIdentifier, IpIdentifier};
use clap::ValueEnum as _;
use std::{net::SocketAddr, path::PathBuf};

#[async_trait::async_trait(?Send)]
pub(super) trait Prompts {
    fn text(&mut self, message: &str, default: Option<&str>) -> CliResult<String>;
    fn method(&mut self, choices: &[ValidationMethod]) -> CliResult<ValidationMethod>;
    fn invalid(&mut self, message: &str);
    async fn provider(&mut self, data_dir: Option<&std::path::Path>) -> CliResult<String>;
}

pub(super) struct TerminalPrompts<'a>(pub(super) &'a OutputSession);

#[async_trait::async_trait(?Send)]
impl Prompts for TerminalPrompts<'_> {
    async fn provider(&mut self, data_dir: Option<&std::path::Path>) -> CliResult<String> {
        let root = data_dir.map_or_else(crate::config::default_data_dir, |root| {
            Ok(root.to_path_buf())
        })?;
        crate::commands::provider::execute::select(&root, self.0).await
    }
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

/// Split interactive input into DNS and IP identifiers. Each token's kind is
/// unambiguous: only exact IP literals become IP identifiers, and dotted-quad
/// spellings that are neither canonical IPv4 nor ordinary names are rejected
/// with guidance instead of a silent reinterpretation.
fn parse_identifiers(value: &str) -> CliResult<(Vec<DnsIdentifier>, Vec<IpIdentifier>)> {
    let tokens = value
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let mut domains = Vec::new();
    let mut addresses = Vec::new();
    for token in tokens {
        if let Ok(address) = IpIdentifier::new(token) {
            addresses.push(address);
            continue;
        }
        match DnsIdentifier::new(token) {
            Ok(domain) => domains.push(domain),
            Err(error) => {
                if looks_like_address(token) {
                    return Err(format!(
                        "{token} looks like an IP address but is not a canonical IPv4/IPv6 literal (RFC 8738); enter it exactly as an address or use a DNS name"
                    )
                    .into());
                }
                return Err(error.to_string().into());
            }
        }
    }
    let total = domains.len() + addresses.len();
    if total == 0
        || total > 100
        || domains
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != domains.len()
        || addresses
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != addresses.len()
    {
        return Err(
            "Enter 1–100 distinct DNS names or bare IP addresses; the first is the primary identifier."
                .into(),
        );
    }
    Ok((domains, addresses))
}

/// Dotted-quad or colon-bearing input that the strict parsers both rejected.
fn looks_like_address(token: &str) -> bool {
    token.contains(':')
        || (token.split('.').count() == 4
            && token
                .split('.')
                .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit())))
}

pub(super) async fn complete(
    args: &mut IssueArgs,
    interactive: bool,
    prompts: &mut dyn Prompts,
) -> CliResult<()> {
    if args.resume.is_some() {
        return Ok(());
    }
    if !interactive {
        let method = args.challenge.ok_or("Specify -c/--challenge <METHOD>; validation selection is interactive only on a terminal.")?;
        if args.domain.is_empty() && args.ip.is_empty() {
            return Err("Specify -d/--domain <DOMAIN> or --ip <ADDRESS> (repeat for SANs), or --resume <CERTIFICATE>.".into());
        }
        if method == ValidationMethod::DnsProvider {
            if args.webroot.is_some() || args.listen_address.is_some() {
                return Err(
                    "DNS provider validation does not use --webroot or --listen-address.".into(),
                );
            }
            crate::commands::cert::validation::provider::provider_configuration(
                args.provider.as_deref(),
            )?;
        } else {
            if args.provider.is_some() || !args.dns_targets.is_empty() {
                return Err(
                    "--provider and --dns-target are only valid with -c dns_provider.".into(),
                );
            }
            configuration(method, args.webroot.as_deref(), args.listen_address)?;
        }
        validate_identifiers(args, method)?;
        validate_dns_targets(args)?;
        return Ok(());
    }
    if args.domain.is_empty() && args.ip.is_empty() {
        let (domains, addresses) = loop {
            let value = prompts.text(
                "DNS names or IP addresses (space or comma separated):",
                None,
            )?;
            match parse_identifiers(&value) {
                Ok(parsed) => break parsed,
                Err(error) => prompts.invalid(&error.to_string()),
            }
        };
        args.domain = domains;
        args.ip = addresses;
    }
    validate_dns_targets(args)?;
    let choices = ValidationMethod::value_variants()
        .iter()
        .copied()
        .filter(|method| {
            ((args.provider.is_none() && args.dns_targets.is_empty())
                || *method == ValidationMethod::DnsProvider)
                && (args.webroot.is_none() || *method == ValidationMethod::Webroot)
                && (args.listen_address.is_none()
                    || matches!(
                        method,
                        ValidationMethod::Standalone | ValidationMethod::TlsAlpn
                    ))
                && (!args.domain.iter().any(DnsIdentifier::is_wildcard)
                    || method.kind().supports_wildcards())
                && (args.ip.is_empty() || method.kind().supports_ip_identifiers())
        })
        .collect::<Vec<_>>();
    if args.challenge.is_none() {
        if choices.is_empty() {
            return Err("No validation method supports the supplied identifiers and method-specific parameters.".into());
        }
        args.challenge = Some(prompts.method(&choices)?);
    }
    let method = args.challenge.ok_or("Missing validation method.")?;
    validate_identifiers(args, method)?;
    if method == ValidationMethod::DnsProvider && args.provider.is_none() {
        args.provider = Some(prompts.provider(args.run.local.data_dir.as_deref()).await?);
    }
    if method == ValidationMethod::DnsProvider {
        crate::commands::cert::validation::provider::provider_configuration(
            args.provider.as_deref(),
        )?;
    } else if args.provider.is_some() || !args.dns_targets.is_empty() {
        return Err("--provider and --dns-target are only valid with -c dns_provider.".into());
    }
    // Reject conflicting explicit options before asking for unrelated missing input.
    if args.webroot.is_some() || args.listen_address.is_some() {
        configuration(method, args.webroot.as_deref(), args.listen_address)?;
    }
    complete_method(args, method, prompts)?;
    if method == ValidationMethod::DnsProvider {
        crate::commands::cert::validation::provider::provider_configuration(
            args.provider.as_deref(),
        )?;
    } else {
        configuration(method, args.webroot.as_deref(), args.listen_address)?;
    }
    Ok(())
}

fn validate_dns_targets(args: &IssueArgs) -> CliResult<()> {
    let targets =
        crate::commands::cert::validation::provider::parse_dns_targets(&args.dns_targets)?;
    for domain in targets.keys() {
        if !args
            .domain
            .iter()
            .any(|identifier| identifier.value() == *domain)
        {
            return Err("DNS target domain does not match a requested domain".into());
        }
    }
    Ok(())
}

fn validate_identifiers(args: &IssueArgs, method: ValidationMethod) -> CliResult<()> {
    if args.domain.iter().any(DnsIdentifier::is_wildcard) && !method.kind().supports_wildcards() {
        return Err(
            "Wildcard domains require DNS-01 or DNS-PERSIST-01; choose manual_dns, dns_provider or dns_persist."
                .into(),
        );
    }
    if !args.ip.is_empty() && !method.kind().supports_ip_identifiers() {
        return Err(
            "IP identifiers require HTTP-01 or TLS-ALPN-01 (RFC 8738); choose manual_http, webroot, standalone or tls_alpn."
                .into(),
        );
    }
    let total = args.domain.len() + args.ip.len();
    if total == 0 || total > 100 {
        return Err("Enter 1–100 identifiers in total across -d/--domain and --ip.".into());
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
            let port = if method == ValidationMethod::Standalone {
                80
            } else {
                443
            };
            // IPv6-only identifier sets cannot be served by an IPv4 wildcard
            // bind; default to the dual-stack IPv6 address for those.
            let default = if !args.ip.is_empty()
                && args.domain.is_empty()
                && args.ip.iter().all(|ip| ip.address().is_ipv6())
            {
                format!("[::]:{port}")
            } else {
                format!("0.0.0.0:{port}")
            };
            args.listen_address = Some(loop {
                let value = prompts.text(
                    "Validation listen address (IP:PORT):",
                    Some(default.as_str()),
                )?;
                match value.parse::<SocketAddr>() {
                    Ok(address) if address.port() != 0 => break address,
                    _ => prompts.invalid("Enter an IPv4/IPv6 socket address with a nonzero port."),
                }
            });
        }
        ValidationMethod::ManualDns
        | ValidationMethod::DnsPersist
        | ValidationMethod::DnsProvider
        | ValidationMethod::ManualHttp
        | ValidationMethod::Webroot
        | ValidationMethod::Standalone
        | ValidationMethod::TlsAlpn => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests;
