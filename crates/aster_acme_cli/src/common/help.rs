//! Shared clap help palette.

use clap::builder::styling::{AnsiColor, Effects, Styles};

/// Apply one versioned product heading and bounded layout to every CLI help page.
pub(crate) fn configure(command: clap::Command) -> clap::Command {
    command
        .help_template(concat!(
            "AsterACME ",
            env!("CARGO_PKG_VERSION"),
            "\n{about}\n\n{usage-heading} {usage}\n\n{all-args}{after-help}"
        ))
        .max_term_width(100)
        .styles(help_styles())
        .mut_subcommands(configure)
}

pub(crate) fn help_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Green.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Yellow.on_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    #[test]
    fn root_and_nested_help_share_the_product_version_without_stale_commands() {
        let mut command = configure(crate::app::Args::command());
        let root = command.render_long_help().to_string();
        assert!(root.starts_with(concat!("AsterACME ", env!("CARGO_PKG_VERSION"), "\n")));
        assert!(root.contains("An ACME client for certificate issuance and management."));
        assert!(command.find_subcommand("order").is_none());
        let cert = command.find_subcommand_mut("cert").unwrap();
        let help = cert
            .find_subcommand_mut("show")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.starts_with(concat!("AsterACME ", env!("CARGO_PKG_VERSION"), "\n")));
        assert!(help.contains("[NAME]"));
    }
}
