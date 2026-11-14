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
    use crate::common::help::*;
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

    #[test]
    fn every_command_supports_standard_flag_help_and_help_paths() {
        let root = configure(crate::app::Args::command());
        let mut paths = vec![
            vec![],
            vec!["account"],
            vec!["cert"],
            vec!["version"],
            vec!["daemon"],
        ];
        for group in ["account", "cert", "daemon"] {
            paths.extend(
                root.find_subcommand(group)
                    .unwrap()
                    .get_subcommands()
                    .map(|command| vec![group, command.get_name()]),
            );
        }
        for path in paths {
            let mut native = vec!["aster-acme", "help"];
            native.extend_from_slice(&path);
            let native = root.clone().try_get_matches_from(native).unwrap_err();
            assert_eq!(native.kind(), clap::error::ErrorKind::DisplayHelp);
            assert!(native.to_string().starts_with("AsterACME "));
            for flag in ["-h", "--help"] {
                let mut direct = vec!["aster-acme"];
                direct.extend_from_slice(&path);
                direct.push(flag);
                let direct = root.clone().try_get_matches_from(direct).unwrap_err();
                assert_eq!(direct.kind(), clap::error::ErrorKind::DisplayHelp);
                assert!(direct.to_string().starts_with("AsterACME "));
            }
        }
    }

    #[test]
    fn a_positional_account_named_help_remains_an_account_target() {
        let command = configure(crate::app::Args::command());
        let matches = command
            .clone()
            .try_get_matches_from(["aster-acme", "account", "rotate-key", "help"])
            .unwrap();
        let target = matches
            .subcommand_matches("account")
            .unwrap()
            .subcommand_matches("rotate-key")
            .unwrap();
        assert_eq!(
            target
                .get_one::<String>("positional_name")
                .map(String::as_str),
            Some("help")
        );
        let error = command
            .try_get_matches_from(["aster-acme", "account", "help", "rotate-key", "--help"])
            .unwrap_err();
        assert_ne!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn debug_is_a_cross_cutting_diagnostic_flag_not_an_account_or_validation_override() {
        use clap::Parser;
        for args in [
            vec!["aster-acme", "--debug", "cert", "issue", "--resume", "web"],
            vec!["aster-acme", "cert", "issue", "--resume", "web", "--debug"],
            vec!["aster-acme", "account", "list", "--json", "--debug"],
            vec!["aster-acme", "version", "--debug"],
        ] {
            assert!(crate::app::Args::try_parse_from(args).unwrap().debug);
        }
    }
}
