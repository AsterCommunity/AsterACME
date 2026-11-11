//! Shared human output policy: terminal colors, untrusted text, fields and hints.

/// Terminal palette; ANSI escape codes belong only to this rendering boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Style {
    Plain,
    Red,
    Green,
    Yellow,
    Blue,
    Cyan,
    BoldRed,
    BoldGreen,
    BoldYellow,
    BoldCyan,
}

impl Style {
    const fn ansi(self) -> &'static str {
        match self {
            Self::Plain => "",
            Self::Red => "31",
            Self::Green => "32",
            Self::Yellow => "33",
            Self::Blue => "34",
            Self::Cyan => "36",
            Self::BoldRed => "1;31",
            Self::BoldGreen => "1;32",
            Self::BoldYellow => "1;33",
            Self::BoldCyan => "1;36",
        }
    }
}

pub(crate) fn colors(terminal: bool) -> bool {
    terminal
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}

pub(crate) fn styled(text: &str, style: Style, enabled: bool) -> String {
    if enabled && !matches!(style, Style::Plain) {
        format!("\x1b[{}m{text}\x1b[0m", style.ansi())
    } else {
        text.to_owned()
    }
}

/// CA details and configured names are untrusted terminal text, including on errors.
pub(crate) fn safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// A separator is useful only when a report follows human progress output.
#[derive(Clone, Copy)]
pub(crate) enum ResultPreceding {
    None,
    Progress,
}

/// Separate a foreground progress stream from its final report; machine output
/// remains exactly one document with no human separators.
pub(crate) fn print_result(text: &str, json: bool, preceding: ResultPreceding) {
    if !json && matches!(preceding, ResultPreceding::Progress) {
        eprintln!();
    }
    println!("{text}");
}

/// Presentation hint; paint only the label so the command text stays easy to copy.
pub(crate) fn tips(message: &str, color: bool) -> String {
    format!("{} {}", styled("Tips:", Style::Blue, color), safe(message))
}

/// Shared detail-field layout; callers can style already escaped semantic values.
pub(crate) fn field(label: &str, value: &str, color: bool) -> String {
    use unicode_width::UnicodeWidthStr;
    let padding = " ".repeat(25_usize.saturating_sub(label.width()));
    format!("  {}{padding}  {value}", styled(label, Style::Cyan, color))
}

/// Confirmation blocks share the same field alignment and warning policy as details.
pub(crate) fn confirmation(details: &str, color: bool) -> String {
    details
        .lines()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                return styled(&safe(line), Style::BoldYellow, color);
            }
            if let Some((label, value)) = line
                .strip_prefix("  ")
                .and_then(|line| line.split_once(": "))
            {
                return field(&format!("{label}:"), &safe(value), color);
            }
            styled(&safe(line), Style::Yellow, color && !line.is_empty())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tips_style_only_the_label_and_plain_output_remains_copyable() {
        assert_eq!(
            tips("Use cert show <NAME>.", false),
            "Tips: Use cert show <NAME>."
        );
        assert_eq!(
            tips("Use cert show <NAME>.", true),
            "\x1b[34mTips:\x1b[0m Use cert show <NAME>."
        );
        assert!(!tips("bad\x1b[2J", false).contains('\x1b'));
        assert_eq!(
            field("Requested:", "2026-11-10 17:01:10 UTC", false),
            "  Requested:                 2026-11-10 17:01:10 UTC"
        );
    }
    #[test]
    fn details_and_confirmation_align_values_without_coloring_or_modifying_the_values() {
        let fields = [
            field("CA:", "https://ca.example/directory", false),
            field(
                "First registered locally:",
                "2026-11-10 17:01:10 UTC",
                false,
            ),
        ];
        assert_eq!(fields[0].find("https://"), fields[1].find("2026-"));
        let message = "Permanently deactivate account\n  Name: default\n  CA: https://ca.example/directory\n\nThis cannot be undone.";
        let colored = confirmation(message, true);
        assert!(colored.contains("\x1b[1;33mPermanently"));
        assert!(colored.contains("\x1b[36mName:\x1b[0m"));
        assert!(colored.contains("\x1b[33mThis cannot be undone."));
        let plain = confirmation(message, false);
        assert!(!plain.contains('\x1b'));
        assert!(plain.contains("https://ca.example/directory"));
    }
    #[test]
    fn palette_has_one_encoding_boundary_and_plain_never_emits_escape_sequences() {
        for (style, code) in [
            (Style::Red, "31"),
            (Style::Green, "32"),
            (Style::Yellow, "33"),
            (Style::Blue, "34"),
            (Style::Cyan, "36"),
            (Style::BoldRed, "1;31"),
            (Style::BoldGreen, "1;32"),
            (Style::BoldYellow, "1;33"),
            (Style::BoldCyan, "1;36"),
        ] {
            assert_eq!(
                styled("value", style, true),
                format!("\x1b[{code}mvalue\x1b[0m")
            );
            assert_eq!(styled("value", style, false), "value");
        }
        assert_eq!(styled("value", Style::Plain, true), "value");
    }
}
