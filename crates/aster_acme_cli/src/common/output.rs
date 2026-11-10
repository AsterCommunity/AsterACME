//! Shared human output policy: terminal colors, untrusted text, fields and hints.

pub(crate) fn colors(terminal: bool) -> bool {
    terminal
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}

pub(crate) fn styled(text: &str, code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{code}m{text}\x1b[0m")
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

/// Presentation hint; paint only the label so the command text stays easy to copy.
pub(crate) fn tips(message: &str, color: bool) -> String {
    format!("{} {}", styled("Tips:", "34", color), safe(message))
}

/// Shared detail-field layout; callers can style already escaped semantic values.
pub(crate) fn field(label: &str, value: &str, color: bool) -> String {
    use unicode_width::UnicodeWidthStr;
    let padding = " ".repeat(25_usize.saturating_sub(label.width()));
    format!("  {}{padding}  {value}", styled(label, "36", color))
}

/// Confirmation blocks share the same field alignment and warning policy as details.
pub(crate) fn confirmation(details: &str, color: bool) -> String {
    details
        .lines()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                return styled(&safe(line), "1;33", color);
            }
            if let Some((label, value)) = line
                .strip_prefix("  ")
                .and_then(|line| line.split_once(": "))
            {
                return field(&format!("{label}:"), &safe(value), color);
            }
            styled(&safe(line), "33", color && !line.is_empty())
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
}
