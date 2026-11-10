//! Shared selector row presentation; filtering, defaults and operation policy stay with owners.
use super::{output::safe, time::timestamp};
use std::fmt;

/// Stable ordering of identity, optional summary, time, state and selection marker.
/// This is display data only: terminal selection retains a separate caller-owned index.
pub(crate) struct ChoiceLabel<'a> {
    pub(crate) name: &'a str,
    pub(crate) summary: Option<&'a str>,
    pub(crate) at: Option<time::OffsetDateTime>,
    pub(crate) status: Option<&'a str>,
    pub(crate) marker: Option<&'a str>,
}

impl fmt::Display for ChoiceLabel<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = vec![safe(self.name)];
        if let Some(summary) = self.summary {
            parts.push(safe(summary));
        }
        parts.push(timestamp(self.at));
        if let Some(status) = self.status {
            parts.push(safe(status));
        }
        if let Some(marker) = self.marker {
            parts.push(safe(marker));
        }
        formatter.write_str(&parts.join(" | "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rows_share_field_order_time_and_control_escaping_with_optional_details() {
        let label = ChoiceLabel {
            name: "web",
            summary: Some("example.com, *.example.com"),
            at: Some(time::OffsetDateTime::UNIX_EPOCH),
            status: Some("completed"),
            marker: Some("in use"),
        };
        assert_eq!(
            label.to_string(),
            "web | example.com, *.example.com | 1970-01-01 00:00:00 UTC | completed | in use"
        );
        let label = ChoiceLabel {
            name: "account\n",
            summary: None,
            at: None,
            status: Some("pending"),
            marker: None,
        };
        assert_eq!(label.to_string(), "account\\n | — | pending");
        assert!(!label.to_string().contains('\n'));
    }
}
