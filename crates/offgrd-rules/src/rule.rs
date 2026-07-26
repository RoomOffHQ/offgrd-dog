use offgrd_common::{Event, EventCategory, EventPayload, Severity};
use serde::{Deserialize, Serialize};

/// A single detection rule. Deliberately close to Sigma's shape
/// (id/title/description/severity/references) so a future
/// `offgrd-cli rules import-sigma` converter has an easy target,
/// even though the `condition` matching language here is much
/// simpler than full Sigma for now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    #[serde(default)]
    pub mitre_attack_id: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    pub condition: Condition,
}

/// Match conditions against a single `Event`. All present fields must
/// match (logical AND) for the rule to fire; `None`/empty fields are
/// ignored rather than treated as "must be absent".
///
/// This is intentionally flat rather than a general boolean
/// expression tree (AND/OR/NOT) — that's real complexity better added
/// once a flat AND-of-fields ruleset proves too limiting in practice,
/// not guessed at up front.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    /// Only match events of this category, e.g. "process".
    #[serde(default)]
    pub category: Option<EventCategory>,

    /// Case-insensitive substring match against the process image
    /// path, if the event carries a `ProcessRef` (ProcessStarted).
    #[serde(default)]
    pub image_path_contains: Option<String>,

    /// Case-insensitive substring match against the process command
    /// line, if present (ETW-sourced events only for now — the
    /// Toolhelp32 snapshot collector doesn't populate this field).
    #[serde(default)]
    pub command_line_contains: Option<String>,
}

impl Rule {
    /// Returns `true` if this rule's condition matches `event`.
    pub fn matches(&self, event: &Event) -> bool {
        self.condition.matches(event)
    }
}

impl Condition {
    pub fn matches(&self, event: &Event) -> bool {
        if let Some(expected_category) = self.category {
            if expected_category != event.category {
                return false;
            }
        }

        if self.image_path_contains.is_none() && self.command_line_contains.is_none() {
            return true; // Category-only rule (or empty condition): nothing more to check.
        }

        let EventPayload::ProcessStarted { process } = &event.payload else {
            // A rule asking about image_path/command_line can only
            // ever match ProcessStarted events; anything else is a
            // non-match rather than an error.
            return false;
        };

        if let Some(needle) = &self.image_path_contains {
            let matched = process
                .image_path
                .as_deref()
                .map(|path| path.to_lowercase().contains(&needle.to_lowercase()))
                .unwrap_or(false);
            if !matched {
                return false;
            }
        }

        if let Some(needle) = &self.command_line_contains {
            let matched = process
                .command_line
                .as_deref()
                .map(|cmd| cmd.to_lowercase().contains(&needle.to_lowercase()))
                .unwrap_or(false);
            if !matched {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use offgrd_common::{EventSource, ProcessRef};

    fn process_event(image_path: &str, command_line: Option<&str>) -> Event {
        let mut process = ProcessRef::new(1234).with_image_path(image_path);
        if let Some(cmd) = command_line {
            process = process.with_command_line(cmd);
        }
        Event::new(
            EventSource::Snapshot,
            EventCategory::Process,
            EventPayload::ProcessStarted { process },
        )
    }

    fn rule_matching_powershell() -> Rule {
        Rule {
            id: "test-powershell".into(),
            title: "PowerShell execution".into(),
            description: String::new(),
            severity: Severity::Medium,
            mitre_attack_id: None,
            references: vec![],
            condition: Condition {
                category: Some(EventCategory::Process),
                image_path_contains: Some("powershell.exe".into()),
                command_line_contains: None,
            },
        }
    }

    #[test]
    fn matches_on_image_path_substring_case_insensitive() {
        let rule = rule_matching_powershell();
        let event = process_event(r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe", None);
        assert!(rule.matches(&event));
    }

    #[test]
    fn does_not_match_unrelated_process() {
        let rule = rule_matching_powershell();
        let event = process_event(r"C:\Windows\System32\notepad.exe", None);
        assert!(!rule.matches(&event));
    }

    #[test]
    fn matches_on_command_line_when_specified() {
        let rule = Rule {
            id: "test-encoded".into(),
            title: "Encoded command".into(),
            description: String::new(),
            severity: Severity::High,
            mitre_attack_id: None,
            references: vec![],
            condition: Condition {
                category: None,
                image_path_contains: None,
                command_line_contains: Some("-EncodedCommand".into()),
            },
        };

        let matching = process_event(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            Some("powershell.exe -EncodedCommand SQBFAFgA"),
        );
        let non_matching = process_event(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            Some("powershell.exe -File script.ps1"),
        );

        assert!(rule.matches(&matching));
        assert!(!rule.matches(&non_matching));
    }

    #[test]
    fn category_only_rule_matches_any_event_in_that_category() {
        let rule = Rule {
            id: "test-any-process".into(),
            title: "Any process event".into(),
            description: String::new(),
            severity: Severity::Info,
            mitre_attack_id: None,
            references: vec![],
            condition: Condition {
                category: Some(EventCategory::Process),
                image_path_contains: None,
                command_line_contains: None,
            },
        };

        assert!(rule.matches(&process_event(r"C:\anything.exe", None)));
    }
}
