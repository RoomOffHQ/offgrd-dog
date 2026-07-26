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

    /// Case-insensitive substring match against an autorun entry's
    /// value data, if the event carries one (`AutorunEntryObserved`
    /// events only).
    #[serde(default)]
    pub value_data_contains: Option<String>,
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

        if self.image_path_contains.is_some() || self.command_line_contains.is_some() {
            if !self.matches_process_fields(event) {
                return false;
            }
        }

        if let Some(needle) = &self.value_data_contains {
            if !self.matches_value_data(event, needle) {
                return false;
            }
        }

        true
    }

    /// Checks `image_path_contains`/`command_line_contains` against a
    /// `ProcessStarted` event. Returns `false` for any other event
    /// shape — a rule asking about process fields can only ever match
    /// process-start events, not e.g. autorun entries.
    fn matches_process_fields(&self, event: &Event) -> bool {
        let EventPayload::ProcessStarted { process } = &event.payload else {
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

    /// Checks `value_data_contains` against an `AutorunEntryObserved`
    /// event. Returns `false` for any other event shape, same
    /// reasoning as `matches_process_fields`.
    fn matches_value_data(&self, event: &Event, needle: &str) -> bool {
        let EventPayload::AutorunEntryObserved { value_data, .. } = &event.payload else {
            return false;
        };
        value_data.to_lowercase().contains(&needle.to_lowercase())
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
                value_data_contains: None,
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
                value_data_contains: None,
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
                value_data_contains: None,
            },
        };

        assert!(rule.matches(&process_event(r"C:\anything.exe", None)));
    }

    #[test]
    fn value_data_contains_matches_autorun_entries_only() {
        let rule = Rule {
            id: "test-autorun-appdata".into(),
            title: "Autorun in AppData".into(),
            description: String::new(),
            severity: Severity::Medium,
            mitre_attack_id: None,
            references: vec![],
            condition: Condition {
                category: Some(EventCategory::Persistence),
                image_path_contains: None,
                command_line_contains: None,
                value_data_contains: Some(r"\AppData\".into()),
            },
        };

        let matching = Event::new(
            EventSource::Snapshot,
            EventCategory::Persistence,
            EventPayload::AutorunEntryObserved {
                hive: "HKCU".into(),
                key_path: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
                value_name: "Updater".into(),
                value_data: r"C:\Users\alice\AppData\Roaming\updater.exe".into(),
            },
        );
        let non_matching = Event::new(
            EventSource::Snapshot,
            EventCategory::Persistence,
            EventPayload::AutorunEntryObserved {
                hive: "HKLM".into(),
                key_path: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
                value_name: "Driver Booster".into(),
                value_data: r"C:\Program Files\IObit\DriverBooster\Booster.exe".into(),
            },
        );
        // A ProcessStarted event should never match a value_data_contains
        // rule, regardless of content — different payload shape entirely.
        let wrong_shape = process_event(r"C:\Users\alice\AppData\evil.exe", None);

        assert!(rule.matches(&matching));
        assert!(!rule.matches(&non_matching));
        assert!(!rule.matches(&wrong_shape));
    }
}
