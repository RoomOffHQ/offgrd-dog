use crate::{Alert, Rule};
use anyhow::{Context, Result};
use offgrd_common::Event;
use std::path::Path;

/// A loaded collection of rules, ready to evaluate against events.
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Read-only access to the loaded rules themselves — used by the
    /// GUI's Rules view to show what's actually loaded (id, title,
    /// severity, description) rather than just a count.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Loads every `*.yaml`/`*.yml` file in `dir` (non-recursive for
    /// now) as a single `Rule` each. A directory that doesn't exist or
    /// contains no rule files yields an empty, valid `RuleSet` rather
    /// than an error — running `offgrd alerts` before you've written
    /// any rules yet shouldn't be a hard failure.
    ///
    /// Fails fast on the first invalid rule file. If you want to keep
    /// going and see *every* problem in one pass (e.g. for a
    /// `rules check` linting command), use `load_dir_report` instead.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<Self> {
        let (ruleset, errors) = Self::load_dir_report(dir)?;
        if let Some(first_error) = errors.into_iter().next() {
            anyhow::bail!(first_error);
        }
        Ok(ruleset)
    }

    /// Like `load_dir`, but never fails because of a single bad rule
    /// file: it loads everything that parses successfully into the
    /// returned `RuleSet`, and returns a human-readable error string
    /// per file that didn't. Only I/O errors reading the directory
    /// itself (not individual files) are still a hard `Err`.
    pub fn load_dir_report(dir: impl AsRef<Path>) -> Result<(Self, Vec<String>)> {
        let dir = dir.as_ref();
        if !dir.exists() {
            return Ok((Self::new(Vec::new()), Vec::new()));
        }

        let mut rules = Vec::new();
        let mut errors = Vec::new();

        for entry in std::fs::read_dir(dir)
            .with_context(|| format!("failed to read rules directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let is_yaml = path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
                .unwrap_or(false);
            if !is_yaml {
                continue;
            }

            match load_one_rule_file(&path) {
                Ok(rule) => rules.push(rule),
                Err(err) => errors.push(format!("{}: {err:#}", path.display())),
            }
        }

        Ok((Self::new(rules), errors))
    }

    /// Evaluates every loaded rule against a single event, returning
    /// one `Alert` per matching rule (an event can trigger more than
    /// one rule).
    pub fn evaluate(&self, event: &Event) -> Vec<Alert> {
        self.rules
            .iter()
            .filter(|rule| rule.matches(event))
            .map(|rule| crate::alert::alert_from_rule_match(rule, event))
            .collect()
    }

    /// Convenience for evaluating a batch of events at once (e.g. a
    /// full process snapshot), preserving event order.
    pub fn evaluate_all(&self, events: &[Event]) -> Vec<Alert> {
        events.iter().flat_map(|event| self.evaluate(event)).collect()
    }
}

/// Reads and parses a single rule YAML file.
fn load_one_rule_file(path: &Path) -> Result<Rule> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read rule file {}", path.display()))?;
    let rule: Rule = serde_yaml::from_str(&contents)
        .with_context(|| format!("failed to parse rule file {}", path.display()))?;
    Ok(rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use offgrd_common::{EventCategory, EventPayload, EventSource, ProcessRef};

    fn write_rule_file(dir: &Path, filename: &str, yaml: &str) {
        std::fs::write(dir.join(filename), yaml).expect("write rule file");
    }

    #[test]
    fn loads_rules_from_directory_and_ignores_non_yaml_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_rule_file(
            dir.path(),
            "powershell.yaml",
            r#"
id: powershell-exec
title: PowerShell execution
severity: Medium
condition:
  category: Process
  image_path_contains: powershell.exe
"#,
        );
        write_rule_file(dir.path(), "README.md", "not a rule");

        let ruleset = RuleSet::load_dir(dir.path()).expect("load rules");
        assert_eq!(ruleset.len(), 1);
    }

    #[test]
    fn missing_rules_directory_yields_empty_ruleset_not_error() {
        let ruleset = RuleSet::load_dir("/this/path/does/not/exist").expect("should not error");
        assert!(ruleset.is_empty());
    }

    #[test]
    fn evaluate_all_produces_one_alert_per_matching_event() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_rule_file(
            dir.path(),
            "powershell.yaml",
            r#"
id: powershell-exec
title: PowerShell execution
severity: Medium
condition:
  image_path_contains: powershell.exe
"#,
        );
        let ruleset = RuleSet::load_dir(dir.path()).expect("load rules");

        let matching = Event::new(
            EventSource::Snapshot,
            EventCategory::Process,
            EventPayload::ProcessStarted {
                process: ProcessRef::new(1).with_image_path(r"C:\Windows\System32\powershell.exe"),
            },
        );
        let non_matching = Event::new(
            EventSource::Snapshot,
            EventCategory::Process,
            EventPayload::ProcessStarted {
                process: ProcessRef::new(2).with_image_path(r"C:\Windows\System32\notepad.exe"),
            },
        );

        let alerts = ruleset.evaluate_all(&[matching, non_matching]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "powershell-exec");
    }

    #[test]
    fn load_dir_report_collects_errors_instead_of_failing_fast() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_rule_file(
            dir.path(),
            "good.yaml",
            r#"
id: good-rule
title: A valid rule
severity: Low
condition:
  image_path_contains: cmd.exe
"#,
        );
        write_rule_file(dir.path(), "bad.yaml", "this: [is not, a valid rule shape");

        let (ruleset, errors) = RuleSet::load_dir_report(dir.path()).expect("should not error");
        assert_eq!(ruleset.len(), 1, "the good rule should still load");
        assert_eq!(errors.len(), 1, "the bad rule should be reported, not silently dropped");
        assert!(errors[0].contains("bad.yaml"));
    }

    #[test]
    fn load_dir_fails_fast_on_first_bad_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_rule_file(dir.path(), "bad.yaml", "not: valid: yaml: at: all: [");

        let result = RuleSet::load_dir(dir.path());
        assert!(result.is_err(), "load_dir should still surface a hard error");
    }
}
