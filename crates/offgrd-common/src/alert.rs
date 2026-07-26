use crate::Severity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The result of a detection rule matching an event. Lives in
/// offgrd-common (rather than offgrd-rules, where the matching logic
/// itself lives) specifically so that offgrd-core's `EventStore` can
/// persist it without offgrd-core having to depend on offgrd-rules —
/// core is meant to be lower-level, foundational infrastructure that
/// higher-level crates (rules, and later the correlation engine)
/// build on, not the other way around.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Alert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub rule_id: String,
    pub rule_title: String,
    pub severity: Severity,
    pub triggering_event_id: Uuid,
}

impl Alert {
    /// Constructs a new alert. Takes plain fields rather than a `Rule`
    /// reference so this crate doesn't need to know anything about
    /// how rules are defined or matched — offgrd-rules calls this with
    /// the relevant fields already extracted.
    pub fn new(
        rule_id: impl Into<String>,
        rule_title: impl Into<String>,
        severity: Severity,
        triggering_event_id: Uuid,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            rule_id: rule_id.into(),
            rule_title: rule_title.into(),
            severity,
            triggering_event_id,
        }
    }
}
