use crate::process::ProcessRef;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Where a raw observation originated. Used for provenance/debugging
/// and for filtering in the UI ("show me only ETW-sourced events"),
/// never for branching detection logic — detection logic should only
/// ever look at `category` + `payload`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventSource {
    /// Produced directly by offgrd-cli/offgrd-core, not observed from
    /// the OS (e.g. "process enumeration snapshot at startup").
    Snapshot,
    Etw,
    Wmi,
    Minifilter,
    RegistryNotify,
    /// Synthesized by the correlation engine from other events
    /// (e.g. an alert), rather than observed directly.
    Derived,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventCategory {
    Process,
    Network,
    Dns,
    Registry,
    File,
    Persistence,
    Alert,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Category-specific data. Every collector produces one of these
/// variants; nothing outside this enum needs to know the source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventPayload {
    ProcessStarted {
        process: ProcessRef,
    },
    ProcessEnded {
        pid: u32,
        exit_code: Option<i32>,
    },
    /// Placeholder variants for modules not yet implemented — kept
    /// here so the schema shape is stable and future collectors slot
    /// in without breaking existing serialized data.
    Note {
        message: String,
    },
}

/// The normalized envelope every collector emits and everything else
/// (storage, correlation engine, UI, CLI) consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub category: EventCategory,
    pub severity_hint: Option<Severity>,
    pub payload: EventPayload,
}

impl Event {
    pub fn new(source: EventSource, category: EventCategory, payload: EventPayload) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source,
            category,
            severity_hint: None,
            payload,
        }
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity_hint = Some(severity);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_roundtrips_through_json() {
        let process = ProcessRef::new(1234)
            .with_parent(4)
            .with_image_path(r"C:\Windows\System32\notepad.exe");
        let ev = Event::new(
            EventSource::Snapshot,
            EventCategory::Process,
            EventPayload::ProcessStarted { process },
        )
        .with_severity(Severity::Info);

        let json = serde_json::to_string(&ev).expect("serialize");
        let back: Event = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ev.id, back.id);
        assert_eq!(ev.category, back.category);
    }
}
