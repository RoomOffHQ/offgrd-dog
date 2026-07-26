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
    Certificates,
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
    /// A single active TCP connection observed at snapshot time (from
    /// `GetExtendedTcpTable` — see `offgrd-collectors::NetworkSnapshotCollector`).
    /// Modeled as "observed", not "started"/"ended": a point-in-time
    /// snapshot can't tell when a connection was actually established,
    /// only that it currently exists — same honesty principle as
    /// `ProcessRef` not claiming command-line data it doesn't have.
    NetworkConnectionObserved {
        pid: Option<u32>,
        local_addr: String,
        local_port: u16,
        remote_addr: String,
        remote_port: u16,
        state: String,
    },
    /// A single autorun/persistence entry observed at snapshot time
    /// (registry Run/RunOnce keys for now — see
    /// `offgrd-collectors::AutorunsCollector`). Scheduled tasks,
    /// services, and startup-folder shortcuts are the same
    /// conceptual thing but different data sources — deliberately not
    /// unified into one "persistence mechanism" abstraction yet,
    /// since only registry Run keys are actually implemented so far.
    AutorunEntryObserved {
        /// e.g. "HKLM" or "HKCU".
        hive: String,
        /// e.g. `Software\Microsoft\Windows\CurrentVersion\Run`.
        key_path: String,
        /// The registry value's name.
        value_name: String,
        /// The registry value's data (typically a command line to
        /// execute at logon).
        value_data: String,
    },
    /// A single Windows service observed at snapshot time (via the
    /// Service Control Manager — see
    /// `offgrd-collectors::ServicesCollector`).
    ServiceObserved {
        service_name: String,
        display_name: String,
        /// e.g. "Running", "Stopped", "Paused" — decoded from the
        /// SCM's numeric state, not the raw number, so rules/UI don't
        /// need to know the Win32 constant values.
        state: String,
        /// e.g. "Own Process", "Share Process", "Kernel Driver" — the
        /// service type, decoded the same way.
        service_type: String,
        /// e.g. "Auto Start", "Manual", "Disabled".
        start_type: Option<String>,
        binary_path: Option<String>,
    },
    /// A single certificate observed in a Windows certificate store
    /// (via `CertEnumCertificatesInStore` — see
    /// `offgrd-collectors::CertificatesCollector`). Covers installed
    /// certificates (system trust store contents), not live TLS
    /// connection inspection (SNI/chain-of-a-live-connection) — that's
    /// a separate, not-yet-implemented capability (see the
    /// architecture doc's TLS Certificate Inspector module).
    CertificateObserved {
        /// e.g. "ROOT", "CA", "MY" — the store name it was found in.
        store_name: String,
        subject: String,
        issuer: String,
        /// Hex-encoded SHA-1 thumbprint, the conventional way
        /// Windows tooling (certmgr, PowerShell's Get-ChildItem
        /// Cert:\) identifies a specific certificate.
        thumbprint: String,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
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
