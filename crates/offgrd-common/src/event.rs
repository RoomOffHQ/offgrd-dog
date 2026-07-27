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
    Sessions,
    Software,
    Clipboard,
    Accounts,
    Activity,
    Environment,
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
    /// A single loaded module (DLL) observed for a process at
    /// snapshot time (via Toolhelp32's `Module32First`/`Module32Next`
    /// — see `offgrd-collectors::ModulesCollector`). A precursor to
    /// DLL-injection detection: an unexpected module (wrong path,
    /// unsigned, in a process that shouldn't load it) is one of the
    /// clearest injection signals, though the actual "is this
    /// suspicious" judgment is a future rule-engine/correlation
    /// concern, not this collector's job — it only reports facts.
    LoadedModuleObserved {
        pid: u32,
        module_name: String,
        module_path: String,
        base_size: u32,
    },
    /// A single active RDP/console session observed at snapshot time
    /// (via `WTSEnumerateSessionsW` — see
    /// `offgrd-collectors::SessionsCollector`).
    SessionObserved {
        session_id: u32,
        /// e.g. "Active", "Disconnected", "Listen".
        state: String,
        /// e.g. "Console" for the local session, "RDP-Tcp#N" for a
        /// remote desktop session, or empty for the listener session.
        station_name: String,
        user_name: Option<String>,
    },
    /// A single line from the hosts file, kept as a raw entry rather
    /// than pre-judged as "suspicious" — the whole point of this
    /// collector is visibility, not a verdict (see
    /// `offgrd-collectors::HostsFileCollector`).
    HostsFileEntryObserved {
        ip_address: String,
        hostname: String,
        /// The full raw line, for context (comments on the same
        /// line, original formatting) — `ip_address`/`hostname` are
        /// parsed out of this for convenience but this preserves the
        /// source of truth.
        raw_line: String,
    },
    /// A shortcut or executable found directly in a Startup folder
    /// (`shell:startup` for the current user, or the all-users
    /// equivalent) — see `offgrd-collectors::StartupFolderCollector`.
    StartupFolderEntryObserved {
        /// "CurrentUser" or "AllUsers".
        scope: String,
        file_name: String,
        full_path: String,
    },
    /// A single named pipe visible under `\\.\pipe\` — see
    /// `offgrd-collectors::NamedPipesCollector`.
    NamedPipeObserved {
        pipe_name: String,
    },
    /// A single entry from the registry's "Add/Remove Programs" list
    /// — see `offgrd-collectors::InstalledProgramsCollector`.
    InstalledProgramObserved {
        display_name: String,
        display_version: Option<String>,
        publisher: Option<String>,
        install_location: Option<String>,
    },
    /// A snapshot of the current clipboard's text content, if any —
    /// see `offgrd-collectors::ClipboardCollector`. Text formats only
    /// for this first pass (no images/files); a genuinely
    /// privacy-sensitive capability, flagged prominently in the CLI
    /// help text and GUI, not silently collected.
    ClipboardTextObserved {
        text: String,
    },
    /// A local user account or group observed at snapshot time (via
    /// `NetUserEnum`/`NetLocalGroupEnum` — see
    /// `offgrd-collectors::LocalAccountsCollector`).
    LocalAccountObserved {
        /// "User" or "Group".
        kind: String,
        name: String,
        /// For users: whether the account is disabled. `None` for groups.
        disabled: Option<bool>,
        comment: Option<String>,
    },
    /// A single SMB/network share observed at snapshot time (via
    /// `NetShareEnum` — see `offgrd-collectors::NetworkSharesCollector`).
    NetworkShareObserved {
        share_name: String,
        local_path: Option<String>,
        comment: Option<String>,
    },
    /// The current foreground (focused) window at snapshot time (via
    /// `GetForegroundWindow` — see
    /// `offgrd-collectors::ForegroundWindowCollector`). Deliberately
    /// point-in-time only, not a continuous tracker — see that
    /// collector's doc comment for the UX/ethics reasoning.
    ForegroundWindowObserved {
        window_title: String,
        pid: Option<u32>,
        process_image_path: Option<String>,
    },
    /// A single process environment variable (see
    /// `offgrd-collectors::EnvironmentCollector`) — this process's own
    /// environment only, not another process's (reading another
    /// process's environment block needs the same
    /// PEB-reading-via-undocumented-API concern already noted for
    /// command lines; deliberately not attempted).
    EnvironmentVariableObserved {
        name: String,
        value: String,
    },
    /// A single resolved-hostname entry from the local DNS resolver
    /// cache (see `offgrd-collectors::DnsCacheCollector`). Parsed from
    /// `ipconfig /displaydns` output rather than the undocumented
    /// `DnsGetCacheDataTable` API — a deliberate pragmatic tradeoff,
    /// see that collector's doc comment.
    DnsCacheEntryObserved {
        hostname: String,
        record_type: String,
        data: String,
    },
    /// System idle/input state at snapshot time (via
    /// `GetLastInputInfo` — see `offgrd-collectors::IdleTimeCollector`).
    IdleStateObserved {
        idle_seconds: u64,
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
