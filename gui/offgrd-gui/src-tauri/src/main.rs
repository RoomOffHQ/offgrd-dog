//! OffGrd Dog GUI — Tauri backend.
//!
//! This is intentionally a thin layer: every `#[tauri::command]` here
//! just calls into `offgrd-collectors`/`offgrd-core`/`offgrd-rules`,
//! the exact same crates `offgrd-cli` uses. The GUI has zero
//! detection/collection logic of its own beyond the live-monitor loop
//! in `live.rs` (which itself just reuses `ProcessSnapshotCollector`)
//! — it's a consumer of the pipeline, same as the CLI, just with a
//! nicer front end. This keeps the two UIs from silently drifting
//! apart in behavior.
//!
//! Data-transfer types (`ProcessDto`, `AlertDto`, ...) are small,
//! JSON-friendly views over `offgrd-common` types rather than
//! `#[tauri::command]`-exposing the domain types directly — keeps the
//! JS-facing shape stable even if the internal `Event`/`Alert` schema
//! changes shape later.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod live;

use offgrd_collectors::ProcessSnapshotCollector;
use offgrd_common::{Event, EventPayload};
use offgrd_core::{Collector, EventBus, EventStore};
use offgrd_rules::RuleSet;
use serde::{Deserialize, Serialize};
use tauri::Manager;
use tokio::sync::broadcast::error::TryRecvError;

/// Resolved, per-install filesystem locations, computed once at
/// startup from Tauri's app data directory rather than the CLI's
/// simplification of relative paths (`./offgrd.db`, `./rules`) — a
/// packaged GUI app can be launched from anywhere (Start Menu,
/// desktop shortcut), so it can't assume a "current directory" the
/// way a CLI invoked from a repo checkout can.
#[derive(Clone)]
pub struct AppPaths {
    pub db_path: String,
    pub rules_dir: String,
}

impl AppPaths {
    /// Resolves real paths under Tauri's app-data directory, creating
    /// it if necessary. Falls back to the CLI's relative-path
    /// defaults if the app data directory can't be determined (should
    /// only happen in unusual sandboxing situations) — better to
    /// still run somewhere than fail to start entirely.
    fn resolve(app_handle: &tauri::AppHandle) -> Self {
        let base = app_handle
            .path_resolver()
            .app_data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        if let Err(err) = std::fs::create_dir_all(&base) {
            eprintln!(
                "offgrd-gui: could not create app data dir {}: {err} (falling back to relative paths)",
                base.display()
            );
            return Self {
                db_path: "offgrd.db".to_string(),
                rules_dir: "rules".to_string(),
            };
        }

        let db_path = base.join("offgrd.db").to_string_lossy().to_string();

        // Rules are content the user/community edits and shares (see
        // CONTRIBUTING.md's "New detection rule" workflow) — look for
        // a `rules/` folder next to the executable first (matches the
        // CLI's convention and makes it easy to drop in custom rule
        // sets), falling back to a copy under the app data dir that
        // we seed with nothing (empty is a valid, handled state — see
        // `RuleSet::load_dir`) rather than silently inventing rules.
        let exe_relative_rules = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|p| p.join("rules")));
        let rules_dir = exe_relative_rules
            .filter(|p| p.exists())
            .unwrap_or_else(|| base.join("rules"))
            .to_string_lossy()
            .to_string();

        Self { db_path, rules_dir }
    }
}

#[derive(Serialize, Clone)]
pub struct ProcessDto {
    pid: u32,
    ppid: Option<u32>,
    image_path: Option<String>,
    command_line: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct AlertDto {
    id: String,
    timestamp: String,
    rule_id: String,
    rule_title: String,
    severity: String,
    triggering_event_id: String,
}

#[derive(Serialize, Clone)]
struct DashboardSummary {
    process_count: usize,
    stored_event_count: i64,
    stored_alert_count: i64,
    loaded_rule_count: usize,
    rule_load_errors: Vec<String>,
    db_path: String,
    rules_dir: String,
}

pub(crate) fn process_to_dto(event: &Event) -> Option<ProcessDto> {
    match &event.payload {
        EventPayload::ProcessStarted { process } => Some(ProcessDto {
            pid: process.pid,
            ppid: process.parent_pid,
            image_path: process.image_path.clone(),
            command_line: process.command_line.clone(),
        }),
        _ => None,
    }
}

pub(crate) fn alert_to_dto(alert: &offgrd_common::Alert) -> AlertDto {
    AlertDto {
        id: alert.id.to_string(),
        timestamp: alert.timestamp.to_rfc3339(),
        rule_id: alert.rule_id.clone(),
        rule_title: alert.rule_title.clone(),
        severity: format!("{:?}", alert.severity),
        triggering_event_id: alert.triggering_event_id.to_string(),
    }
}

#[derive(Serialize, Clone)]
struct RuleDto {
    id: String,
    title: String,
    description: String,
    severity: String,
    mitre_attack_id: Option<String>,
    condition_summary: String,
}

fn rule_to_dto(rule: &offgrd_rules::Rule) -> RuleDto {
    // A short, human-readable summary of what the condition actually
    // checks — the full struct is more detail than the Rules list
    // view needs at a glance; someone editing the YAML directly (see
    // CONTRIBUTING.md) is the audience for the full condition shape.
    let mut parts = Vec::new();
    if let Some(category) = rule.condition.category {
        parts.push(format!("category = {category:?}"));
    }
    if let Some(needle) = &rule.condition.image_path_contains {
        parts.push(format!("image path contains \"{needle}\""));
    }
    if let Some(needle) = &rule.condition.command_line_contains {
        parts.push(format!("command line contains \"{needle}\""));
    }
    let condition_summary = if parts.is_empty() {
        "matches any event".to_string()
    } else {
        parts.join(" AND ")
    };

    RuleDto {
        id: rule.id.clone(),
        title: rule.title.clone(),
        description: rule.description.clone(),
        severity: format!("{:?}", rule.severity),
        mitre_attack_id: rule.mitre_attack_id.clone(),
        condition_summary,
    }
}

/// Lists every currently loaded rule, for the GUI's Rules view.
#[tauri::command]
fn list_rules(
    rules_dir: Option<String>,
    paths: tauri::State<'_, AppPaths>,
) -> Result<Vec<RuleDto>, String> {
    let dir = rules_dir.unwrap_or_else(|| paths.rules_dir.clone());
    let ruleset = RuleSet::load_dir(&dir).map_err(|e| e.to_string())?;
    Ok(ruleset.rules().iter().map(rule_to_dto).collect())
}

/// The three monitoring intensity levels requested: Normal (fully
/// on-demand, nothing runs in the background), Moderate (live process
/// monitoring at a relaxed interval), Paranoid (fast process
/// monitoring plus periodic full-spectrum scans — network, autoruns,
/// services, certificates — with every bundled rule evaluated against
/// all of it). `live.rs` reads this each loop iteration so switching
/// modes takes effect on the next tick, no restart needed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MonitoringMode {
    Normal,
    Moderate,
    Paranoid,
}

impl MonitoringMode {
    /// How often the process-diff tick runs. `None` means "don't loop
    /// at all" (Normal mode — the background task sleeps on a long
    /// interval and just re-checks whether the mode has changed).
    pub fn process_poll_interval(&self) -> Option<std::time::Duration> {
        match self {
            MonitoringMode::Normal => None,
            MonitoringMode::Moderate => Some(std::time::Duration::from_secs(10)),
            MonitoringMode::Paranoid => Some(std::time::Duration::from_secs(3)),
        }
    }

    /// Only Paranoid mode runs the extra collectors (network,
    /// autoruns, services, certificates) periodically in the
    /// background — these are heavier and noisier, appropriate for
    /// "I want to see everything" but not for a lighter-touch mode.
    pub fn runs_full_spectrum_scans(&self) -> bool {
        matches!(self, MonitoringMode::Paranoid)
    }

    /// How often the full-spectrum scan runs, in units of process-poll
    /// ticks (e.g. 10 means "every 10th process-diff tick").
    pub fn full_spectrum_scan_every_n_ticks(&self) -> u32 {
        10
    }
}

pub struct MonitoringState(pub std::sync::Mutex<MonitoringMode>);

#[tauri::command]
fn get_monitoring_mode(state: tauri::State<'_, MonitoringState>) -> MonitoringMode {
    *state.0.lock().expect("monitoring mode mutex poisoned")
}

#[tauri::command]
fn set_monitoring_mode(mode: MonitoringMode, state: tauri::State<'_, MonitoringState>) {
    *state.0.lock().expect("monitoring mode mutex poisoned") = mode;
}

#[derive(Serialize, Clone)]
struct LocalAccountDto {
    kind: String,
    name: String,
    disabled: Option<bool>,
    comment: Option<String>,
}

#[derive(Serialize, Clone)]
struct NetworkShareDto {
    share_name: String,
    local_path: Option<String>,
    comment: Option<String>,
}

#[derive(Serialize, Clone)]
struct ForegroundWindowDto {
    window_title: String,
    pid: Option<u32>,
    process_image_path: Option<String>,
}

#[derive(Serialize, Clone)]
struct EnvironmentVariableDto {
    name: String,
    value: String,
}

#[derive(Serialize, Clone)]
struct DnsCacheEntryDto {
    hostname: String,
    record_type: String,
    data: String,
}

#[derive(Serialize, Clone)]
struct IdleStateDto {
    idle_seconds: u64,
}

#[tauri::command]
async fn list_local_accounts() -> Result<Vec<LocalAccountDto>, String> {
    collect_and_extract(offgrd_collectors::LocalAccountsCollector, |event| match &event.payload {
        EventPayload::LocalAccountObserved { kind, name, disabled, comment } => {
            Some(LocalAccountDto {
                kind: kind.clone(),
                name: name.clone(),
                disabled: *disabled,
                comment: comment.clone(),
            })
        }
        _ => None,
    })
    .await
}

#[tauri::command]
async fn list_network_shares() -> Result<Vec<NetworkShareDto>, String> {
    collect_and_extract(offgrd_collectors::NetworkSharesCollector, |event| match &event.payload {
        EventPayload::NetworkShareObserved { share_name, local_path, comment } => {
            Some(NetworkShareDto {
                share_name: share_name.clone(),
                local_path: local_path.clone(),
                comment: comment.clone(),
            })
        }
        _ => None,
    })
    .await
}

/// Single-shot, explicit-only, matching the CLI's `offgrd foreground`
/// — never called by the live monitor or an auto-refresh path, same
/// reasoning as `get_clipboard_snapshot`.
#[tauri::command]
async fn get_foreground_window() -> Result<Option<ForegroundWindowDto>, String> {
    let results = collect_and_extract(offgrd_collectors::ForegroundWindowCollector, |event| match &event.payload {
        EventPayload::ForegroundWindowObserved { window_title, pid, process_image_path } => {
            Some(ForegroundWindowDto {
                window_title: window_title.clone(),
                pid: *pid,
                process_image_path: process_image_path.clone(),
            })
        }
        _ => None,
    })
    .await?;
    Ok(results.into_iter().next())
}

#[tauri::command]
async fn list_environment_variables() -> Result<Vec<EnvironmentVariableDto>, String> {
    collect_and_extract(offgrd_collectors::EnvironmentCollector, |event| match &event.payload {
        EventPayload::EnvironmentVariableObserved { name, value } => {
            Some(EnvironmentVariableDto { name: name.clone(), value: value.clone() })
        }
        _ => None,
    })
    .await
}

#[tauri::command]
async fn list_dns_cache() -> Result<Vec<DnsCacheEntryDto>, String> {
    collect_and_extract(offgrd_collectors::DnsCacheCollector, |event| match &event.payload {
        EventPayload::DnsCacheEntryObserved { hostname, record_type, data } => {
            Some(DnsCacheEntryDto {
                hostname: hostname.clone(),
                record_type: record_type.clone(),
                data: data.clone(),
            })
        }
        _ => None,
    })
    .await
}

#[tauri::command]
async fn get_idle_state() -> Result<Option<IdleStateDto>, String> {
    let results = collect_and_extract(offgrd_collectors::IdleTimeCollector, |event| match &event.payload {
        EventPayload::IdleStateObserved { idle_seconds } => Some(IdleStateDto { idle_seconds: *idle_seconds }),
        _ => None,
    })
    .await?;
    Ok(results.into_iter().next())
}

#[derive(Serialize, Clone)]
struct ModuleDto {
    pid: u32,
    module_name: String,
    module_path: String,
    base_size: u32,
}

#[derive(Serialize, Clone)]
struct SessionDto {
    session_id: u32,
    state: String,
    station_name: String,
    user_name: Option<String>,
}

#[derive(Serialize, Clone)]
struct HostsEntryDto {
    ip_address: String,
    hostname: String,
    raw_line: String,
}

#[derive(Serialize, Clone)]
struct StartupItemDto {
    scope: String,
    file_name: String,
    full_path: String,
}

#[derive(Serialize, Clone)]
struct NamedPipeDto {
    pipe_name: String,
}

#[derive(Serialize, Clone)]
struct InstalledProgramDto {
    display_name: String,
    display_version: Option<String>,
    publisher: Option<String>,
    install_location: Option<String>,
}

#[tauri::command]
async fn list_modules() -> Result<Vec<ModuleDto>, String> {
    collect_and_extract(offgrd_collectors::ModulesCollector, |event| match &event.payload {
        EventPayload::LoadedModuleObserved { pid, module_name, module_path, base_size } => {
            Some(ModuleDto {
                pid: *pid,
                module_name: module_name.clone(),
                module_path: module_path.clone(),
                base_size: *base_size,
            })
        }
        _ => None,
    })
    .await
}

#[tauri::command]
async fn list_sessions() -> Result<Vec<SessionDto>, String> {
    collect_and_extract(offgrd_collectors::SessionsCollector, |event| match &event.payload {
        EventPayload::SessionObserved { session_id, state, station_name, user_name } => {
            Some(SessionDto {
                session_id: *session_id,
                state: state.clone(),
                station_name: station_name.clone(),
                user_name: user_name.clone(),
            })
        }
        _ => None,
    })
    .await
}

#[tauri::command]
async fn list_hosts_entries() -> Result<Vec<HostsEntryDto>, String> {
    collect_and_extract(offgrd_collectors::HostsFileCollector, |event| match &event.payload {
        EventPayload::HostsFileEntryObserved { ip_address, hostname, raw_line } => {
            Some(HostsEntryDto {
                ip_address: ip_address.clone(),
                hostname: hostname.clone(),
                raw_line: raw_line.clone(),
            })
        }
        _ => None,
    })
    .await
}

#[tauri::command]
async fn list_startup_items() -> Result<Vec<StartupItemDto>, String> {
    collect_and_extract(offgrd_collectors::StartupFolderCollector, |event| match &event.payload {
        EventPayload::StartupFolderEntryObserved { scope, file_name, full_path } => {
            Some(StartupItemDto {
                scope: scope.clone(),
                file_name: file_name.clone(),
                full_path: full_path.clone(),
            })
        }
        _ => None,
    })
    .await
}

#[tauri::command]
async fn list_named_pipes() -> Result<Vec<NamedPipeDto>, String> {
    collect_and_extract(offgrd_collectors::NamedPipesCollector, |event| match &event.payload {
        EventPayload::NamedPipeObserved { pipe_name } => {
            Some(NamedPipeDto { pipe_name: pipe_name.clone() })
        }
        _ => None,
    })
    .await
}

#[tauri::command]
async fn list_installed_programs() -> Result<Vec<InstalledProgramDto>, String> {
    collect_and_extract(offgrd_collectors::InstalledProgramsCollector, |event| match &event.payload {
        EventPayload::InstalledProgramObserved { display_name, display_version, publisher, install_location } => {
            Some(InstalledProgramDto {
                display_name: display_name.clone(),
                display_version: display_version.clone(),
                publisher: publisher.clone(),
                install_location: install_location.clone(),
            })
        }
        _ => None,
    })
    .await
}

/// Deliberately a separate, explicit, single-shot command rather than
/// something the Dashboard/live monitor ever calls automatically —
/// see `ClipboardCollector`'s doc comment on why this is
/// privacy-sensitive. The frontend gates this behind an explicit
/// "Reveal clipboard" button, never an auto-refresh.
#[tauri::command]
async fn get_clipboard_snapshot() -> Result<Option<String>, String> {
    offgrd_collectors::clipboard::read_clipboard_text().map_err(|e| e.to_string())
}

#[derive(Serialize, Clone)]
struct NetworkConnectionDto {
    pid: Option<u32>,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: String,
}

#[derive(Serialize, Clone)]
struct AutorunEntryDto {
    hive: String,
    key_path: String,
    value_name: String,
    value_data: String,
}

#[derive(Serialize, Clone)]
struct ServiceDto {
    service_name: String,
    display_name: String,
    state: String,
    service_type: String,
}

#[derive(Serialize, Clone)]
struct CertificateDto {
    store_name: String,
    subject: String,
    issuer: String,
    thumbprint: String,
    not_before: String,
    not_after: String,
}

/// Runs a one-shot collector through a scratch `EventBus` and maps
/// matching events to DTOs via `extract`. Shared by all four
/// "list_*" commands below so each one is a two-line body instead of
/// repeating the bus/subscribe/run/drain dance four times — the same
/// boilerplate `list_processes` still has inline (kept inline there
/// since it predates this helper and changing a working, simple
/// command isn't worth the churn for its own sake).
async fn collect_and_extract<C, T>(
    collector: C,
    extract: impl Fn(&Event) -> Option<T>,
) -> Result<Vec<T>, String>
where
    C: offgrd_core::Collector,
{
    let bus = EventBus::new();
    let mut subscription = bus.subscribe();
    collector.run(&bus).await.map_err(|e| e.to_string())?;

    let mut results = Vec::new();
    loop {
        match subscription.try_recv() {
            Ok(event) => {
                if let Some(item) = extract(&event) {
                    results.push(item);
                }
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }
    Ok(results)
}

#[tauri::command]
async fn list_network() -> Result<Vec<NetworkConnectionDto>, String> {
    collect_and_extract(offgrd_collectors::NetworkSnapshotCollector, |event| {
        match &event.payload {
            EventPayload::NetworkConnectionObserved {
                pid,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
            } => Some(NetworkConnectionDto {
                pid: *pid,
                local_addr: local_addr.clone(),
                local_port: *local_port,
                remote_addr: remote_addr.clone(),
                remote_port: *remote_port,
                state: state.clone(),
            }),
            _ => None,
        }
    })
    .await
}

#[tauri::command]
async fn list_autoruns() -> Result<Vec<AutorunEntryDto>, String> {
    collect_and_extract(offgrd_collectors::AutorunsCollector, |event| {
        match &event.payload {
            EventPayload::AutorunEntryObserved {
                hive,
                key_path,
                value_name,
                value_data,
            } => Some(AutorunEntryDto {
                hive: hive.clone(),
                key_path: key_path.clone(),
                value_name: value_name.clone(),
                value_data: value_data.clone(),
            }),
            _ => None,
        }
    })
    .await
}

#[tauri::command]
async fn list_services() -> Result<Vec<ServiceDto>, String> {
    collect_and_extract(offgrd_collectors::ServicesCollector, |event| {
        match &event.payload {
            EventPayload::ServiceObserved {
                service_name,
                display_name,
                state,
                service_type,
                ..
            } => Some(ServiceDto {
                service_name: service_name.clone(),
                display_name: display_name.clone(),
                state: state.clone(),
                service_type: service_type.clone(),
            }),
            _ => None,
        }
    })
    .await
}

#[tauri::command]
async fn list_certificates() -> Result<Vec<CertificateDto>, String> {
    collect_and_extract(offgrd_collectors::CertificatesCollector, |event| {
        match &event.payload {
            EventPayload::CertificateObserved {
                store_name,
                subject,
                issuer,
                thumbprint,
                not_before,
                not_after,
            } => Some(CertificateDto {
                store_name: store_name.clone(),
                subject: subject.clone(),
                issuer: issuer.clone(),
                thumbprint: thumbprint.clone(),
                not_before: not_before.to_rfc3339(),
                not_after: not_after.to_rfc3339(),
            }),
            _ => None,
        }
    })
    .await
}

/// Runs a fresh process snapshot through a scratch `EventBus`,
/// returning the flat list of processes. Same pattern as
/// `offgrd ps` in the CLI.
#[tauri::command]
async fn list_processes() -> Result<Vec<ProcessDto>, String> {
    let bus = EventBus::new();
    let mut subscription = bus.subscribe();
    let collector = ProcessSnapshotCollector;
    collector.run(&bus).await.map_err(|e| e.to_string())?;

    let mut processes = Vec::new();
    loop {
        match subscription.try_recv() {
            Ok(event) => {
                if let Some(dto) = process_to_dto(&event) {
                    processes.push(dto);
                }
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }

    Ok(processes)
}

/// Loads rules from the resolved rules directory (or an explicit
/// override), evaluates them against a fresh process snapshot, and
/// returns whatever matched. Mirrors `offgrd alerts` in the CLI.
#[tauri::command]
async fn run_alerts_scan(
    rules_dir: Option<String>,
    paths: tauri::State<'_, AppPaths>,
) -> Result<Vec<AlertDto>, String> {
    let dir = rules_dir.unwrap_or_else(|| paths.rules_dir.clone());
    let ruleset = RuleSet::load_dir(&dir).map_err(|e| e.to_string())?;

    let bus = EventBus::new();
    let mut subscription = bus.subscribe();
    let collector = ProcessSnapshotCollector;
    collector.run(&bus).await.map_err(|e| e.to_string())?;

    let mut events = Vec::new();
    loop {
        match subscription.try_recv() {
            Ok(event) => events.push(event),
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }

    let alerts = ruleset.evaluate_all(&events);
    Ok(alerts.iter().map(alert_to_dto).collect())
}

/// Reads back previously stored alerts (from the CLI's `--save`
/// flags, or the GUI's own always-on live monitor — see `live.rs`).
#[tauri::command]
fn get_alert_history(
    limit: Option<i64>,
    paths: tauri::State<'_, AppPaths>,
) -> Result<Vec<AlertDto>, String> {
    let store = EventStore::open(&paths.db_path).map_err(|e| e.to_string())?;
    let alerts = store
        .recent_alerts(limit.unwrap_or(100))
        .map_err(|e| e.to_string())?;
    Ok(alerts.iter().map(alert_to_dto).collect())
}

/// One call that populates the Dashboard view.
#[tauri::command]
async fn get_dashboard_summary(
    paths: tauri::State<'_, AppPaths>,
) -> Result<DashboardSummary, String> {
    let processes = list_processes().await?;

    let store = EventStore::open(&paths.db_path).map_err(|e| e.to_string())?;
    let stored_event_count = store.count().map_err(|e| e.to_string())?;
    let stored_alert_count = store.alert_count().map_err(|e| e.to_string())?;

    let (ruleset, rule_load_errors) =
        RuleSet::load_dir_report(&paths.rules_dir).map_err(|e| e.to_string())?;

    Ok(DashboardSummary {
        process_count: processes.len(),
        stored_event_count,
        stored_alert_count,
        loaded_rule_count: ruleset.len(),
        rule_load_errors,
        db_path: paths.db_path.clone(),
        rules_dir: paths.rules_dir.clone(),
    })
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let paths = AppPaths::resolve(&app.handle());
            let monitoring_state = MonitoringState(std::sync::Mutex::new(MonitoringMode::Normal));
            app.manage(paths.clone());
            app.manage(monitoring_state);
            live::spawn(app.handle(), paths);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_processes,
            run_alerts_scan,
            get_alert_history,
            get_dashboard_summary,
            list_rules,
            list_network,
            list_autoruns,
            list_services,
            list_certificates,
            list_modules,
            list_sessions,
            list_hosts_entries,
            list_startup_items,
            list_named_pipes,
            list_installed_programs,
            get_clipboard_snapshot,
            list_local_accounts,
            list_network_shares,
            get_foreground_window,
            list_environment_variables,
            list_dns_cache,
            get_idle_state,
            get_monitoring_mode,
            set_monitoring_mode,
        ])
        .run(tauri::generate_context!())
        .expect("error while running OffGrd Dog GUI");
}
