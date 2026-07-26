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
use serde::Serialize;
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
            live::spawn(app.handle(), paths.clone());
            app.manage(paths);
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running OffGrd Dog GUI");
}
