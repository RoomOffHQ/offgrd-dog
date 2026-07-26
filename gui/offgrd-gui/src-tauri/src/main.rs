//! OffGrd Dog GUI — Tauri backend.
//!
//! This is intentionally a thin layer: every `#[tauri::command]` here
//! just calls into `offgrd-collectors`/`offgrd-core`/`offgrd-rules`,
//! the exact same crates `offgrd-cli` uses. The GUI has zero
//! detection/collection logic of its own — it's a consumer of the
//! pipeline, same as the CLI, just with a nicer front end. This keeps
//! the two UIs from silently drifting apart in behavior.
//!
//! Data-transfer types (`ProcessDto`, `AlertDto`, ...) are small,
//! JSON-friendly views over `offgrd-common` types rather than
//! `#[tauri::command]`-exposing the domain types directly — keeps the
//! JS-facing shape stable even if the internal `Event`/`Alert` schema
//! changes shape later.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use offgrd_collectors::ProcessSnapshotCollector;
use offgrd_common::{Event, EventPayload};
use offgrd_core::{Collector, EventBus, EventStore};
use offgrd_rules::RuleSet;
use serde::Serialize;
use tokio::sync::broadcast::error::TryRecvError;

/// Default rules directory, relative to wherever the app runs from —
/// mirrors the CLI's default. A real packaged app will need a proper
/// per-user data directory for this and for the database path; see
/// WIP.md.
const DEFAULT_RULES_DIR: &str = "rules";
const DEFAULT_DB_PATH: &str = "offgrd.db";

#[derive(Serialize, Clone)]
struct ProcessDto {
    pid: u32,
    ppid: Option<u32>,
    image_path: Option<String>,
    command_line: Option<String>,
}

#[derive(Serialize, Clone)]
struct AlertDto {
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
}

fn process_to_dto(event: &Event) -> Option<ProcessDto> {
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

fn alert_to_dto(alert: &offgrd_common::Alert) -> AlertDto {
    AlertDto {
        id: alert.id.to_string(),
        timestamp: alert.timestamp.to_rfc3339(),
        rule_id: alert.rule_id.clone(),
        rule_title: alert.rule_title.clone(),
        severity: format!("{:?}", alert.severity),
        triggering_event_id: alert.triggering_event_id.to_string(),
    }
}

/// Runs a fresh process snapshot through a scratch `EventBus`,
/// returning the flat list of processes. Same pattern as
/// `offgrd ps` in the CLI — see `offgrd-cli/src/main.rs::run_ps` for
/// the reference version this was copied from.
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

/// Loads rules from `rules_dir` (defaults to `rules/`), evaluates them
/// against a fresh process snapshot, and returns whatever matched.
/// Mirrors `offgrd alerts` in the CLI.
#[tauri::command]
async fn run_alerts_scan(rules_dir: Option<String>) -> Result<Vec<AlertDto>, String> {
    let rules_dir = rules_dir.unwrap_or_else(|| DEFAULT_RULES_DIR.to_string());
    let ruleset = RuleSet::load_dir(&rules_dir).map_err(|e| e.to_string())?;

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

/// Reads back previously stored alerts (via `offgrd alerts --save` or
/// `offgrd monitor --save-alerts` from the CLI, or a future
/// GUI-native "auto-save" toggle).
#[tauri::command]
fn get_alert_history(limit: Option<i64>) -> Result<Vec<AlertDto>, String> {
    let store = EventStore::open(DEFAULT_DB_PATH).map_err(|e| e.to_string())?;
    let alerts = store
        .recent_alerts(limit.unwrap_or(100))
        .map_err(|e| e.to_string())?;
    Ok(alerts.iter().map(alert_to_dto).collect())
}

/// One call that populates the Dashboard view: current process count
/// (fresh snapshot), how much history is stored, and whether the
/// bundled rules loaded cleanly.
#[tauri::command]
async fn get_dashboard_summary() -> Result<DashboardSummary, String> {
    let processes = list_processes().await?;

    let store = EventStore::open(DEFAULT_DB_PATH).map_err(|e| e.to_string())?;
    let stored_event_count = store.count().map_err(|e| e.to_string())?;
    let stored_alert_count = store.alert_count().map_err(|e| e.to_string())?;

    let (ruleset, rule_load_errors) =
        RuleSet::load_dir_report(DEFAULT_RULES_DIR).map_err(|e| e.to_string())?;

    Ok(DashboardSummary {
        process_count: processes.len(),
        stored_event_count,
        stored_alert_count,
        loaded_rule_count: ruleset.len(),
        rule_load_errors,
    })
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_processes,
            run_alerts_scan,
            get_alert_history,
            get_dashboard_summary,
        ])
        .run(tauri::generate_context!())
        .expect("error while running OffGrd Dog GUI");
}
