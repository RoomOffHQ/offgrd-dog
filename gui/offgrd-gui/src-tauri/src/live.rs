//! Background live monitor for the GUI.
//!
//! Uses the same `offgrd_collectors::PollDiffer` the CLI's
//! `monitor.rs` uses (previously this was a second, hand-copied
//! implementation of the polling-diff logic — now there's exactly
//! one). This module only owns what's genuinely GUI-specific: the
//! interval loop, persisting to the GUI's resolved `EventStore`, and
//! pushing results to the frontend via Tauri's event system
//! (`AppHandle::emit_all`) instead of printing to stdout.
//!
//! JS side listens with:
//! ```js
//! window.__TAURI__.event.listen('offgrd://process-event', (e) => { ... });
//! window.__TAURI__.event.listen('offgrd://alert-event', (e) => { ... });
//! ```

use crate::{alert_to_dto, process_to_dto, AppPaths};
use offgrd_collectors::{PollDiffer, PollTick};
use offgrd_core::EventStore;
use offgrd_rules::RuleSet;
use std::time::Duration;
use tauri::{AppHandle, Manager};

const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Spawns the live monitor as a background task via Tauri's own async
/// runtime handle (`tauri::async_runtime::spawn`, not raw
/// `tokio::spawn` — Tauri manages its own runtime and this is the
/// documented-portable way to spawn background work from it).
/// Fire-and-forget from `main.rs`'s `setup` hook — errors inside the
/// loop are logged to stderr rather than propagated, since there's no
/// caller left to hand them to once the task is spawned.
pub fn spawn(app_handle: AppHandle, paths: AppPaths) {
    tauri::async_runtime::spawn(async move {
        if let Err(err) = run(app_handle, paths).await {
            eprintln!("offgrd-gui: live monitor stopped with error: {err:#}");
        }
    });
}

async fn run(app_handle: AppHandle, paths: AppPaths) -> anyhow::Result<()> {
    let ruleset = RuleSet::load_dir(&paths.rules_dir)?;
    let store = EventStore::open(&paths.db_path)?;
    let mut differ = PollDiffer::new();

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        let new_events = match differ.tick().await? {
            PollTick::Baseline { .. } => continue,
            PollTick::Diff(events) => events,
        };

        for event in &new_events {
            let _ = store.insert(event);
            if let Some(dto) = process_to_dto(event) {
                let _ = app_handle.emit_all("offgrd://process-event", &dto);
            }
        }

        let alerts = ruleset.evaluate_all(&new_events);
        for alert in &alerts {
            let _ = store.insert_alert(alert);
            let _ = app_handle.emit_all("offgrd://alert-event", alert_to_dto(alert));
        }
    }
}
