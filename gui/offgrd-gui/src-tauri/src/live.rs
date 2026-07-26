//! Background live monitor for the GUI.
//!
//! Reads `MonitoringMode` (see `main.rs`) fresh on every loop
//! iteration via `AppHandle::state`, so switching modes in the UI
//! takes effect on the next tick without restarting the app:
//! - **Normal**: the loop just sleeps on a long interval and re-checks
//!   the mode — nothing runs in the background.
//! - **Moderate**: process-diff ticks only, relaxed interval.
//! - **Paranoid**: fast process-diff ticks, PLUS every Nth tick also
//!   runs the network/autoruns/services/certificates collectors and
//!   evaluates rules against everything they observe.
//!
//! Uses the same `offgrd_collectors::PollDiffer` the CLI's
//! `monitor.rs` uses for the process side. Pushes results to the
//! frontend via Tauri's event system (`AppHandle::emit_all`) rather
//! than printing to stdout.

use crate::{
    alert_to_dto, process_to_dto, AppPaths, MonitoringMode, MonitoringState,
};
use offgrd_collectors::{PollDiffer, PollTick};
use offgrd_core::{Collector, EventBus, EventStore};
use offgrd_rules::RuleSet;
use serde::Serialize;
use std::time::Duration;
use tauri::{AppHandle, Manager};

/// How long the loop sleeps in Normal mode before re-checking whether
/// the mode has changed. Short enough that switching to Moderate/
/// Paranoid from the UI feels responsive, long enough not to spin.
const NORMAL_MODE_IDLE_CHECK: Duration = Duration::from_secs(2);

/// A lightweight "something happened" notification for scan activity
/// that doesn't have a dedicated typed DTO/event yet (network,
/// autoruns, services, certificates) — powers the GUI's activity
/// toast/log without needing four more typed event channels.
#[derive(Serialize, Clone)]
struct ActivityNotice {
    category: String,
    message: String,
}

pub fn spawn(app_handle: AppHandle, paths: AppPaths) {
    tauri::async_runtime::spawn(async move {
        if let Err(err) = run(app_handle, paths).await {
            eprintln!("offgrd-gui: live monitor stopped with error: {err:#}");
        }
    });
}

fn current_mode(app_handle: &AppHandle) -> MonitoringMode {
    let state = app_handle.state::<MonitoringState>();
    *state.0.lock().expect("monitoring mode mutex poisoned")
}

async fn run(app_handle: AppHandle, paths: AppPaths) -> anyhow::Result<()> {
    let ruleset = RuleSet::load_dir(&paths.rules_dir)?;
    let store = EventStore::open(&paths.db_path)?;
    let mut differ = PollDiffer::new();
    let mut tick_count: u32 = 0;

    loop {
        let mode = current_mode(&app_handle);

        let Some(interval) = mode.process_poll_interval() else {
            // Normal mode: idle, just periodically re-check the mode.
            tokio::time::sleep(NORMAL_MODE_IDLE_CHECK).await;
            continue;
        };
        tokio::time::sleep(interval).await;

        // Re-check after sleeping: the mode may have changed to
        // Normal while we were asleep, or a Moderate/Paranoid
        // interval change should apply on the very next tick.
        let mode = current_mode(&app_handle);
        let Some(_) = mode.process_poll_interval() else {
            continue;
        };

        tick_count += 1;

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

        if mode.runs_full_spectrum_scans()
            && tick_count % mode.full_spectrum_scan_every_n_ticks() == 0
        {
            run_full_spectrum_scan(&app_handle, &store, &ruleset).await;
        }
    }
}

/// Paranoid-mode-only: runs the four "extra" collectors, persists
/// everything, evaluates rules against all of it, and emits a
/// lightweight activity notice per category so the GUI can show
/// something happened without needing four more typed DTO event
/// channels (those exist for the on-demand "Refresh" views already —
/// see `main.rs`'s `list_network`/`list_autoruns`/etc).
async fn run_full_spectrum_scan(app_handle: &AppHandle, store: &EventStore, ruleset: &RuleSet) {
    async fn collect<C: Collector>(collector: C) -> anyhow::Result<Vec<offgrd_common::Event>> {
        let bus = EventBus::new();
        let mut subscription = bus.subscribe();
        collector.run(&bus).await?;
        let mut events = Vec::new();
        loop {
            match subscription.try_recv() {
                Ok(event) => events.push(event),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
                | Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
            }
        }
        Ok(events)
    }

    let jobs: Vec<(&str, anyhow::Result<Vec<offgrd_common::Event>>)> = vec![
        (
            "network",
            collect(offgrd_collectors::NetworkSnapshotCollector).await,
        ),
        (
            "autoruns",
            collect(offgrd_collectors::AutorunsCollector).await,
        ),
        (
            "services",
            collect(offgrd_collectors::ServicesCollector).await,
        ),
        (
            "certificates",
            collect(offgrd_collectors::CertificatesCollector).await,
        ),
    ];

    for (category, result) in jobs {
        match result {
            Ok(events) => {
                for event in &events {
                    let _ = store.insert(event);
                }
                let alerts = ruleset.evaluate_all(&events);
                for alert in &alerts {
                    let _ = store.insert_alert(alert);
                    let _ = app_handle.emit_all("offgrd://alert-event", alert_to_dto(alert));
                }
                let _ = app_handle.emit_all(
                    "offgrd://activity",
                    ActivityNotice {
                        category: category.to_string(),
                        message: format!("Paranoid scan: {} {category} entries observed", events.len()),
                    },
                );
            }
            Err(err) => {
                eprintln!("offgrd-gui: paranoid scan of '{category}' failed: {err:#}");
            }
        }
    }
}
