//! Polling-based "daemon-lite" monitor.
//!
//! `EtwProcessCollector` (see `etw_collector.rs`) is still experimental
//! and unverified, so real continuous monitoring shouldn't wait on it.
//! This module gets there a different, much lower-risk way: repeatedly
//! run the already-solid `ProcessSnapshotCollector` on a fixed
//! interval, diff each snapshot against the previous one by pid set,
//! and only treat *newly appeared* / *newly gone* pids as
//! start/stop events — so a 5-second poll loop doesn't re-report every
//! already-running process on every tick.
//!
//! This is intentionally not "the ETW collector but slower" — it's a
//! different tradeoff (coarser timing resolution, no command line,
//! polling overhead) that happens to be usable *today*. Once ETW is
//! verified working, `offgrd monitor` and the future ETW-based daemon
//! mode can coexist: polling as a robust fallback / non-admin path,
//! ETW as the higher-fidelity default.

use offgrd_collectors::ProcessSnapshotCollector;
use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};
use offgrd_core::{Collector, EventBus, EventStore};
use offgrd_rules::RuleSet;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::broadcast::error::TryRecvError;

pub struct MonitorConfig {
    pub interval: Duration,
    pub rules_dir: String,
    pub save_events: bool,
    pub save_alerts: bool,
    pub db_path: String,
    pub json: bool,
}

/// Runs the poll loop until Ctrl+C is received. Prints a running log
/// of process start/stop events and any triggered alerts as they
/// happen.
pub async fn run(config: MonitorConfig) -> Result<()> {
    let ruleset = RuleSet::load_dir(&config.rules_dir)?;
    eprintln!(
        "offgrd: monitor starting — polling every {:?}, {} rule(s) loaded from '{}'. Press Ctrl+C to stop.",
        config.interval,
        ruleset.len(),
        config.rules_dir
    );

    let store = if config.save_events || config.save_alerts {
        Some(EventStore::open(&config.db_path)?)
    } else {
        None
    };

    let mut previous_pids: HashSet<u32> = HashSet::new();
    let mut first_tick = true;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(config.interval) => {}
            _ = tokio::signal::ctrl_c() => {
                eprintln!("offgrd: Ctrl+C received, stopping monitor.");
                break;
            }
        }

        let snapshot = take_snapshot().await?;
        let current_pids: HashSet<u32> = snapshot.keys().copied().collect();

        if first_tick {
            // On the very first tick, everything currently running is
            // "pre-existing", not "newly started" — reporting a
            // start event for every process already on the system the
            // moment you launch offgrd would be noisy and misleading.
            // We still record the baseline so the *next* tick's diff
            // is meaningful.
            previous_pids = current_pids;
            first_tick = false;
            eprintln!(
                "offgrd: baseline captured ({} process(es) currently running).",
                previous_pids.len()
            );
            continue;
        }

        let started: Vec<u32> = current_pids.difference(&previous_pids).copied().collect();
        let stopped: Vec<u32> = previous_pids.difference(&current_pids).copied().collect();

        let mut new_events = Vec::new();
        for pid in &started {
            if let Some(process) = snapshot.get(pid) {
                new_events.push(Event::new(
                    EventSource::Snapshot,
                    EventCategory::Process,
                    EventPayload::ProcessStarted {
                        process: process.clone(),
                    },
                ));
            }
        }
        for pid in &stopped {
            new_events.push(Event::new(
                EventSource::Snapshot,
                EventCategory::Process,
                EventPayload::ProcessEnded {
                    pid: *pid,
                    exit_code: None, // Polling can't observe exit codes, only absence.
                },
            ));
        }

        for event in &new_events {
            print_event(event, config.json);
            if config.save_events {
                if let Some(store) = &store {
                    store.insert(event)?;
                }
            }
        }

        let alerts = ruleset.evaluate_all(&new_events);
        for alert in &alerts {
            print_alert(alert, config.json);
            if config.save_alerts {
                if let Some(store) = &store {
                    store.insert_alert(alert)?;
                }
            }
        }

        previous_pids = current_pids;
    }

    Ok(())
}

/// Runs one `ProcessSnapshotCollector` pass through a fresh bus and
/// returns the result keyed by pid for easy diffing.
async fn take_snapshot() -> Result<HashMap<u32, offgrd_common::ProcessRef>> {
    let bus = EventBus::new();
    let mut subscription = bus.subscribe();
    let collector = ProcessSnapshotCollector;
    collector.run(&bus).await?;

    let mut snapshot = HashMap::new();
    loop {
        match subscription.try_recv() {
            Ok(event) => {
                if let EventPayload::ProcessStarted { process } = event.payload {
                    snapshot.insert(process.pid, process);
                }
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }
    Ok(snapshot)
}

fn print_event(event: &Event, json: bool) {
    if json {
        if let Ok(line) = serde_json::to_string(event) {
            println!("{line}");
        }
        return;
    }

    match &event.payload {
        EventPayload::ProcessStarted { process } => {
            println!(
                "[START] {}  pid={:<8} ppid={}",
                event.timestamp.format("%H:%M:%S"),
                process.pid,
                process
                    .parent_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
            );
            if let Some(path) = &process.image_path {
                println!("          {path}");
            }
        }
        EventPayload::ProcessEnded { pid, .. } => {
            println!(
                "[STOP]  {}  pid={:<8}",
                event.timestamp.format("%H:%M:%S"),
                pid,
            );
        }
        _ => {}
    }
}

fn print_alert(alert: &offgrd_common::Alert, json: bool) {
    if json {
        if let Ok(line) = serde_json::to_string(alert) {
            println!("{line}");
        }
        return;
    }

    println!(
        "[ALERT] {}  {:?}  {} — {}",
        alert.timestamp.format("%H:%M:%S"),
        alert.severity,
        alert.rule_id,
        alert.rule_title,
    );
}
