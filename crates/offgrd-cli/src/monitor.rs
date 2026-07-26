//! Polling-based "daemon-lite" monitor.
//!
//! `EtwProcessCollector` (see `offgrd-collectors::etw_collector`) is
//! still experimental and unverified, so real continuous monitoring
//! shouldn't wait on it. This module gets there a different, much
//! lower-risk way: repeatedly diff process snapshots on a fixed
//! interval via `offgrd_collectors::PollDiffer` (shared with the GUI's
//! live view — see `gui/offgrd-gui/src-tauri/src/live.rs` — so there's
//! exactly one implementation of the diffing logic itself).
//!
//! This is intentionally not "the ETW collector but slower" — it's a
//! different tradeoff (coarser timing resolution, no command line,
//! polling overhead) that happens to be usable *today*.

use anyhow::Result;
use offgrd_collectors::{PollDiffer, PollTick};
use offgrd_common::{Event, EventPayload};
use offgrd_core::EventStore;
use offgrd_rules::RuleSet;
use std::time::Duration;

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

    let mut differ = PollDiffer::new();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(config.interval) => {}
            _ = tokio::signal::ctrl_c() => {
                eprintln!("offgrd: Ctrl+C received, stopping monitor.");
                break;
            }
        }

        let tick = differ.tick().await?;
        let new_events = match tick {
            PollTick::Baseline { process_count } => {
                eprintln!("offgrd: baseline captured ({process_count} process(es) currently running).");
                continue;
            }
            PollTick::Diff(events) => events,
        };

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
    }

    Ok(())
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
