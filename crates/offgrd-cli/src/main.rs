//! offgrd-cli — the very first runnable, tangible piece of OffGrd Dog.
//!
//! Scope on purpose: enumerate running processes and print them, either
//! as a table or as JSON (`Event` envelopes from offgrd-common). No
//! driver, no ETW, no admin rights required. Under the hood, `ps` now
//! runs as an `offgrd_core::Collector` publishing onto an `EventBus`
//! rather than being called directly — every future collector
//! (network, registry, filesystem, ETW-based process monitoring) will
//! plug into the same pipeline.

mod collector;
#[cfg(windows)]
mod etw_collector;
mod platform;

use anyhow::Result;
use clap::{Parser, Subcommand};
use collector::ProcessSnapshotCollector;
use offgrd_common::{Event, EventPayload};
use offgrd_core::{Collector, EventBus, EventStore};
use tokio::sync::broadcast::error::TryRecvError;

/// Default location of the event store database, relative to the
/// current working directory. A real install will move this to a
/// proper per-user data directory; kept simple and visible for now.
const DEFAULT_DB_PATH: &str = "offgrd.db";

#[derive(Parser)]
#[command(
    name = "offgrd",
    version,
    about = "OffGrd Dog CLI — Know Everything. Trust Nothing."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Emit machine-readable JSON (one Event per line) instead of a table.
    #[arg(long, global = true)]
    json: bool,

    /// Path to the SQLite event store database.
    #[arg(long, global = true, default_value = DEFAULT_DB_PATH)]
    db: String,
}

#[derive(Subcommand)]
enum Command {
    /// List currently running processes.
    Ps {
        /// Render as an indented parent -> child tree instead of a flat table.
        #[arg(long)]
        tree: bool,

        /// Persist the collected events to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// Show previously stored events from the event store (--db).
    History {
        /// Maximum number of events to show, most recent first.
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// (Windows only, EXPERIMENTAL) Watch live process start/stop
    /// events via ETW instead of polling. Runs until Ctrl+C or
    /// --seconds elapses.
    Watch {
        /// Stop automatically after this many seconds (0 = run until Ctrl+C).
        #[arg(long, default_value_t = 0)]
        seconds: u64,

        /// Also persist watched events to the event store (--db).
        #[arg(long)]
        save: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Ps { tree, save } => run_ps(cli.json, tree, save, &cli.db).await,
        Command::History { limit } => run_history(cli.json, limit, &cli.db),
        Command::Watch { seconds, save } => run_watch(cli.json, seconds, save, &cli.db).await,
    }
}

#[cfg(windows)]
async fn run_watch(json: bool, seconds: u64, save: bool, db_path: &str) -> Result<()> {
    use etw_collector::EtwProcessCollector;

    let bus = EventBus::new();
    let mut subscription = bus.subscribe();
    let collector = EtwProcessCollector;

    eprintln!(
        "offgrd: watching Microsoft-Windows-Kernel-Process via ETW{}. Press Ctrl+C to stop.",
        if seconds > 0 {
            format!(" for {seconds}s")
        } else {
            String::new()
        }
    );

    let store = if save {
        Some(EventStore::open(db_path)?)
    } else {
        None
    };

    // Run the (indefinitely-blocking) collector concurrently with a
    // print/store loop that drains the bus as events arrive, and stop
    // both when either Ctrl+C fires, --seconds elapses, or the
    // collector itself errors out.
    let printer = async {
        loop {
            match subscription.recv().await {
                Ok(event) => {
                    if let Some(store) = &store {
                        if let Err(err) = store.insert(&event) {
                            eprintln!("offgrd: failed to store event: {err:#}");
                        }
                    }
                    if json {
                        if let Ok(line) = serde_json::to_string(&event) {
                            println!("{line}");
                        }
                    } else {
                        print_watch_line(&event);
                    }
                }
                Err(_) => break, // Bus closed: collector side ended.
            }
        }
    };

    let timeout = async {
        if seconds > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    tokio::select! {
        result = collector.run(&bus) => { result?; }
        _ = printer => {}
        _ = timeout => { eprintln!("offgrd: --seconds elapsed, stopping."); }
        _ = tokio::signal::ctrl_c() => { eprintln!("offgrd: Ctrl+C received, stopping."); }
    }

    Ok(())
}

#[cfg(not(windows))]
async fn run_watch(_json: bool, _seconds: u64, _save: bool, _db_path: &str) -> Result<()> {
    anyhow::bail!(
        "`offgrd watch` uses ETW and is only implemented on Windows. Build and run this on Windows 10/11."
    )
}

#[cfg(windows)]
fn print_watch_line(event: &Event) {
    match &event.payload {
        EventPayload::ProcessStarted { process } => {
            println!(
                "[START] pid={:<8} ppid={:<8} {}",
                process.pid,
                process
                    .parent_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                process.image_path.as_deref().unwrap_or("-"),
            );
        }
        EventPayload::ProcessEnded { pid, exit_code } => {
            println!(
                "[STOP]  pid={:<8} exit_code={}",
                pid,
                exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
        }
        _ => {}
    }
}

/// Runs the process-snapshot collector through a real `EventBus` and
/// renders whatever it published. The bus/collector plumbing here is
/// intentionally visible (not hidden behind a one-liner) since this
/// is the reference example every future subcommand will copy.
async fn run_ps(json: bool, tree: bool, save: bool, db_path: &str) -> Result<()> {
    let bus = EventBus::new();
    let mut subscription = bus.subscribe();

    let collector = ProcessSnapshotCollector;
    collector.run(&bus).await?;

    // The collector is one-shot and has already returned, so every
    // event it published is sitting in our subscription's buffer now.
    // Drain it with try_recv rather than recv().await: there is no
    // more data coming on this bus, so awaiting would hang forever
    // once the buffer is empty.
    let mut events: Vec<Event> = Vec::new();
    loop {
        match subscription.try_recv() {
            Ok(event) => events.push(event),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Lagged(skipped)) => {
                eprintln!("warning: process-snapshot collector output was truncated, {skipped} event(s) dropped (bus capacity exceeded)");
            }
            Err(TryRecvError::Closed) => break,
        }
    }

    if save {
        let store = EventStore::open(db_path)?;
        for event in &events {
            store.insert(event)?;
        }
        eprintln!("saved {} event(s) to {db_path}", events.len());
    }

    if json {
        for event in &events {
            println!("{}", serde_json::to_string(event)?);
        }
        return Ok(());
    }

    if tree {
        print_tree(&events);
        return Ok(());
    }

    println!("{:>8}  {:>8}  {:<40}  COMMAND LINE", "PID", "PPID", "IMAGE");
    for event in &events {
        let EventPayload::ProcessStarted { process } = &event.payload else {
            continue;
        };
        println!(
            "{:>8}  {:>8}  {:<40}  {}",
            process.pid,
            process
                .parent_pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            process.image_path.as_deref().unwrap_or("-"),
            process.command_line.as_deref().unwrap_or(""),
        );
    }

    Ok(())
}

/// Reads back previously stored events from the event store — proves
/// the storage round-trip end to end via the CLI, independent of the
/// unit tests in `offgrd-core`.
fn run_history(json: bool, limit: i64, db_path: &str) -> Result<()> {
    let store = EventStore::open(db_path)?;
    let events = store.recent(limit)?;

    if events.is_empty() {
        eprintln!("no events stored in {db_path} yet — try `offgrd ps --save` first");
        return Ok(());
    }

    if json {
        for event in &events {
            println!("{}", serde_json::to_string(event)?);
        }
        return Ok(());
    }

    println!(
        "{:<24}  {:>8}  {:>8}  IMAGE",
        "TIMESTAMP (UTC)", "PID", "PPID"
    );
    for event in &events {
        if let EventPayload::ProcessStarted { process } = &event.payload {
            println!(
                "{:<24}  {:>8}  {:>8}  {}",
                event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                process.pid,
                process
                    .parent_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                process.image_path.as_deref().unwrap_or("-"),
            );
        }
    }

    Ok(())
}

/// Renders the flat process list as an indented parent -> child tree.
///
/// Roots are processes whose `parent_pid` doesn't correspond to any
/// pid we actually saw in this snapshot (either it's pid 0/4/System,
/// or the parent already exited — both are normal). This is a display
/// concern only: no cycle-detection subtlety needed since we do a
/// straightforward recursive walk over a pid->children map and guard
/// against re-visiting a pid via `visited`.
fn print_tree(events: &[Event]) {
    use std::collections::{HashMap, HashSet};

    let mut by_pid: HashMap<u32, &offgrd_common::ProcessRef> = HashMap::new();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();

    for event in events {
        if let EventPayload::ProcessStarted { process } = &event.payload {
            by_pid.insert(process.pid, process);
        }
    }
    for process in by_pid.values() {
        if let Some(ppid) = process.parent_pid {
            if by_pid.contains_key(&ppid) && ppid != process.pid {
                children.entry(ppid).or_default().push(process.pid);
            }
        }
    }

    let all_pids: HashSet<u32> = by_pid.keys().copied().collect();
    let child_pids: HashSet<u32> = children.values().flatten().copied().collect();
    let mut roots: Vec<u32> = all_pids.difference(&child_pids).copied().collect();
    roots.sort_unstable();

    let mut visited: HashSet<u32> = HashSet::new();
    for root in roots {
        print_node(root, 0, &by_pid, &children, &mut visited);
    }
}

fn print_node(
    pid: u32,
    depth: usize,
    by_pid: &std::collections::HashMap<u32, &offgrd_common::ProcessRef>,
    children: &std::collections::HashMap<u32, Vec<u32>>,
    visited: &mut std::collections::HashSet<u32>,
) {
    if !visited.insert(pid) {
        return; // Defensive: avoid infinite loop if data is ever malformed.
    }

    if let Some(process) = by_pid.get(&pid) {
        let indent = "  ".repeat(depth);
        let name = process.image_path.as_deref().unwrap_or("-");
        println!("{indent}├─ [{pid}] {name}");
    }

    if let Some(kids) = children.get(&pid) {
        let mut kids = kids.clone();
        kids.sort_unstable();
        for kid in kids {
            print_node(kid, depth + 1, by_pid, children, visited);
        }
    }
}
