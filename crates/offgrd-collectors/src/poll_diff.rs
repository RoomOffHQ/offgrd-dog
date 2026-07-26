//! Shared "poll a snapshot, diff against the previous one" logic.
//!
//! Both `offgrd-cli`'s `monitor` command and `offgrd-gui`'s always-on
//! live view need the same thing: take a `ProcessSnapshotCollector`
//! snapshot on an interval, and turn it into "what's new" (processes
//! that appeared/disappeared since last time) rather than re-reporting
//! everything that's already running on every tick. That logic used to
//! be copy-pasted in both places; it lives here now so there's exactly
//! one implementation to get right.
//!
//! This module deliberately does NOT own the interval/sleep loop,
//! rule evaluation, storage, or how results get displayed/emitted —
//! callers (CLI, GUI) differ a lot on those fronts (print to stdout vs.
//! Tauri events, `--seconds` timeout vs. Ctrl+C only, etc.) and forcing
//! a shared abstraction over that part would be premature. `PollDiffer`
//! only owns the one genuinely shared, easy-to-get-subtly-wrong bit:
//! the pid-set diffing and "first tick is a baseline, not a burst of
//! false start events" rule.

use crate::ProcessSnapshotCollector;
use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource, ProcessRef};
use offgrd_core::{Collector, EventBus};
use std::collections::{HashMap, HashSet};
use tokio::sync::broadcast::error::TryRecvError;

/// The result of one `PollDiffer::tick()` call.
pub enum PollTick {
    /// The very first tick: no previous snapshot to diff against, so
    /// this is just establishing the baseline. `process_count` is
    /// informational (e.g. for a log line like "baseline captured (42
    /// processes)"), not something callers need to act on.
    Baseline { process_count: usize },
    /// Every subsequent tick: the process-start/stop events observed
    /// since the previous tick. May be empty if nothing changed.
    Diff(Vec<Event>),
}

/// Holds the diffing state (previous pid set, whether we've taken a
/// baseline yet) between ticks. Callers own the interval/timing;
/// this just needs `tick()` called repeatedly.
#[derive(Default)]
pub struct PollDiffer {
    previous_pids: HashSet<u32>,
    has_baseline: bool,
}

impl PollDiffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes a fresh process snapshot and diffs it against the
    /// previous call's snapshot. The very first call always returns
    /// `PollTick::Baseline` and never `PollTick::Diff`, regardless of
    /// what's running — see the module doc for why.
    pub async fn tick(&mut self) -> Result<PollTick> {
        let snapshot = take_snapshot().await?;
        let current_pids: HashSet<u32> = snapshot.keys().copied().collect();

        if !self.has_baseline {
            self.previous_pids = current_pids;
            self.has_baseline = true;
            return Ok(PollTick::Baseline {
                process_count: self.previous_pids.len(),
            });
        }

        let started: Vec<u32> = current_pids
            .difference(&self.previous_pids)
            .copied()
            .collect();
        let stopped: Vec<u32> = self
            .previous_pids
            .difference(&current_pids)
            .copied()
            .collect();

        let mut events = Vec::with_capacity(started.len() + stopped.len());
        for pid in &started {
            if let Some(process) = snapshot.get(pid) {
                events.push(Event::new(
                    EventSource::Snapshot,
                    EventCategory::Process,
                    EventPayload::ProcessStarted {
                        process: process.clone(),
                    },
                ));
            }
        }
        for pid in &stopped {
            events.push(Event::new(
                EventSource::Snapshot,
                EventCategory::Process,
                EventPayload::ProcessEnded {
                    pid: *pid,
                    exit_code: None, // Polling can't observe exit codes, only absence.
                },
            ));
        }

        self.previous_pids = current_pids;
        Ok(PollTick::Diff(events))
    }
}

/// Runs one `ProcessSnapshotCollector` pass through a fresh bus and
/// returns the result keyed by pid for easy diffing.
async fn take_snapshot() -> Result<HashMap<u32, ProcessRef>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_tick_is_always_a_baseline() {
        let mut differ = PollDiffer::new();
        match differ.tick().await.expect("tick should succeed") {
            PollTick::Baseline { .. } => {}
            PollTick::Diff(_) => panic!("first tick should be a Baseline, not a Diff"),
        }
    }

    #[tokio::test]
    async fn second_tick_is_a_diff() {
        let mut differ = PollDiffer::new();
        differ.tick().await.expect("first tick");
        match differ.tick().await.expect("second tick") {
            PollTick::Diff(_) => {}
            PollTick::Baseline { .. } => panic!("second tick should be a Diff, not a Baseline"),
        }
    }
}
