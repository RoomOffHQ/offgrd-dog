//! The first real `offgrd_core::Collector` implementation: wraps the
//! existing `platform::list_processes()` Win32 code so it publishes
//! onto a shared `EventBus` instead of being called directly. This is
//! deliberately a thin wrapper — all the actual Windows-API work
//! stays in `platform`, unchanged; this module only adapts it to the
//! `Collector` trait so `offgrd-cli` (and later, other consumers like
//! a GUI or a daemon) can treat "list processes" the same way as
//! every future collector (ETW, registry, network, ...).

use crate::platform;
use anyhow::Result;
use async_trait::async_trait;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};
use offgrd_core::{Collector, EventBus};

pub struct ProcessSnapshotCollector;

#[async_trait]
impl Collector for ProcessSnapshotCollector {
    fn name(&self) -> &'static str {
        "process-snapshot"
    }

    /// One-shot: enumerates processes right now and publishes one
    /// `Event::ProcessStarted` per process, then returns. Unlike a
    /// future ETW-based collector, this does not keep running — it's
    /// a point-in-time snapshot, which is exactly what Toolhelp32
    /// gives us.
    async fn run(&self, bus: &EventBus) -> Result<()> {
        let processes = platform::list_processes()?;

        for process in processes {
            bus.publish(Event::new(
                EventSource::Snapshot,
                EventCategory::Process,
                EventPayload::ProcessStarted { process },
            ));
        }

        Ok(())
    }
}
