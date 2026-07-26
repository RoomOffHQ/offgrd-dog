//! **EXPERIMENTAL — first pass, not yet verified to compile.**
//!
//! Live process start/stop events from the `Microsoft-Windows-Kernel-Process`
//! ETW provider, via the `ferrisetw` crate rather than hand-rolled
//! `windows`-crate ETW/TDH bindings (StartTrace/EnableTraceEx2/OpenTrace
//! + manual property parsing is a lot of surface area to get right
//! blind, in an environment where I can't compile against it myself).
//!
//! Unlike `ProcessSnapshotCollector` (point-in-time, one-shot), this
//! collector runs indefinitely: it starts an ETW session, and for
//! every process-start/stop event it receives, publishes an `Event`
//! onto the bus in real time. It needs to run on a background thread
//! (ferrisetw's trace processing loop is blocking), stopped via the
//! returned `EtwProcessCollector::stop()` handle rather than by
//! `Collector::run` ever returning on its own.
//!
//! Known unknowns to resolve once this compiles for the first time:
//! - Exact `ferrisetw` 1.x API surface (`Provider::by_guid` vs. `by_name`,
//!   `UserTrace` builder method names, `Parser::try_parse` generic
//!   bounds) — written from best recollection of the crate's public
//!   API, not verified against a pinned version's docs.
//! - Whether `Microsoft-Windows-Kernel-Process` needs to be enabled
//!   with specific keywords/level to receive process start (event ID
//!   1) and stop (event ID 2) — currently enabling with default
//!   level/keywords (everything).
//! - Whether this needs to run elevated. Historically, consuming this
//!   particular provider does not require admin (unlike the classic
//!   NT Kernel Logger), but that should be confirmed on a real machine.

use anyhow::{Context, Result};
use async_trait::async_trait;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceTrait, UserTrace};
use ferrisetw::EventRecord;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource, ProcessRef};
use offgrd_core::{Collector, EventBus};
use std::sync::mpsc;
use std::thread::JoinHandle;

/// GUID of the `Microsoft-Windows-Kernel-Process` provider. Stable
/// across Windows versions (it's a published, documented provider
/// GUID, unlike the event schema details above).
const KERNEL_PROCESS_PROVIDER_GUID: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";

/// Event ID for "process started" within this provider's manifest.
const EVENT_ID_PROCESS_START: u16 = 1;
/// Event ID for "process stopped/ended" within this provider's manifest.
const EVENT_ID_PROCESS_STOP: u16 = 2;

pub struct EtwProcessCollector;

#[async_trait]
impl Collector for EtwProcessCollector {
    fn name(&self) -> &'static str {
        "etw-kernel-process"
    }

    /// Starts the ETW session on a dedicated OS thread (ferrisetw's
    /// processing loop blocks), forwards decoded events back to this
    /// async context over a channel, and republishes them onto `bus`.
    /// Runs until the channel closes (i.e. the ETW thread exits/errors)
    /// — there is deliberately no fixed duration here; callers that
    /// want a bounded "watch for N seconds" behavior should wrap this
    /// with `tokio::time::timeout` rather than this collector growing
    /// its own timer.
    async fn run(&self, bus: &EventBus) -> Result<()> {
        let (tx, rx) = mpsc::channel::<Event>();

        let etw_thread = spawn_etw_thread(tx)?;

        // Bridge the blocking mpsc receiver into this async task by
        // polling it on a blocking thread pool via spawn_blocking,
        // rather than busy-looping `try_recv` on the async executor.
        let bus = bus.clone();
        let bridge = tokio::task::spawn_blocking(move || {
            while let Ok(event) = rx.recv() {
                bus.publish(event);
            }
        });

        bridge.await.context("ETW event bridge task panicked")?;
        etw_thread
            .join()
            .map_err(|_| anyhow::anyhow!("ETW collector thread panicked"))?
    }
}

fn spawn_etw_thread(tx: mpsc::Sender<Event>) -> Result<JoinHandle<Result<()>>> {
    let handle = std::thread::Builder::new()
        .name("offgrd-etw-kernel-process".into())
        .spawn(move || run_etw_session(tx))
        .context("failed to spawn ETW collector thread")?;
    Ok(handle)
}

/// Runs the actual ETW trace session. Blocks until the session is
/// stopped (either by the process exiting, or by a future
/// `EtwProcessCollector::stop()` handle we haven't added yet — see
/// WIP.md; this first pass only supports running until the whole
/// program exits).
fn run_etw_session(tx: mpsc::Sender<Event>) -> Result<()> {
    let callback = move |record: &EventRecord, schema_locator: &SchemaLocator| {
        if let Err(err) = handle_event(record, schema_locator, &tx) {
            eprintln!("offgrd: failed to decode ETW event: {err:#}");
        }
    };

    let provider = Provider::by_guid(KERNEL_PROCESS_PROVIDER_GUID)
        .add_callback(callback)
        .build();

    // `start_and_process` is expected to block for the lifetime of the
    // trace session, driving the callback above for every event.
    let _trace = UserTrace::new()
        .enable(provider)
        .start_and_process()
        .context("failed to start ETW trace session for Microsoft-Windows-Kernel-Process")?;

    Ok(())
}

fn handle_event(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    tx: &mpsc::Sender<Event>,
) -> Result<()> {
    let event_id = record.event_id();
    if event_id != EVENT_ID_PROCESS_START && event_id != EVENT_ID_PROCESS_STOP {
        return Ok(()); // Not a process start/stop event; ignore.
    }

    let schema = schema_locator
        .event_schema(record)
        .context("no schema found for event")?;
    let parser = Parser::create(record, &schema);

    if event_id == EVENT_ID_PROCESS_START {
        let pid: u32 = parser
            .try_parse("ProcessID")
            .context("missing ProcessID field")?;
        let parent_pid: Option<u32> = parser.try_parse("ParentProcessID").ok();
        let image_name: Option<String> = parser.try_parse("ImageName").ok();
        let command_line: Option<String> = parser.try_parse("CommandLine").ok();

        let mut process = ProcessRef::new(pid);
        if let Some(ppid) = parent_pid {
            process = process.with_parent(ppid);
        }
        if let Some(image) = image_name {
            process = process.with_image_path(image);
        }
        if let Some(cmd) = command_line {
            process = process.with_command_line(cmd);
        }

        let event = Event::new(
            EventSource::Etw,
            EventCategory::Process,
            EventPayload::ProcessStarted { process },
        );
        let _ = tx.send(event); // Receiver gone = shutting down; not an error here.
    } else {
        let pid: u32 = parser
            .try_parse("ProcessID")
            .context("missing ProcessID field")?;
        let exit_code: Option<i32> = parser.try_parse("ExitCode").ok();

        let event = Event::new(
            EventSource::Etw,
            EventCategory::Process,
            EventPayload::ProcessEnded { pid, exit_code },
        );
        let _ = tx.send(event);
    }

    Ok(())
}
