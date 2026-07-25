use crate::bus::EventBus;
use async_trait::async_trait;

/// Contract every data source implements: given a bus, run
/// (potentially forever, for a live collector like a future ETW
/// subscription; or once, for a snapshot-style collector like process
/// enumeration) and publish `Event`s as it observes them.
///
/// Deliberately minimal for this milestone — no lifecycle hooks
/// (start/stop/pause) yet, no error-recovery policy yet. Those get
/// added once we have a second, genuinely different collector
/// (ETW-based) to design against, rather than guessing the right
/// abstraction from one example.
#[async_trait]
pub trait Collector: Send + Sync {
    /// Short, stable, human-readable name for logging/diagnostics
    /// (e.g. "process-snapshot", "etw-kernel-process").
    fn name(&self) -> &'static str;

    /// Run the collector, publishing events to `bus` as they're
    /// observed. Returning `Ok(())` means the collector finished
    /// normally (fine for one-shot snapshot collectors); returning
    /// `Err` means it failed and the caller should decide whether to
    /// retry, log, or surface an alert about the collector itself.
    async fn run(&self, bus: &EventBus) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

    /// A trivial collector used only to prove the trait object works
    /// end-to-end through a real `EventBus` — this is the shape every
    /// future real collector (process snapshot, ETW, registry, etc.)
    /// will follow.
    struct OneShotNoteCollector {
        message: &'static str,
    }

    #[async_trait]
    impl Collector for OneShotNoteCollector {
        fn name(&self) -> &'static str {
            "one-shot-note"
        }

        async fn run(&self, bus: &EventBus) -> anyhow::Result<()> {
            bus.publish(Event::new(
                EventSource::Snapshot,
                EventCategory::Process,
                EventPayload::Note {
                    message: self.message.to_string(),
                },
            ));
            Ok(())
        }
    }

    #[tokio::test]
    async fn collector_publishes_to_bus() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let collector = OneShotNoteCollector { message: "hello" };

        collector.run(&bus).await.expect("collector should succeed");

        let event = rx.recv().await.expect("should receive published event");
        match event.payload {
            EventPayload::Note { message } => assert_eq!(message, "hello"),
            other => panic!("unexpected payload: {other:?}"),
        }
    }
}
