use offgrd_common::Event;
use tokio::sync::broadcast;

/// Default channel capacity: how many events a slow subscriber can
/// lag behind before it starts missing events (it'll get a `Lagged`
/// error from `recv()`, which is recoverable — see `EventBus::subscribe`
/// docs). 4096 is a starting point, not a tuned constant; collectors
/// producing high-volume categories (filesystem, network) may need
/// their own bus or a larger capacity once those land.
const DEFAULT_CAPACITY: usize = 4096;

/// A cheap-to-clone, multi-producer multi-consumer broadcast bus for
/// `Event`s. Collectors call `publish`; consumers (storage, rule
/// engine, UI, CLI) call `subscribe` and read from the returned
/// receiver independently — each subscriber sees every event, there's
/// no queue-competition between them.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _receiver) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publishes an event to all current subscribers. Returns the
    /// number of subscribers it was delivered to (0 if none are
    /// currently listening — that's not an error, just means nobody's
    /// watching right now, e.g. during startup before storage has
    /// subscribed yet).
    pub fn publish(&self, event: Event) -> usize {
        self.sender.send(event).unwrap_or(0)
    }

    /// Subscribes to the bus. Each call returns an independent
    /// receiver that will see every event published *after* this call
    /// (not before — there's no history replay here; that's what
    /// storage + the timeline module are for). If a subscriber falls
    /// too far behind (doesn't call `recv()` often enough relative to
    /// `capacity`), its next `recv()` returns
    /// `Err(RecvError::Lagged(n))` rather than blocking forever or
    /// silently dropping data unnoticed — callers should log and keep
    /// going, not treat it as fatal.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use offgrd_common::{EventCategory, EventPayload, EventSource};

    fn sample_event() -> Event {
        Event::new(
            EventSource::Snapshot,
            EventCategory::Process,
            EventPayload::Note {
                message: "test".into(),
            },
        )
    }

    #[tokio::test]
    async fn subscriber_receives_published_event() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let sent = sample_event();
        let sent_id = sent.id;
        let delivered = bus.publish(sent);
        assert_eq!(delivered, 1);

        let received = rx.recv().await.expect("should receive the event");
        assert_eq!(received.id, sent_id);
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_does_not_error() {
        let bus = EventBus::new();
        let delivered = bus.publish(sample_event());
        assert_eq!(delivered, 0);
    }

    #[tokio::test]
    async fn multiple_subscribers_all_receive_the_same_event() {
        let bus = EventBus::new();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.publish(sample_event());

        let e1 = rx1.recv().await.expect("subscriber 1 receives");
        let e2 = rx2.recv().await.expect("subscriber 2 receives");
        assert_eq!(e1.id, e2.id);
    }
}
