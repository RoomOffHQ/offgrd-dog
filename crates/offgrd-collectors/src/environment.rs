//! Environment Variables Inspector — this process's own environment
//! block, most useful for spotting PATH-hijacking-style tampering
//! (an entry prepended to PATH pointing at a writable, non-standard
//! directory is a classic technique). Reading *another* process's
//! environment needs the same PEB-access concerns already noted for
//! command lines elsewhere in this project — deliberately not
//! attempted; this covers `offgrd`'s own environment (which, since it
//! inherits its parent shell's environment, is still a reasonable
//! proxy for "what does this user's normal environment look like").
//!
//! Pure `std::env`, zero `unsafe` code.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

pub fn list_environment_variables() -> Result<Vec<Event>> {
    Ok(std::env::vars()
        .map(|(name, value)| {
            Event::new(
                EventSource::Snapshot,
                EventCategory::Environment,
                EventPayload::EnvironmentVariableObserved { name, value },
            )
        })
        .collect())
}

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call.
pub struct EnvironmentCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for EnvironmentCollector {
    fn name(&self) -> &'static str {
        "environment-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_environment_variables()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}
