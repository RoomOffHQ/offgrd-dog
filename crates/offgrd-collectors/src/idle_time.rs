//! Idle Time Monitor — how long since the last keyboard/mouse input,
//! via `GetLastInputInfo`. The lowest-security-relevance collector in
//! this batch, included mainly as a cheap, genuinely trivial API to
//! round out the snapshot — useful context alongside Sessions (e.g.
//! "this session shows Active but the machine has been idle for 6
//! hours" is a small, real signal).

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    pub fn snapshot_idle_time() -> Result<Event> {
        let mut info = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            ..Default::default()
        };

        // SAFETY: `info.cbSize` is set to the correct struct size as
        // required by the Win32 API contract; `info` is a valid
        // out-parameter the API populates with the tick count of the
        // last input event.
        let ok = unsafe { GetLastInputInfo(&mut info) };
        if !ok.as_bool() {
            anyhow::bail!("GetLastInputInfo failed");
        }

        // SAFETY: `GetTickCount` takes no arguments, always safe to call.
        let now = unsafe { GetTickCount() };
        let idle_ms = now.wrapping_sub(info.dwTime); // wrapping_sub handles the ~49-day tick counter wraparound.
        let idle_seconds = (idle_ms as u64) / 1000;

        Ok(Event::new(
            EventSource::Snapshot,
            EventCategory::Activity,
            EventPayload::IdleStateObserved { idle_seconds },
        ))
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn snapshot_idle_time() -> Result<Event> {
        anyhow::bail!("Idle Time Monitor uses the Win32 input API and is only implemented on Windows.")
    }
}

#[cfg(windows)]
pub use windows_impl::snapshot_idle_time;
#[cfg(not(windows))]
pub use other_impl::snapshot_idle_time;

/// The `offgrd_core::Collector` wrapper. Publishes exactly one event
/// per `run()` call.
pub struct IdleTimeCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for IdleTimeCollector {
    fn name(&self) -> &'static str {
        "idle-time-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        bus.publish(snapshot_idle_time()?);
        Ok(())
    }
}
