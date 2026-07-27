//! Named Pipes Monitor — enumerates visible named pipes under
//! `\\.\pipe\`. Reveals inter-process communication channels; some
//! services and malware families use recognizably-named pipes, and
//! an unexpectedly-named or unusually-permissioned pipe is a real
//! signal worth being able to see. Simple `FindFirstFileW`/
//! `FindNextFileW` walk — the same file-enumeration API family
//! Explorer itself uses under the hood, just pointed at the special
//! `\\.\pipe\` namespace.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, FindNextFileW, WIN32_FIND_DATAW};

    pub fn list_named_pipes() -> Result<Vec<Event>> {
        let pattern = to_wide(r"\\.\pipe\*");
        let mut find_data = WIN32_FIND_DATAW::default();

        // SAFETY: `pattern` is a valid, NUL-terminated wide string
        // alive for the duration of this call; `find_data` is a valid
        // out-parameter the API populates with the first match.
        let handle = unsafe { FindFirstFileW(PCWSTR(pattern.as_ptr()), &mut find_data) };
        let handle = match handle {
            Ok(h) => h,
            Err(_) => return Ok(Vec::new()), // No pipes visible — not an error.
        };

        struct FindGuard(windows::Win32::Foundation::HANDLE);
        impl Drop for FindGuard {
            fn drop(&mut self) {
                // SAFETY: `self.0` is the valid find-handle from the
                // successful call above, not yet closed.
                unsafe {
                    let _ = FindClose(self.0);
                }
            }
        }
        let _guard = FindGuard(handle);

        let mut events = Vec::new();
        loop {
            let name = wide_to_string(&find_data.cFileName);
            if !name.is_empty() {
                events.push(Event::new(
                    EventSource::Snapshot,
                    EventCategory::File,
                    EventPayload::NamedPipeObserved { pipe_name: name },
                ));
            }

            // SAFETY: `handle` is a valid, still-open find handle;
            // `find_data` is reused as the out-parameter for the next
            // match, same contract as the initial call.
            if unsafe { FindNextFileW(handle, &mut find_data) }.is_err() {
                break; // ERROR_NO_MORE_FILES: normal end of enumeration.
            }
        }

        Ok(events)
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_to_string(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn list_named_pipes() -> Result<Vec<Event>> {
        anyhow::bail!("Named Pipes Monitor is a Windows-specific concept and is only implemented on Windows.")
    }
}

#[cfg(windows)]
pub use windows_impl::list_named_pipes;
#[cfg(not(windows))]
pub use other_impl::list_named_pipes;

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call.
pub struct NamedPipesCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for NamedPipesCollector {
    fn name(&self) -> &'static str {
        "named-pipes-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_named_pipes()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}
