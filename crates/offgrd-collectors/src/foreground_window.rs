//! Foreground Window Monitor — reports which window currently has
//! focus, via `GetForegroundWindow`/`GetWindowTextW`/
//! `GetWindowThreadProcessId`.
//!
//! **Deliberately a point-in-time snapshot, not a continuous
//! tracker.** A collector that logs every foreground-window change
//! over time is functionally adjacent to a keylogger/activity
//! monitor — a much more sensitive capability than anything else in
//! this project, and one this collector explicitly does NOT
//! implement. This only answers "what's focused right now, at the
//! moment you asked" (`offgrd foreground` / a manual GUI refresh),
//! the same one-shot-on-demand model as every other snapshot
//! collector — never a background poll loop recording history.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId};

    pub fn snapshot_foreground_window() -> Result<Event> {
        // SAFETY: `GetForegroundWindow` takes no arguments and simply
        // returns the current foreground window handle (or null if
        // none) — always safe to call.
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd == HWND(0) {
            return Ok(Event::new(
                EventSource::Snapshot,
                EventCategory::Activity,
                EventPayload::ForegroundWindowObserved {
                    window_title: String::new(),
                    pid: None,
                    process_image_path: None,
                },
            ));
        }

        let mut title_buf = [0u16; 512];
        // SAFETY: `hwnd` is a valid window handle just obtained above;
        // `title_buf` is a real, correctly-sized mutable buffer whose
        // capacity (as a length, not byte count — this is the `W`
        // Unicode variant) is passed to the API.
        let len = unsafe { GetWindowTextW(hwnd, &mut title_buf) };
        let window_title = String::from_utf16_lossy(&title_buf[..len.max(0) as usize]);

        let mut pid: u32 = 0;
        // SAFETY: `hwnd` is valid; `pid` is a valid out-parameter.
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };

        let process_image_path = if pid != 0 { full_image_path(pid) } else { None };

        Ok(Event::new(
            EventSource::Snapshot,
            EventCategory::Activity,
            EventPayload::ForegroundWindowObserved {
                window_title,
                pid: if pid != 0 { Some(pid) } else { None },
                process_image_path,
            },
        ))
    }

    /// Same best-effort pattern as `ProcessSnapshotCollector`'s
    /// `full_image_path` — returns `None` rather than erroring if the
    /// process can't be opened.
    fn full_image_path(pid: u32) -> Option<String> {
        // SAFETY: documented, low-privilege query handle open; may
        // legitimately fail for processes we can't access.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;

        struct HandleGuard(windows::Win32::Foundation::HANDLE);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                // SAFETY: valid handle from the successful open above.
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(self.0);
                }
            }
        }
        let _guard = HandleGuard(handle);

        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        // SAFETY: `handle` is valid; `buffer`/`size` describe a real,
        // sufficiently-sized mutable buffer per this API's contract.
        let ok = unsafe {
            QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, windows::core::PWSTR(buffer.as_mut_ptr()), &mut size)
        };
        if ok.is_err() {
            return None;
        }
        Some(String::from_utf16_lossy(&buffer[..size as usize]))
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn snapshot_foreground_window() -> Result<Event> {
        anyhow::bail!("Foreground Window Monitor uses the Win32 UI API and is only implemented on Windows.")
    }
}

#[cfg(windows)]
pub use windows_impl::snapshot_foreground_window;
#[cfg(not(windows))]
pub use other_impl::snapshot_foreground_window;

/// The `offgrd_core::Collector` wrapper. Publishes exactly one event
/// per `run()` call — see the module doc for why this is
/// deliberately snapshot-only, never a continuous tracker.
pub struct ForegroundWindowCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for ForegroundWindowCollector {
    fn name(&self) -> &'static str {
        "foreground-window-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        bus.publish(snapshot_foreground_window()?);
        Ok(())
    }
}
