//! Clipboard Monitor — snapshots the current clipboard's text content
//! via `OpenClipboard`/`GetClipboardData(CF_UNICODETEXT)`.
//!
//! **This is a genuinely privacy-sensitive capability.** It reads
//! whatever text is currently on the user's own clipboard — which is
//! exactly the point (clipboard-hijacking malware, e.g. crypto-
//! address-swapping clippers, is a real threat this can help a user
//! notice), but it's flagged prominently here, in the CLI help text,
//! and in the GUI rather than being a quiet background capability.
//! Text formats only for this first pass — no images, no file lists.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
    use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    /// Returns the current clipboard's text content, or `None` if the
    /// clipboard is empty, contains no text format, or can't be
    /// opened right now (e.g. another process is holding it open —
    /// transient and not worth treating as an error).
    pub fn read_clipboard_text() -> Result<Option<String>> {
        // SAFETY: `OpenClipboard(None)` (null hwnd = associate with
        // the current task, not a specific window) is the documented
        // way to open the clipboard without owning a window; we close
        // it via `CloseClipboard` on every path below.
        let opened = unsafe { OpenClipboard(HWND(0)) };
        if opened.is_err() {
            return Ok(None); // Couldn't open right now — treat as "nothing observed," not an error.
        }

        struct ClipboardGuard;
        impl Drop for ClipboardGuard {
            fn drop(&mut self) {
                // SAFETY: we only construct this guard after a
                // successful `OpenClipboard`, so closing here is
                // always paired correctly.
                unsafe {
                    let _ = CloseClipboard();
                }
            }
        }
        let _guard = ClipboardGuard;

        // SAFETY: the clipboard is open (guard above proves it); a
        // null return means no CF_UNICODETEXT data is present, which
        // we handle as "no text," not an error.
        let handle = unsafe { GetClipboardData(CF_UNICODETEXT.0.into()) };
        let Ok(handle) = handle else {
            return Ok(None);
        };
        if handle.is_invalid() {
            return Ok(None);
        }

        // SAFETY: `handle` is a valid global memory handle owned by
        // the clipboard (per `GetClipboardData`'s contract for
        // CF_UNICODETEXT specifically — a global memory block of
        // NUL-terminated UTF-16 text); `GlobalLock` returns a pointer
        // valid until the matching `GlobalUnlock` below.
        let ptr = unsafe { GlobalLock(windows::Win32::Foundation::HGLOBAL(handle.0)) };
        if ptr.is_null() {
            return Ok(None);
        }

        // SAFETY: `ptr` points at NUL-terminated UTF-16 text per the
        // CF_UNICODETEXT format contract; we only read up to the NUL
        // terminator, never past it, and only for the duration before
        // `GlobalUnlock` below (the pointer isn't retained afterward).
        let text = unsafe {
            let wide_ptr = ptr as *const u16;
            let mut len = 0usize;
            while *wide_ptr.add(len) != 0 {
                len += 1;
                if len > 1_000_000 {
                    break; // Sanity cap — never trust an unbounded scan on external data.
                }
            }
            let slice = std::slice::from_raw_parts(wide_ptr, len);
            String::from_utf16_lossy(slice)
        };

        // SAFETY: unlocking the same handle locked above, exactly once.
        unsafe {
            let _ = GlobalUnlock(windows::Win32::Foundation::HGLOBAL(handle.0));
        }

        if text.is_empty() {
            Ok(None)
        } else {
            Ok(Some(text))
        }
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn read_clipboard_text() -> Result<Option<String>> {
        anyhow::bail!("Clipboard Monitor uses the Windows clipboard API and is only implemented on Windows.")
    }
}

#[cfg(windows)]
pub use windows_impl::read_clipboard_text;
#[cfg(not(windows))]
pub use other_impl::read_clipboard_text;

/// The `offgrd_core::Collector` wrapper. Publishes zero or one event
/// (empty clipboard / no text format = zero events, not an error).
pub struct ClipboardCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for ClipboardCollector {
    fn name(&self) -> &'static str {
        "clipboard-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        if let Some(text) = read_clipboard_text()? {
            bus.publish(Event::new(
                EventSource::Snapshot,
                EventCategory::Clipboard,
                EventPayload::ClipboardTextObserved { text },
            ));
        }
        Ok(())
    }
}
