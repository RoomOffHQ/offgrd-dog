//! Active sessions (console + RDP) — `WTSEnumerateSessionsW`. Shows
//! every logon session on the machine, local or remote: "is someone
//! else logged into my machine right now" is one of the more
//! viscerally useful things this project can surface.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::Win32::System::RemoteDesktop::{
        WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName,
        WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
    };

    pub fn list_sessions() -> Result<Vec<Event>> {
        let mut session_info_ptr: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count: u32 = 0;

        // SAFETY: `WTS_CURRENT_SERVER_HANDLE` (local machine) is a
        // documented sentinel handle value requiring no separate
        // `WTSOpenServer` call; `session_info_ptr`/`count` are valid
        // out-parameters the API populates and which we free via
        // `WTSFreeMemory` below on every path.
        let ok = unsafe {
            WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut session_info_ptr, &mut count)
        };
        if !ok.as_bool() {
            anyhow::bail!("WTSEnumerateSessionsW failed");
        }

        struct MemGuard(*mut WTS_SESSION_INFOW);
        impl Drop for MemGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: `self.0` is the valid, non-null buffer
                    // returned by the successful enumeration call
                    // above, freed exactly once here.
                    unsafe { WTSFreeMemory(self.0 as *mut _) };
                }
            }
        }
        let _guard = MemGuard(session_info_ptr);

        // SAFETY: `session_info_ptr` was populated by the successful
        // call above with `count` entries of `WTS_SESSION_INFOW`, the
        // documented layout for this API — reading `count` entries
        // stays within the API-allocated buffer.
        let sessions: &[WTS_SESSION_INFOW] =
            unsafe { std::slice::from_raw_parts(session_info_ptr, count as usize) };

        Ok(sessions.iter().map(session_to_event).collect())
    }

    fn session_to_event(session: &WTS_SESSION_INFOW) -> Event {
        let station_name = pwstr_field_to_string(session.pWinStationName);
        let user_name = query_user_name(session.SessionId);

        Event::new(
            EventSource::Snapshot,
            EventCategory::Sessions,
            EventPayload::SessionObserved {
                session_id: session.SessionId,
                state: connect_state_label(session.State),
                station_name,
                user_name,
            },
        )
    }

    fn query_user_name(session_id: u32) -> Option<String> {
        let mut buffer_ptr: windows::core::PWSTR = windows::core::PWSTR::null();
        let mut bytes_returned: u32 = 0;

        // SAFETY: `WTS_CURRENT_SERVER_HANDLE` needs no separate open;
        // `session_id` is a value we just received from
        // `WTSEnumerateSessionsW`; `buffer_ptr`/`bytes_returned` are
        // valid out-parameters, freed via `WTSFreeMemory` below.
        let ok = unsafe {
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                session_id,
                WTSUserName,
                &mut buffer_ptr,
                &mut bytes_returned,
            )
        };
        if !ok.as_bool() || buffer_ptr.is_null() {
            return None;
        }

        // SAFETY: `buffer_ptr` is the valid, non-null buffer just
        // returned by the successful call above.
        let name = unsafe { buffer_ptr.to_string() }.unwrap_or_default();
        // SAFETY: freeing the same buffer exactly once, after we're
        // done reading it.
        unsafe { WTSFreeMemory(buffer_ptr.0 as *mut _) };

        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    fn pwstr_field_to_string(field: windows::core::PWSTR) -> String {
        if field.is_null() {
            return String::new();
        }
        // SAFETY: `field` is a fixed-size embedded wide-char array
        // within `WTS_SESSION_INFOW` (not a separately-owned
        // allocation), valid for as long as the containing struct is
        // alive, which covers this call.
        unsafe { field.to_string() }.unwrap_or_default()
    }

    fn connect_state_label(state: WTS_CONNECTSTATE_CLASS) -> String {
        match state.0 {
            0 => "Active",
            1 => "Connected",
            2 => "ConnectQuery",
            3 => "Shadow",
            4 => "Disconnected",
            5 => "Idle",
            6 => "Listen",
            7 => "Reset",
            8 => "Down",
            9 => "Init",
            other => return format!("Unknown({other})"),
        }
        .to_string()
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn list_sessions() -> Result<Vec<Event>> {
        anyhow::bail!("Sessions monitor uses the Remote Desktop Services API and is only implemented on Windows.")
    }
}

#[cfg(windows)]
pub use windows_impl::list_sessions;
#[cfg(not(windows))]
pub use other_impl::list_sessions;

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call.
pub struct SessionsCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for SessionsCollector {
    fn name(&self) -> &'static str {
        "sessions-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_sessions()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}
