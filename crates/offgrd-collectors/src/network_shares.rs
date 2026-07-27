//! Network Shares Monitor — enumerates local SMB shares via
//! `NetShareEnum`. Reveals unexpected file sharing — a share someone
//! doesn't remember creating (or one malware quietly added for
//! lateral movement/exfiltration) is a real, visible signal.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetShareEnum, MAX_PREFERRED_LENGTH, SHARE_INFO_2,
    };

    pub fn list_shares() -> Result<Vec<Event>> {
        let mut buffer: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        let mut resume_handle: u32 = 0;

        // SAFETY: level 2 (`SHARE_INFO_2`, includes path/comment) with
        // a null server name targets the local machine, a documented,
        // standard call; `buffer` is freed via `NetApiBufferFree`
        // below on every path.
        let status = unsafe {
            NetShareEnum(
                None,
                2,
                &mut buffer,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                Some(&mut resume_handle),
            )
        };
        if status != 0 {
            anyhow::bail!("NetShareEnum failed with code {status}");
        }

        struct BufferGuard(*mut u8);
        impl Drop for BufferGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: valid buffer from the successful call
                    // above, freed exactly once.
                    unsafe {
                        let _ = NetApiBufferFree(Some(self.0 as *mut _));
                    }
                }
            }
        }
        let _guard = BufferGuard(buffer);

        // SAFETY: `buffer` was populated with `entries_read` entries
        // of `SHARE_INFO_2`, the documented layout for level-2
        // `NetShareEnum`.
        let shares: &[SHARE_INFO_2] = unsafe {
            std::slice::from_raw_parts(buffer as *const SHARE_INFO_2, entries_read as usize)
        };

        Ok(shares.iter().map(share_to_event).collect())
    }

    fn share_to_event(share: &SHARE_INFO_2) -> Event {
        Event::new(
            EventSource::Snapshot,
            EventCategory::Network,
            EventPayload::NetworkShareObserved {
                share_name: pwstr_to_string(share.shi2_netname),
                local_path: optional_pwstr_to_string(share.shi2_path),
                comment: optional_pwstr_to_string(share.shi2_remark),
            },
        )
    }

    fn pwstr_to_string(pwstr: windows::core::PWSTR) -> String {
        if pwstr.is_null() {
            return String::new();
        }
        // SAFETY: caller guarantees this points at a valid,
        // NUL-terminated wide string owned by the enumeration buffer,
        // alive for the duration of this call.
        unsafe { pwstr.to_string() }.unwrap_or_default()
    }

    fn optional_pwstr_to_string(pwstr: windows::core::PWSTR) -> Option<String> {
        let s = pwstr_to_string(pwstr);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn list_shares() -> Result<Vec<Event>> {
        anyhow::bail!("Network Shares Monitor uses the Windows Net API and is only implemented on Windows.")
    }
}

#[cfg(windows)]
pub use windows_impl::list_shares;
#[cfg(not(windows))]
pub use other_impl::list_shares;

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call.
pub struct NetworkSharesCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for NetworkSharesCollector {
    fn name(&self) -> &'static str {
        "network-shares-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_shares()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}
