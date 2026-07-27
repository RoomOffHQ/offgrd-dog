//! Local Accounts Monitor — enumerates local user accounts and groups
//! via the Windows Net API (`NetUserEnum`/`NetLocalGroupEnum`). A
//! hidden/disabled-but-reactivatable account, or an unexpected
//! addition to the local Administrators group, is a real persistence/
//! privilege-escalation signal worth being able to see at a glance.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetLocalGroupEnum, NetUserEnum, FILTER_NORMAL_ACCOUNT,
        LOCALGROUP_INFO_0, MAX_PREFERRED_LENGTH, USER_INFO_2,
    };

    pub fn list_local_accounts() -> Result<Vec<Event>> {
        let mut events = list_users()?;
        events.append(&mut list_groups()?);
        Ok(events)
    }

    fn list_users() -> Result<Vec<Event>> {
        let mut buffer: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        let mut resume_handle: u32 = 0;

        // SAFETY: level 2 (`USER_INFO_2`) with a null server name
        // targets the local machine, a documented, standard call;
        // `buffer` is populated by the API and freed via
        // `NetApiBufferFree` below on every path.
        let status = unsafe {
            NetUserEnum(
                None,
                2,
                FILTER_NORMAL_ACCOUNT,
                &mut buffer,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                Some(&mut resume_handle),
            )
        };
        if status != 0 {
            anyhow::bail!("NetUserEnum failed with code {status}");
        }

        struct BufferGuard(*mut u8);
        impl Drop for BufferGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: `self.0` is the valid buffer returned by
                    // the successful call above, freed exactly once.
                    unsafe {
                        let _ = NetApiBufferFree(Some(self.0 as *mut _));
                    }
                }
            }
        }
        let _guard = BufferGuard(buffer);

        // SAFETY: `buffer` was populated with `entries_read` entries
        // of `USER_INFO_2`, the documented layout for level-2
        // `NetUserEnum` — reading that many entries stays within the
        // API-allocated buffer.
        let users: &[USER_INFO_2] =
            unsafe { std::slice::from_raw_parts(buffer as *const USER_INFO_2, entries_read as usize) };

        Ok(users
            .iter()
            .map(|user| {
                Event::new(
                    EventSource::Snapshot,
                    EventCategory::Accounts,
                    EventPayload::LocalAccountObserved {
                        kind: "User".to_string(),
                        name: pwstr_to_string(user.usri2_name),
                        disabled: Some(user.usri2_flags & 0x0002 != 0), // UF_ACCOUNTDISABLE
                        comment: optional_pwstr_to_string(user.usri2_comment),
                    },
                )
            })
            .collect())
    }

    fn list_groups() -> Result<Vec<Event>> {
        let mut buffer: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        let mut resume_handle: u32 = 0;

        // SAFETY: same contract as NetUserEnum above, level 0
        // (`LOCALGROUP_INFO_0`, name only) is sufficient for our purposes.
        let status = unsafe {
            NetLocalGroupEnum(
                None,
                0,
                &mut buffer,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                Some(&mut resume_handle),
            )
        };
        if status != 0 {
            anyhow::bail!("NetLocalGroupEnum failed with code {status}");
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
        // of `LOCALGROUP_INFO_0`, the documented layout for level-0
        // `NetLocalGroupEnum`.
        let groups: &[LOCALGROUP_INFO_0] = unsafe {
            std::slice::from_raw_parts(buffer as *const LOCALGROUP_INFO_0, entries_read as usize)
        };

        Ok(groups
            .iter()
            .map(|group| {
                Event::new(
                    EventSource::Snapshot,
                    EventCategory::Accounts,
                    EventPayload::LocalAccountObserved {
                        kind: "Group".to_string(),
                        name: pwstr_to_string(group.lgrpi0_name),
                        disabled: None,
                        comment: None,
                    },
                )
            })
            .collect())
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

    pub fn list_local_accounts() -> Result<Vec<Event>> {
        anyhow::bail!("Local Accounts Monitor uses the Windows Net API and is only implemented on Windows.")
    }
}

#[cfg(windows)]
pub use windows_impl::list_local_accounts;
#[cfg(not(windows))]
pub use other_impl::list_local_accounts;

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call.
pub struct LocalAccountsCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for LocalAccountsCollector {
    fn name(&self) -> &'static str {
        "local-accounts-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_local_accounts()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}
