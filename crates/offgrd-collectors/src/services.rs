//! Service Manager — enumerates Windows services via the Service
//! Control Manager (`EnumServicesStatusExW`).
//!
//! Scope on purpose, tighter than usual for this module specifically:
//! this first pass reports name, display name, state, and type only.
//! `start_type` (Auto/Manual/Disabled) and `binary_path` need a
//! separate `QueryServiceConfigW` call per service — a second
//! variable-length-buffer two-call dance, on top of the one this
//! module already does for the service list itself. Rather than
//! stack two independent "get buffer size, allocate, call again"
//! patterns in one unverified pass, this ships with those two fields
//! always `None` for now; wiring up `QueryServiceConfigW` is a
//! contained, mechanical follow-up once this simpler version is
//! confirmed working.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows::Win32::System::Services::{
        CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
        SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
        SERVICE_DRIVER,
    };

    pub fn list_services() -> Result<Vec<Event>> {
        // SAFETY: `OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)`
        // opens a handle to the local machine's default SCM database
        // with enumerate-only rights — a documented, standard,
        // low-privilege open (no admin rights required to enumerate
        // service *status*, only to change services).
        let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) }?;

        struct ScmGuard(windows::Win32::Foundation::HANDLE);
        impl Drop for ScmGuard {
            fn drop(&mut self) {
                // SAFETY: `self.0` is the valid SCM handle opened
                // above and hasn't been closed yet.
                unsafe {
                    let _ = CloseServiceHandle(self.0);
                }
            }
        }
        let _guard = ScmGuard(scm);

        // Two-call pattern, same shape as GetExtendedTcpTable: first
        // call to learn the required buffer size (and how many
        // services will be returned), then a real call with a
        // correctly-sized buffer.
        let mut bytes_needed: u32 = 0;
        let mut services_returned: u32 = 0;
        let mut resume_handle: u32 = 0;

        // SAFETY: passing an empty buffer with `bytes_needed`
        // reporting 0 available bytes is the documented way to query
        // the required size; the API does not write through the
        // buffer pointer in this failure mode, only the out-params.
        let first_call = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32 | SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                None,
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                None,
            )
        };
        // We expect this first call to fail with ERROR_MORE_DATA
        // (buffer too small) — that's success for the size-query
        // purpose, not a real error.
        if first_call.is_err() {
            let code = unsafe { windows::Win32::Foundation::GetLastError() };
            if code != ERROR_MORE_DATA {
                anyhow::bail!("EnumServicesStatusExW size query failed with code {}", code.0);
            }
        }
        if bytes_needed == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; bytes_needed as usize];
        resume_handle = 0;

        // SAFETY: `buffer` is sized exactly to what the previous call
        // reported via `bytes_needed`, remains valid for the duration
        // of this call, and the API writes at most that many bytes
        // into it (an array of `ENUM_SERVICE_STATUS_PROCESSW`,
        // documented layout).
        let second_call = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32 | SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                Some(&mut buffer),
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                None,
            )
        };
        if second_call.is_err() {
            let code = unsafe { windows::Win32::Foundation::GetLastError() };
            if code != ERROR_SUCCESS {
                anyhow::bail!("EnumServicesStatusExW failed with code {}", code.0);
            }
        }

        // SAFETY: `buffer` was populated by the successful call above
        // with `services_returned` entries of
        // `ENUM_SERVICE_STATUS_PROCESSW`, the documented struct this
        // API fills the buffer with — reading `services_returned`
        // entries from this pointer stays within `buffer`'s
        // allocation, per the same reasoning as the network
        // collector's table-row reads.
        let entries: &[ENUM_SERVICE_STATUS_PROCESSW] = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                services_returned as usize,
            )
        };

        Ok(entries.iter().map(entry_to_event).collect())
    }

    fn entry_to_event(entry: &ENUM_SERVICE_STATUS_PROCESSW) -> Event {
        // SAFETY: `lpServiceName`/`lpDisplayName` are non-null,
        // NUL-terminated wide-string pointers owned by the same
        // buffer this struct lives in (populated by
        // EnumServicesStatusExW, valid for as long as `buffer` in
        // `list_services` is alive, which covers this call since it
        // happens before `buffer` is dropped).
        let service_name = unsafe { pwstr_to_string(entry.lpServiceName) };
        let display_name = unsafe { pwstr_to_string(entry.lpDisplayName) };

        let status = &entry.ServiceStatusProcess;

        Event::new(
            EventSource::Snapshot,
            EventCategory::Persistence,
            EventPayload::ServiceObserved {
                service_name,
                display_name,
                state: service_state_label(status.dwCurrentState.0),
                service_type: service_type_label(status.dwServiceType.0),
                start_type: None, // See module doc: needs QueryServiceConfigW, not implemented yet.
                binary_path: None,
            },
        )
    }

    unsafe fn pwstr_to_string(pwstr: windows::core::PWSTR) -> String {
        if pwstr.is_null() {
            return String::new();
        }
        // SAFETY: caller (entry_to_event) guarantees this points at a
        // valid, NUL-terminated wide string alive for the duration of
        // this call.
        pwstr.to_string().unwrap_or_default()
    }

    fn service_state_label(state: u32) -> String {
        match state {
            1 => "Stopped",
            2 => "Start Pending",
            3 => "Stop Pending",
            4 => "Running",
            5 => "Continue Pending",
            6 => "Pause Pending",
            7 => "Paused",
            other => return format!("Unknown({other})"),
        }
        .to_string()
    }

    fn service_type_label(service_type: u32) -> String {
        // SERVICE_* type flags are bitflags; report the most specific
        // match rather than trying to enumerate every combination.
        if service_type & 0x00000010 != 0 {
            "Own Process".to_string()
        } else if service_type & 0x00000020 != 0 {
            "Share Process".to_string()
        } else if service_type & 0x00000001 != 0 {
            "Kernel Driver".to_string()
        } else if service_type & 0x00000002 != 0 {
            "File System Driver".to_string()
        } else {
            format!("Unknown(0x{service_type:x})")
        }
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn list_services() -> Result<Vec<Event>> {
        anyhow::bail!(
            "Service Manager uses the Windows Service Control Manager and is only implemented on Windows."
        )
    }
}

#[cfg(windows)]
pub use windows_impl::list_services;
#[cfg(not(windows))]
pub use other_impl::list_services;

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call,
/// same shape as the other snapshot collectors.
pub struct ServicesCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for ServicesCollector {
    fn name(&self) -> &'static str {
        "services-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_services()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}
