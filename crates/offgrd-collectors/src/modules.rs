//! Loaded Modules (DLLs) per process — Toolhelp32's
//! `Module32First`/`Module32Next`, the exact same API family as
//! `ProcessSnapshotCollector`. A precursor to injection detection: an
//! unexpected module (wrong path, unsigned, present in a process that
//! has no business loading it) is one of the clearest DLL-injection
//! signals — but judging "unexpected" is a future rule-engine/
//! correlation concern. This collector only reports facts: which
//! modules are loaded, where, and how big.
//!
//! Scope on purpose: enumerates modules for every process it can open
//! a Toolhelp snapshot for; processes that can't be snapshotted
//! (protected/system processes without sufficient rights) are skipped
//! with a logged note, not a hard failure.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };

    /// Enumerates loaded modules for a single process by pid. Returns
    /// an empty list (not an error) if the process can't be
    /// snapshotted — e.g. it's a protected process, or it exited
    /// between being listed and this call.
    pub fn list_modules_for_pid(pid: u32) -> Result<Vec<Event>> {
        // SAFETY: `CreateToolhelp32Snapshot` with the module flags and
        // a specific pid is a documented, well-defined Win32 call.
        // It's expected to fail (Err) for processes we can't snapshot
        // (e.g. protected processes) — that's handled below as "no
        // modules observed," not propagated as an error, matching
        // this collector's "best-effort per process" contract.
        let snapshot = match unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        } {
            Ok(handle) => handle,
            Err(_) => return Ok(Vec::new()),
        };

        struct SnapshotGuard(windows::Win32::Foundation::HANDLE);
        impl Drop for SnapshotGuard {
            fn drop(&mut self) {
                // SAFETY: `self.0` is the valid snapshot handle from
                // the successful call above, not yet closed.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
        let _guard = SnapshotGuard(snapshot);

        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        let mut events = Vec::new();

        // SAFETY: `entry.dwSize` is set to the correct struct size as
        // required by the Win32 API contract; `snapshot` is a valid,
        // still-open handle for the duration of this call.
        if unsafe { Module32FirstW(snapshot, &mut entry) }.is_err() {
            return Ok(Vec::new()); // No modules (or can't enumerate) — not an error.
        }

        loop {
            events.push(entry_to_event(pid, &entry));

            // SAFETY: same handle/struct-size contract as Module32FirstW.
            if unsafe { Module32NextW(snapshot, &mut entry) }.is_err() {
                break; // ERROR_NO_MORE_FILES: normal end of enumeration.
            }
        }

        Ok(events)
    }

    fn entry_to_event(pid: u32, entry: &MODULEENTRY32W) -> Event {
        Event::new(
            EventSource::Snapshot,
            EventCategory::Process,
            EventPayload::LoadedModuleObserved {
                pid,
                module_name: wide_to_string(&entry.szModule),
                module_path: wide_to_string(&entry.szExePath),
                base_size: entry.modBaseSize,
            },
        )
    }

    fn wide_to_string(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn list_modules_for_pid(_pid: u32) -> Result<Vec<Event>> {
        anyhow::bail!("Loaded Modules uses Toolhelp32 and is only implemented on Windows.")
    }
}

#[cfg(windows)]
pub use windows_impl::list_modules_for_pid;
#[cfg(not(windows))]
pub use other_impl::list_modules_for_pid;

/// Enumerates loaded modules across every currently running process.
/// Reuses `ProcessSnapshotCollector`'s process list purely to get the
/// pid list to iterate — does not depend on its `Collector` output.
pub fn list_all_modules() -> Result<Vec<Event>> {
    let processes = crate::platform::list_processes()?;
    let mut events = Vec::new();
    for process in processes {
        match list_modules_for_pid(process.pid) {
            Ok(mut module_events) => events.append(&mut module_events),
            Err(err) => {
                eprintln!(
                    "offgrd: could not enumerate modules for pid {}: {err:#}",
                    process.pid
                );
            }
        }
    }
    Ok(events)
}

/// The `offgrd_core::Collector` wrapper — one-shot, scans every
/// currently running process.
pub struct ModulesCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for ModulesCollector {
    fn name(&self) -> &'static str {
        "modules-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_all_modules()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}
