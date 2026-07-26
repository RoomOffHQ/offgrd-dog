//! Real Windows implementation using `CreateToolhelp32Snapshot`.
//!
//! No admin rights required: this only reads process *existence*
//! metadata (pid, ppid, exe name) that any user can already see in
//! Task Manager. Command-line retrieval (which does need more care -
//! `OpenProcess` + `NtQueryInformationProcess` on other users' processes
//! can fail under standard privileges) is left as `None` here and will
//! be added in the ETW-based collector milestone, where we can get it
//! from process-start events instead of poking at live processes.

//! Real Windows implementation using `CreateToolhelp32Snapshot`.
//!
//! No admin rights required for the base enumeration: this reads
//! process *existence* metadata (pid, ppid, exe name) that any user
//! can already see in Task Manager. We additionally try to resolve
//! the *full* image path via `OpenProcess` +
//! `QueryFullProcessImageNameW`; this can fail with access-denied for
//! protected/elevated/system processes when we're not elevated
//! ourselves, in which case we fall back to the short exe name from
//! the snapshot rather than failing the whole listing.
//!
//! Full command-line retrieval is intentionally NOT done here via the
//! undocumented PEB/`NtQueryInformationProcess` route — it's fragile,
//! version-dependent, and needs WOW64 special-casing to read a 64-bit
//! PEB from a 32-bit build. It will instead come from the ETW
//! `Microsoft-Windows-Kernel-Process` collector (milestone 5 in
//! WIP.md), which hands us the command line directly and reliably at
//! process-creation time.

use anyhow::{bail, Result};
use offgrd_common::ProcessRef;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

pub fn list_processes() -> Result<Vec<ProcessRef>> {
    // SAFETY: `CreateToolhelp32Snapshot` with TH32CS_SNAPPROCESS and a
    // pid of 0 (all processes) is a well-defined, documented Win32 call
    // that does not take ownership of any memory we must manage beyond
    // the returned handle, which we close via `CloseHandle` below on
    // every exit path (including early bail via `?` — handled with a
    // guard).
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a valid handle from either
            // CreateToolhelp32Snapshot or OpenProcess and has not been
            // closed yet; CloseHandle is safe to call on any valid
            // handle exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    let _snapshot_guard = HandleGuard(snapshot);

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut processes = Vec::new();

    // SAFETY: `entry.dwSize` is set to the correct struct size as
    // required by the Win32 API contract, and `snapshot` is a valid,
    // still-open handle for the duration of this call.
    let first_ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    if first_ok.is_err() {
        bail!("Process32FirstW failed - no processes returned by snapshot");
    }

    loop {
        processes.push(entry_to_process_ref(&entry));

        // SAFETY: same handle/struct-size contract as Process32FirstW.
        let next_ok = unsafe { Process32NextW(snapshot, &mut entry) };
        if next_ok.is_err() {
            break; // ERROR_NO_MORE_FILES: normal end of enumeration.
        }
    }

    Ok(processes)
}

fn entry_to_process_ref(entry: &PROCESSENTRY32W) -> ProcessRef {
    let short_name = wide_to_string(&entry.szExeFile);
    let mut process = ProcessRef::new(entry.th32ProcessID).with_parent(entry.th32ParentProcessID);

    match full_image_path(entry.th32ProcessID) {
        Some(full_path) => process = process.with_image_path(full_path),
        None if !short_name.is_empty() => process = process.with_image_path(short_name),
        None => {}
    }

    process
}

/// Best-effort resolution of a process's full image path. Returns
/// `None` (never an error) if the process can't be opened — e.g. it's
/// a protected process, a system process, or has already exited
/// between the snapshot and this call. Callers should treat that as
/// "unknown", not as a reason to drop the process from the listing.
fn full_image_path(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION is a
    // documented, low-privilege query handle open; it may legitimately
    // fail (returns Err) for processes we don't have access to, which
    // we handle below rather than unwrap.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            // SAFETY: `self.0` is the valid handle opened just above.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    let _guard = HandleGuard(handle);

    let mut buffer = [0u16; 1024];
    let mut size = buffer.len() as u32;

    // SAFETY: `handle` is a valid, open process handle from the
    // successful OpenProcess call above; `buffer`/`size` describe a
    // real, sufficiently-sized (MAX_PATH-plus-margin) mutable buffer
    // that the API will not write past according to `size` on input,
    // and which is updated in place to the written length on output.
    let ok = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, windows::core::PWSTR(buffer.as_mut_ptr()), &mut size)
    };

    if ok.is_err() {
        return None;
    }

    Some(String::from_utf16_lossy(&buffer[..size as usize]))
}

/// Converts a NUL-terminated/padded wide (UTF-16) buffer, as used by
/// Win32 `W`-suffixed APIs, into a `String`.
fn wide_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}
