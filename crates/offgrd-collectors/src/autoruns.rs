//! Persistence / Autoruns Monitor — enumerates well-known registry
//! "Run at logon" keys, the same locations Sysinternals Autoruns
//! checks first and by far the most common persistence mechanism for
//! both legitimate software and malware alike.
//!
//! Scope on purpose, matching the project's "ship the honest MVP"
//! pattern: this first pass covers registry `Run`/`RunOnce` keys only
//! (HKLM and HKCU, 32-bit and 64-bit registry views on 64-bit
//! Windows). Scheduled tasks, services, startup-folder shortcuts, and
//! WMI event subscriptions are all real persistence mechanisms too
//! (see the architecture doc's Autoruns/Persistence Monitor module)
//! but are separate data sources with their own APIs — deliberately
//! not attempted together in one unverified pass.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

/// The well-known Run-key locations checked. `(hive_label, subkey,
/// view_is_wow64_32key)` — the WOW64 flag matters because on 64-bit
/// Windows, HKLM has a separate 32-bit view
/// (`Software\WOW6432Node\...`) that a naive single read would miss
/// entirely, silently hiding half of what's actually configured to
/// run at logon.
const RUN_KEY_LOCATIONS: &[(&str, &str)] = &[
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (
        "HKLM",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
];

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        KEY_READ, REG_SZ, REG_EXPAND_SZ,
    };

    pub fn list_autorun_entries() -> Result<Vec<Event>> {
        let mut events = Vec::new();

        for (hive_label, subkey) in RUN_KEY_LOCATIONS {
            let root = match *hive_label {
                "HKLM" => HKEY_LOCAL_MACHINE,
                "HKCU" => HKEY_CURRENT_USER,
                _ => continue, // Unreachable given the const list above, but no panics over data.
            };

            match read_string_values(root, subkey) {
                Ok(values) => {
                    for (name, data) in values {
                        events.push(Event::new(
                            EventSource::Snapshot,
                            EventCategory::Persistence,
                            EventPayload::AutorunEntryObserved {
                                hive: hive_label.to_string(),
                                key_path: subkey.to_string(),
                                value_name: name,
                                value_data: data,
                            },
                        ));
                    }
                }
                Err(err) => {
                    // A missing key (e.g. no WOW6432Node on a machine
                    // that's never installed 32-bit software) is
                    // normal, not a reason to fail the whole scan —
                    // log to stderr and keep checking the other
                    // locations.
                    eprintln!(
                        "offgrd: could not read {hive_label}\\{subkey}: {err:#} (skipping, likely doesn't exist on this system)"
                    );
                }
            }
        }

        Ok(events)
    }

    /// Opens `subkey` under `root` and reads every `REG_SZ`/`REG_EXPAND_SZ`
    /// value as a (name, data) pair. Non-string values (rare in Run
    /// keys, but possible) are skipped rather than causing an error.
    fn read_string_values(root: HKEY, subkey: &str) -> Result<Vec<(String, String)>> {
        let subkey_wide = to_wide(subkey);
        let mut hkey = HKEY::default();

        // SAFETY: `subkey_wide` is a valid, NUL-terminated wide string
        // alive for the duration of this call; `root` is one of the
        // predefined HKEY constants (always "open"); `hkey` is a valid
        // out-pointer for the opened key handle, closed below via
        // `RegCloseKey` on every path (including early `?` returns —
        // handled with a guard).
        let open_result = unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(subkey_wide.as_ptr()),
                0,
                KEY_READ,
                &mut hkey,
            )
        };
        if open_result != ERROR_SUCCESS {
            anyhow::bail!("RegOpenKeyExW failed with code {}", open_result.0);
        }

        struct KeyGuard(HKEY);
        impl Drop for KeyGuard {
            fn drop(&mut self) {
                // SAFETY: `self.0` is the valid key handle opened
                // above and hasn't been closed yet.
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
            }
        }
        let _guard = KeyGuard(hkey);

        let mut results = Vec::new();
        let mut index: u32 = 0;

        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len: u32 = name_buf.len() as u32;
            let mut value_type: u32 = 0;
            let mut data_buf = [0u8; 4096];
            let mut data_len: u32 = data_buf.len() as u32;

            // SAFETY: `hkey` is a valid, still-open key handle;
            // `name_buf`/`name_len` and `data_buf`/`data_len` describe
            // real, correctly-sized mutable buffers with their
            // capacities passed by reference, which the API respects
            // per its documented contract (writes at most the
            // capacity, updates the length out-params to the actual
            // written size).
            let enum_result = unsafe {
                RegEnumValueW(
                    hkey,
                    index,
                    Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut value_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                )
            };

            if enum_result == ERROR_NO_MORE_ITEMS {
                break;
            }
            if enum_result != ERROR_SUCCESS {
                anyhow::bail!("RegEnumValueW failed with code {}", enum_result.0);
            }

            if value_type == REG_SZ.0 || value_type == REG_EXPAND_SZ.0 {
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let data = wide_bytes_to_string(&data_buf[..data_len as usize]);
                results.push((name, data));
            }

            index += 1;
        }

        Ok(results)
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Registry string values are stored as raw UTF-16LE bytes
    /// (including a NUL terminator we need to trim); reinterpret the
    /// byte buffer as u16 code units before decoding.
    fn wide_bytes_to_string(bytes: &[u8]) -> String {
        let words: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        let len = words.iter().position(|&c| c == 0).unwrap_or(words.len());
        String::from_utf16_lossy(&words[..len])
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn list_autorun_entries() -> Result<Vec<Event>> {
        anyhow::bail!(
            "Autoruns/Persistence Monitor reads the Windows registry and is only implemented on Windows."
        )
    }
}

#[cfg(windows)]
pub use windows_impl::list_autorun_entries;
#[cfg(not(windows))]
pub use other_impl::list_autorun_entries;

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call,
/// same shape as `ProcessSnapshotCollector`/`NetworkSnapshotCollector`.
pub struct AutorunsCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for AutorunsCollector {
    fn name(&self) -> &'static str {
        "autoruns-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_autorun_entries()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}
