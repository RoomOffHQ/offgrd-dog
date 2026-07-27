//! Installed Programs Monitor — reads the registry "Add/Remove
//! Programs" (Uninstall) keys. A baseline software inventory: less
//! flashy than injection/persistence detection, but genuinely useful
//! as a "what's actually installed on this machine" reference, and it
//! reuses the exact registry-reading pattern `AutorunsCollector`
//! already established.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};

/// The two conventional Uninstall key locations: 64-bit view and the
/// 32-bit (`WOW6432Node`) view on 64-bit Windows — same WOW64 gotcha
/// `AutorunsCollector` already accounts for, since a naive single read
/// would silently miss every 32-bit-installed program.
const UNINSTALL_KEY_LOCATIONS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
];

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE,
        KEY_READ, REG_SZ,
    };

    pub fn list_installed_programs() -> Result<Vec<Event>> {
        let mut events = Vec::new();

        for subkey in UNINSTALL_KEY_LOCATIONS {
            match list_under_key(subkey) {
                Ok(mut program_events) => events.append(&mut program_events),
                Err(err) => {
                    eprintln!("offgrd: could not read {subkey}: {err:#} (skipping, likely doesn't exist on this system)");
                }
            }
        }

        Ok(events)
    }

    fn list_under_key(subkey: &str) -> Result<Vec<Event>> {
        let subkey_wide = to_wide(subkey);
        let mut hkey = HKEY::default();

        // SAFETY: same contract as AutorunsCollector's registry open —
        // valid NUL-terminated wide string, predefined HKEY root,
        // valid out-pointer, closed via the guard below.
        let open_result = unsafe {
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(subkey_wide.as_ptr()), 0, KEY_READ, &mut hkey)
        };
        if open_result != ERROR_SUCCESS {
            anyhow::bail!("RegOpenKeyExW failed with code {}", open_result.0);
        }

        struct KeyGuard(HKEY);
        impl Drop for KeyGuard {
            fn drop(&mut self) {
                // SAFETY: valid, still-open key handle from above.
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
            }
        }
        let _guard = KeyGuard(hkey);

        let mut events = Vec::new();
        let mut index: u32 = 0;

        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len: u32 = name_buf.len() as u32;

            // SAFETY: `hkey` is a valid, still-open key handle;
            // `name_buf`/`name_len` describe a real, correctly-sized
            // mutable buffer with its capacity passed by reference,
            // matching `RegEnumKeyExW`'s documented contract.
            let enum_result = unsafe {
                RegEnumKeyExW(
                    hkey,
                    index,
                    windows::core::PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    windows::core::PWSTR::null(),
                    None,
                    None,
                )
            };

            if enum_result == ERROR_NO_MORE_ITEMS {
                break;
            }
            if enum_result != ERROR_SUCCESS {
                anyhow::bail!("RegEnumKeyExW failed with code {}", enum_result.0);
            }

            let subkey_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            if let Some(event) = read_program_entry(hkey, &subkey_name) {
                events.push(event);
            }

            index += 1;
        }

        Ok(events)
    }

    /// Reads one program's subkey (e.g. a GUID or product code) and
    /// extracts `DisplayName`/`DisplayVersion`/`Publisher`/
    /// `InstallLocation`. Returns `None` (not an error) if there's no
    /// `DisplayName` — many subkeys under Uninstall are
    /// updates/patches/components with no user-facing display name,
    /// and Windows' own Add/Remove Programs UI filters those out too.
    fn read_program_entry(parent: HKEY, subkey_name: &str) -> Option<Event> {
        let subkey_wide = to_wide(subkey_name);
        let mut hkey = HKEY::default();

        // SAFETY: same open/close contract as above, on a child key
        // of the already-valid `parent` handle.
        let open_result = unsafe {
            RegOpenKeyExW(parent, PCWSTR(subkey_wide.as_ptr()), 0, KEY_READ, &mut hkey)
        };
        if open_result != ERROR_SUCCESS {
            return None;
        }

        struct KeyGuard(HKEY);
        impl Drop for KeyGuard {
            fn drop(&mut self) {
                // SAFETY: valid, still-open key handle opened above.
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
            }
        }
        let _guard = KeyGuard(hkey);

        let display_name = read_string_value(hkey, "DisplayName")?;
        let display_version = read_string_value(hkey, "DisplayVersion");
        let publisher = read_string_value(hkey, "Publisher");
        let install_location = read_string_value(hkey, "InstallLocation");

        Some(Event::new(
            EventSource::Snapshot,
            EventCategory::Software,
            EventPayload::InstalledProgramObserved {
                display_name,
                display_version,
                publisher,
                install_location,
            },
        ))
    }

    fn read_string_value(hkey: HKEY, value_name: &str) -> Option<String> {
        let value_name_wide = to_wide(value_name);
        let mut value_type: u32 = 0;
        let mut data_buf = [0u8; 1024];
        let mut data_len: u32 = data_buf.len() as u32;

        // SAFETY: `hkey` is a valid, still-open key handle;
        // `value_name_wide` is a valid NUL-terminated wide string;
        // `data_buf`/`data_len` describe a real, correctly-sized
        // mutable buffer with capacity passed by reference, matching
        // `RegQueryValueExW`'s documented contract (in: capacity,
        // out: actual bytes written).
        let result = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(value_name_wide.as_ptr()),
                None,
                Some(&mut value_type),
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_len),
            )
        };

        if result != ERROR_SUCCESS || value_type != REG_SZ.0 {
            return None;
        }

        let words: Vec<u16> = data_buf[..data_len as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let len = words.iter().position(|&c| c == 0).unwrap_or(words.len());
        let s = String::from_utf16_lossy(&words[..len]);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod other_impl {
    use super::*;

    pub fn list_installed_programs() -> Result<Vec<Event>> {
        anyhow::bail!("Installed Programs Monitor reads the Windows registry and is only implemented on Windows.")
    }
}

#[cfg(windows)]
pub use windows_impl::list_installed_programs;
#[cfg(not(windows))]
pub use other_impl::list_installed_programs;

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call.
pub struct InstalledProgramsCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for InstalledProgramsCollector {
    fn name(&self) -> &'static str {
        "installed-programs-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_installed_programs()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}
