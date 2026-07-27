//! Startup Folder Monitor — enumerates shortcuts/executables directly
//! in the current user's and all-users' Startup folders
//! (`shell:startup` / `shell:common startup`). Completes the picture
//! `AutorunsCollector` started (registry Run keys): a shortcut quietly
//! dropped in this folder is just as real a persistence technique and
//! completely invisible to a registry-only view.
//!
//! Pure filesystem enumeration, no `unsafe` code.

use anyhow::Result;
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};
use std::path::PathBuf;

/// Resolves both Startup folder locations without any Windows-
/// specific API — `%APPDATA%`/`%ProgramData%` are plain environment
/// variables Windows always sets, so this needs no `unsafe` shell-API
/// call (`SHGetKnownFolderPath`) for what's otherwise a well-known,
/// stable path.
fn startup_folders() -> Vec<(&'static str, PathBuf)> {
    let mut folders = Vec::new();

    if let Ok(appdata) = std::env::var("APPDATA") {
        folders.push((
            "CurrentUser",
            PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
        ));
    }
    if let Ok(program_data) = std::env::var("ProgramData") {
        folders.push((
            "AllUsers",
            PathBuf::from(program_data)
                .join(r"Microsoft\Windows\Start Menu\Programs\StartUp"),
        ));
    }

    folders
}

pub fn list_startup_entries() -> Result<Vec<Event>> {
    let mut events = Vec::new();

    for (scope, folder) in startup_folders() {
        if !folder.exists() {
            continue; // Not every machine has both — not an error.
        }

        let entries = std::fs::read_dir(&folder).with_context_msg(&folder)?;
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if !path.is_file() {
                continue; // Skip subfolders, if any.
            }

            // "desktop.ini" is a normal, benign Explorer-generated
            // file that appears in almost every folder — excluding it
            // avoids every single machine reporting a spurious
            // "startup entry" that isn't one.
            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if file_name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }

            events.push(Event::new(
                EventSource::Snapshot,
                EventCategory::Persistence,
                EventPayload::StartupFolderEntryObserved {
                    scope: scope.to_string(),
                    file_name,
                    full_path: path.to_string_lossy().to_string(),
                },
            ));
        }
    }

    Ok(events)
}

/// Small extension trait so `read_dir`'s error carries the path it
/// failed on, matching this project's convention of contextful error
/// messages, without pulling in `anyhow::Context` verbosely inline.
trait WithContextMsg<T> {
    fn with_context_msg(self, path: &std::path::Path) -> Result<T>;
}
impl<T> WithContextMsg<T> for std::io::Result<T> {
    fn with_context_msg(self, path: &std::path::Path) -> Result<T> {
        use anyhow::Context;
        self.with_context(|| format!("failed to read startup folder {}", path.display()))
    }
}

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call.
pub struct StartupFolderCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for StartupFolderCollector {
    fn name(&self) -> &'static str {
        "startup-folder-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_startup_entries()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}
