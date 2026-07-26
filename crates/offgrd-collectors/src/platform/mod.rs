//! Platform abstraction: `list_processes()` returns normalized
//! `ProcessRef`s regardless of OS. Only the `windows` submodule talks
//! to a real OS API and contains the project's only `unsafe` code so
//! far (Win32 Toolhelp snapshot). The `other` submodule exists purely
//! so `cargo build`/`cargo test` succeed on any contributor's machine
//! (Linux/macOS) even though OffGrd Dog's actual target is Windows —
//! this keeps CI and local dev friction low without weakening the
//! Windows implementation at all.

use anyhow::Result;
use offgrd_common::ProcessRef;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use self::windows::list_processes;

#[cfg(not(windows))]
mod other;
#[cfg(not(windows))]
pub use other::list_processes;

/// Shared contract both platform backends implement.
#[allow(dead_code)]
pub trait ProcessLister {
    fn list_processes() -> Result<Vec<ProcessRef>>;
}
