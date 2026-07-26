//! offgrd-collectors: every OS-level data collector, shared between
//! `offgrd-cli` and `offgrd-gui` (and, later, a headless daemon) so
//! none of them duplicate raw Win32/ETW code.
//!
//! Unlike `offgrd-common`/`offgrd-core`/`offgrd-rules`, this crate
//! does NOT `forbid(unsafe_code)` at the root: `platform/windows.rs`
//! legitimately needs `unsafe` to call Win32 APIs, and `forbid` (as
//! opposed to `deny`) can't be locally overridden per-module. Every
//! `unsafe` block in this crate has a `// SAFETY:` comment; see
//! `platform/windows.rs` and `etw_collector.rs`.

pub mod platform;
pub mod process_snapshot;

#[cfg(windows)]
pub mod etw_collector;

pub use process_snapshot::ProcessSnapshotCollector;

#[cfg(windows)]
pub use etw_collector::EtwProcessCollector;
