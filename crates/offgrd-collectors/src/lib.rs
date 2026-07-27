//! offgrd-collectors: every OS-level data collector, shared between
//! `offgrd-cli` and `offgrd-gui` (and, later, a headless daemon) so
//! none of them duplicate raw Win32/ETW code.
//!
//! Unlike `offgrd-common`/`offgrd-core`/`offgrd-rules`, this crate
//! does NOT `forbid(unsafe_code)` at the root: several modules
//! legitimately need `unsafe` to call Win32 APIs, and `forbid` (as
//! opposed to `deny`) can't be locally overridden per-module. Every
//! `unsafe` block in this crate has a `// SAFETY:` comment. See
//! `docs/collectors.md` at the repo root for a full per-collector
//! reference (data source, schema, privileges, known limitations).

pub mod autoruns;
pub mod certificates;
pub mod clipboard;
pub mod dns_cache;
pub mod environment;
pub mod foreground_window;
pub mod hosts_file;
pub mod idle_time;
pub mod installed_programs;
pub mod local_accounts;
pub mod modules;
pub mod named_pipes;
pub mod network_shares;
pub mod network_snapshot;
pub mod platform;
pub mod poll_diff;
pub mod process_snapshot;
pub mod services;
pub mod sessions;
pub mod startup_folder;

#[cfg(windows)]
pub mod etw_collector;

pub use autoruns::AutorunsCollector;
pub use certificates::CertificatesCollector;
pub use clipboard::ClipboardCollector;
pub use dns_cache::DnsCacheCollector;
pub use environment::EnvironmentCollector;
pub use foreground_window::ForegroundWindowCollector;
pub use hosts_file::HostsFileCollector;
pub use installed_programs::InstalledProgramsCollector;
pub use local_accounts::LocalAccountsCollector;
pub use modules::ModulesCollector;
pub use named_pipes::NamedPipesCollector;
pub use network_shares::NetworkSharesCollector;
pub use network_snapshot::NetworkSnapshotCollector;
pub use poll_diff::{PollDiffer, PollTick};
pub use process_snapshot::ProcessSnapshotCollector;
pub use services::ServicesCollector;
pub use sessions::SessionsCollector;
pub use startup_folder::StartupFolderCollector;
pub use idle_time::IdleTimeCollector;

#[cfg(windows)]
pub use etw_collector::EtwProcessCollector;
