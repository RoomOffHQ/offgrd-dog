# Collectors Reference

A single reference for every data source implemented so far — what it
collects, the exact `EventPayload` shape it produces, its privilege
requirements, and its known limitations. Each collector lives in
`crates/offgrd-collectors/src/` and implements `offgrd_core::Collector`
(`fn name()`, `async fn run(&self, bus: &EventBus)`).

For the overall pipeline architecture, see
`docs/offgrd-dog-architecture.md`. For what's verified vs. unverified
right now, see `WIP.md` — this file documents *shape and intent*, not
build status.

---

## ProcessSnapshotCollector

- **File**: `process_snapshot.rs`
- **Data source**: Win32 `CreateToolhelp32Snapshot` (Toolhelp32) +
  `OpenProcess`/`QueryFullProcessImageNameW` for full image paths
- **Privileges required**: None (standard user)
- **Payload**: `EventPayload::ProcessStarted { process: ProcessRef }`
  - `ProcessRef`: `pid`, `parent_pid`, `image_path` (full path,
    best-effort — falls back to the short exe name if the process
    can't be opened, e.g. protected/system processes), `command_line`
    (always `None` from this collector — see below),
    `parent_pid_spoofed` (always `None` — populated later by a future
    correlation engine, not by this collector)
- **Known limitations**:
  - No command line. Getting it without ETW requires reading the
    target process's PEB via undocumented `NtQueryInformationProcess`
    — deliberately not implemented (fragile, version/WOW64-dependent).
    Use `EtwProcessCollector` if you need command lines.
  - Point-in-time only — use `PollDiffer` (below) or
    `EtwProcessCollector` for continuous monitoring.

## EtwProcessCollector (Windows only, **experimental/unverified**)

- **File**: `etw_collector.rs`
- **Data source**: `Microsoft-Windows-Kernel-Process` ETW provider, via
  the `ferrisetw` crate
- **Privileges required**: Believed not to require admin for this
  specific provider, but **unconfirmed** — verify on a real machine.
- **Payload**: `ProcessStarted` (with `command_line` populated, unlike
  the snapshot collector) and `ProcessEnded { pid, exit_code }`
- **Status**: See `WIP.md`. `ferrisetw`'s exact API surface
  (`Provider::by_guid`, `Parser::try_parse`, property names like
  `ImageName`/`CommandLine`) is written from recollection, not
  verified against the crate's actual current API. No graceful stop
  mechanism yet (see WIP.md's thread-leak note).

## NetworkSnapshotCollector

- **File**: `network_snapshot.rs`
- **Data source**: Win32 IP Helper API, `GetExtendedTcpTable`
- **Privileges required**: None (same data `netstat -ano` shows)
- **Payload**: `EventPayload::NetworkConnectionObserved { pid,
  local_addr, local_port, remote_addr, remote_port, state }`
- **Known limitations**:
  - IPv4 TCP only. IPv6 (`AF_INET6` variant of the same API) and UDP
    (`GetExtendedUdpTable`) are natural, mechanical follow-ups.
  - Point-in-time only, same as the process snapshot collector.
  - Contains this project's highest-risk `unsafe` code so far (raw
    pointer arithmetic over a variable-length table) — see WIP.md.

## AutorunsCollector

- **File**: `autoruns.rs`
- **Data source**: Registry `Run`/`RunOnce` keys under `HKLM` and
  `HKCU` (including the `WOW6432Node` 32-bit view on 64-bit Windows)
- **Privileges required**: None to read (standard `KEY_READ` access)
- **Payload**: `EventPayload::AutorunEntryObserved { hive, key_path,
  value_name, value_data }`
- **Known limitations**:
  - Registry Run keys only. Scheduled tasks, services-as-persistence,
    startup-folder shortcuts, and WMI event subscriptions are the same
    conceptual mechanism (autostart) but different APIs/data sources —
    not implemented yet.
  - Missing keys (e.g. no `WOW6432Node` on a machine that's never
    installed 32-bit software) are logged and skipped, not treated as
    an error — this is intentional, not a bug if you see the log line.

## ServicesCollector

- **File**: `services.rs`
- **Data source**: Service Control Manager,
  `OpenSCManagerW`/`EnumServicesStatusExW`
- **Privileges required**: None (`SC_MANAGER_ENUMERATE_SERVICE` is
  enumerate-only, no admin needed)
- **Payload**: `EventPayload::ServiceObserved { service_name,
  display_name, state, service_type, start_type, binary_path }`
- **Known limitations**:
  - `start_type` (Auto/Manual/Disabled) and `binary_path` are always
    `None` in this first pass — both need a separate
    `QueryServiceConfigW` call per service (its own two-call
    variable-buffer dance), deliberately deferred rather than stacked
    on top of the service *list's* own two-call pattern in one
    unverified change.

## CertificatesCollector

- **File**: `certificates.rs`
- **Data source**: Windows Crypto API,
  `CertOpenSystemStoreW`/`CertEnumCertificatesInStore` over the
  `ROOT`, `CA`, and `MY` system stores
- **Privileges required**: None to read the current user's stores
- **Payload**: `EventPayload::CertificateObserved { store_name,
  subject, issuer, thumbprint, not_before, not_after }`
- **Known limitations**:
  - This is "what's installed in the trust store," not "TLS chain of
    a live connection" — the latter (SNI, cert chain of an active
    connection) is a separate, harder capability needing Schannel/ETW
    hooks, not implemented.
  - Only `ROOT`/`CA`/`MY` stores checked; `TrustedPublisher`,
    `Disallowed`, and others are real stores too, left for later.
  - Thumbprint is computed with a small hand-rolled SHA-1 (tested
    against known test vectors for `""` and `"abc"`) rather than
    pulling in a crypto crate for one hash — acceptable since it's
    used only as a display/lookup identifier, never for any actual
    trust/security decision.

## ModulesCollector

- **File**: `modules.rs`
- **Data source**: Toolhelp32, `Module32First`/`Module32Next` per pid
  (reuses `platform::list_processes()` to get the pid list)
- **Privileges required**: None for most processes; some
  protected/system processes can't be snapshotted, silently skipped
- **Payload**: `EventPayload::LoadedModuleObserved { pid, module_name,
  module_path, base_size }`
- **Known limitations**: One events-per-pid loop, so scanning every
  process on a busy machine is noticeably slower than the other
  snapshot collectors — no batching/parallelism yet.

## SessionsCollector

- **File**: `sessions.rs`
- **Data source**: `WTSEnumerateSessionsW`/`WTSQuerySessionInformationW`
- **Privileges required**: None to enumerate sessions on the local machine
- **Payload**: `EventPayload::SessionObserved { session_id, state,
  station_name, user_name }`
- **Known limitations**: Local machine only (no remote server query).

## HostsFileCollector

- **File**: `hosts_file.rs`
- **Data source**: Plain text file read of
  `%SystemRoot%\System32\drivers\etc\hosts`
- **Privileges required**: None to read
- **Payload**: `EventPayload::HostsFileEntryObserved { ip_address,
  hostname, raw_line }`
- **Notable**: Zero `unsafe` code — pure file I/O and string parsing.
  3 unit tests covering comment/blank-line handling and one-IP-to-
  many-hostnames lines.

## StartupFolderCollector

- **File**: `startup_folder.rs`
- **Data source**: Filesystem enumeration of `%APPDATA%\Microsoft\
  Windows\Start Menu\Programs\Startup` and the `%ProgramData%`
  equivalent
- **Privileges required**: None to read
- **Payload**: `EventPayload::StartupFolderEntryObserved { scope,
  file_name, full_path }`
- **Notable**: Zero `unsafe` code. Filters out `desktop.ini` (a benign
  Explorer artifact, not a real startup entry).

## NamedPipesCollector

- **File**: `named_pipes.rs`
- **Data source**: `FindFirstFileW`/`FindNextFileW` over `\\.\pipe\*`
- **Privileges required**: None (visibility only, not access)
- **Payload**: `EventPayload::NamedPipeObserved { pipe_name }`

## InstalledProgramsCollector

- **File**: `installed_programs.rs`
- **Data source**: Registry `...\CurrentVersion\Uninstall` keys under
  `HKLM` (both 64-bit and `WOW6432Node` 32-bit views)
- **Privileges required**: None to read
- **Payload**: `EventPayload::InstalledProgramObserved { display_name,
  display_version, publisher, install_location }`
- **Known limitations**: HKLM only (system-wide installs); per-user
  installs under `HKCU` aren't checked yet.

## ClipboardCollector

- **File**: `clipboard.rs`
- **Data source**: `OpenClipboard`/`GetClipboardData(CF_UNICODETEXT)`
- **Privileges required**: None
- **Payload**: `EventPayload::ClipboardTextObserved { text }`
- **⚠️ Privacy-sensitive**: reads whatever text is currently on the
  user's own clipboard. Flagged prominently in the CLI help text
  (`offgrd clipboard --help`) and should be equally prominent in any
  GUI surface for it — never a silent background capability.
- **Known limitations**: Text (`CF_UNICODETEXT`) only — no images,
  file lists, or other clipboard formats.

## PollDiffer (shared utility, not a collector itself)

- **File**: `poll_diff.rs`
- **What it does**: wraps `ProcessSnapshotCollector` to turn repeated
  point-in-time snapshots into "what changed since last time"
  (`PollTick::Baseline` on the first call, `PollTick::Diff(events)` on
  every call after). Used by both `offgrd-cli`'s `monitor` command and
  `offgrd-gui`'s always-on live view — see WIP.md for why this was
  extracted rather than duplicated.
- **Does NOT own**: the interval/timing loop, rule evaluation,
  storage, or display — those differ enough between CLI and GUI that
  forcing a shared abstraction over them would be premature.

---

## Adding a new collector

1. Add whatever `EventPayload` variant(s) it needs to
   `crates/offgrd-common/src/event.rs`. This is an exhaustive `match`
   in a few places (e.g. `crates/offgrd-cli/src/export.rs`) —
   the compiler will tell you everywhere that needs updating.
2. Implement the actual OS-level logic behind a `#[cfg(windows)]` /
   `#[cfg(not(windows))]` split, matching the pattern in any existing
   collector — the non-Windows arm should return a clear
   `anyhow::bail!` explaining it's Windows-only, never silently no-op.
3. Wrap it in a small `pub struct FooCollector;` implementing
   `offgrd_core::Collector`.
4. Add a CLI subcommand in `offgrd-cli/src/main.rs` following the
   `run_net`/`run_autoruns`/`run_services` pattern (bus, subscribe,
   run collector, drain with `try_recv`, optional `--save`, table or
   `--json` output).
5. Update this file and `WIP.md`.
