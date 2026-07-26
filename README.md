# OffGrd Dog

**Know Everything. Trust Nothing.**

Website: [offgrid.online/dog](https://offgrid.online/dog)

An open source Windows system-transparency / counter-surveillance
platform. See `docs/offgrd-dog-architecture.md` for the full
architecture and roadmap, and `WIP.md` for exactly what's implemented
right now vs. planned next.

This is an observability tool, not an antivirus: it never blocks,
quarantines, or modifies anything on its own. It surfaces facts.

## Status

Snapshot-based `offgrd ps`/`history` are solid (compiled/tested
mentally, straightforward Win32 + SQLite). `offgrd watch` (live ETW
process events) is a **first, unverified pass** — see `WIP.md` before
relying on it; expect to need to fix `ferrisetw` API mismatches.

## GUI (Tauri desktop app)

A real desktop UI lives in `gui/offgrd-gui` — dark theme, sidebar
navigation (Dashboard / Processes / Alerts / Rules), sortable/filterable
process table, color-coded severity badges on alerts. It's a thin
consumer of the same `offgrd-collectors`/`offgrd-core`/`offgrd-rules`
crates the CLI uses — no separate detection logic.

**Monitoring posture** (sidebar switcher): **Normal** (nothing runs in
the background — on-demand only, the original behavior), **Moderate**
(live process monitoring every 10s), **Paranoid** (process monitoring
every 3s plus a periodic full-spectrum scan — network, autoruns,
services, certificates — evaluated against every bundled rule).
Switch anytime; takes effect on the next background tick, no restart
needed.

No npm/Node required: the frontend is plain HTML/CSS/JS served
directly as Tauri's `distDir` (`withGlobalTauri: true` exposes
`window.__TAURI__.invoke` with zero bundler step).

```powershell
cargo install tauri-cli --version "^1"
cd gui\offgrd-gui\src-tauri
cargo tauri dev
```

Real app icons (generated placeholder — blue gradient "OD" mark) are
already bundled in `icons/`, so `cargo tauri build` works out of the
box. Swap them for real branding later with:

```powershell
cargo tauri icon path\to\a-1024x1024-icon.png
```

## Verifying everything at once

Given how much has been written across many iterations without a
real compile pass yet (see `WIP.md`), start here:

```powershell
.\verify.ps1
```

Runs `fmt --check`, `build --workspace`, `test --workspace`, `clippy`,
`rules-check`, and the GUI backend's own `cargo build`, in that order
(fast/safe checks first), and prints a pass/fail summary at the end.
Paste back the full console output — not just the summary — for the
fastest path to fixes. Use `.\verify.ps1 -SkipGui` if you haven't
installed `tauri-cli` yet and just want the CLI side checked first.

## Build (Windows 10/11, requires network for the first build)

```powershell
git clone <this repo>
cd offgrd-dog
cargo build --release
```

Note: `offgrd-core` depends on `rusqlite` with the `bundled` feature,
which compiles SQLite from C source as part of the build. This needs
a C toolchain available to `cargo` — on Windows that's the MSVC Build
Tools that come with Visual Studio (the same ones the `windows` crate
and most native Rust/Windows projects already require). No separate
SQLite install is needed.

## Run

```powershell
cargo run --bin offgrd -- ps
cargo run --bin offgrd -- ps --tree
cargo run --bin offgrd -- ps --json
cargo run --bin offgrd -- ps --save        # also persists to offgrd.db (SQLite)
cargo run --bin offgrd -- history          # reads back what --save stored
cargo run --bin offgrd -- history --limit 10 --json

# EXPERIMENTAL — see WIP.md, not yet verified to compile:
cargo run --bin offgrd -- watch --seconds 30
cargo run --bin offgrd -- watch --save --json

# Detection rules (bundled examples in rules/):
cargo run --bin offgrd -- alerts
cargo run --bin offgrd -- alerts --from-history --limit 100
cargo run --bin offgrd -- alerts --rules-dir path\to\custom\rules
cargo run --bin offgrd -- alerts --save
cargo run --bin offgrd -- alert-history
cargo run --bin offgrd -- alert-history --limit 10 --json

# Continuous polling-based monitor (works today, no ETW needed):
cargo run --bin offgrd -- monitor --interval 5 --save-events --save-alerts

# Lint all rule files, reporting every error in one pass:
cargo run --bin offgrd -- rules-check
cargo run --bin offgrd -- rules-check --rules-dir path\to\custom\rules

# Active TCP connections (IPv4, IP Helper API):
cargo run --bin offgrd -- net
cargo run --bin offgrd -- net --save --json

# Registry Run/RunOnce autorun entries:
cargo run --bin offgrd -- autoruns
cargo run --bin offgrd -- autoruns --save --json

# Export stored data to a file (JSON/CSV/HTML/Markdown):
cargo run --bin offgrd -- export --kind events --format html --output events.html
cargo run --bin offgrd -- export --kind alerts --format csv --output alerts.csv
cargo run --bin offgrd -- export --kind events --format markdown --output events.md --limit 50

# Windows services:
cargo run --bin offgrd -- services
cargo run --bin offgrd -- services --save --json

# Certificates in ROOT/CA/MY system stores:
cargo run --bin offgrd -- certs
cargo run --bin offgrd -- certs --save --json
```

## Run tests (any OS)

```
cargo test --workspace
```

`offgrd-common` is OS-agnostic and its tests run anywhere. `offgrd-cli`
compiles everywhere but its `ps` command only works on Windows (see
`crates/offgrd-cli/src/platform/`); on other OSes it returns a clear
error instead of silently doing nothing.

## Repository layout

```
crates/
  offgrd-common/     Shared Event/Alert schema + ProcessRef type (no OS deps)
  offgrd-core/       EventBus, Collector trait, SQLite-backed EventStore
  offgrd-rules/      Stateless YAML rule matching -> Alert
  offgrd-collectors/ Shared collectors (Win32 process snapshot, ETW) - used by CLI and GUI
  offgrd-cli/        Binary: `offgrd ps|history|watch|monitor|alerts|alert-history|rules-check`
gui/
  offgrd-gui/        Tauri desktop app (dark theme, dashboard/processes/alerts/rules)
rules/               Bundled example detection rules (YAML)
docs/
  offgrd-dog-architecture.md   Full architecture & phased roadmap
  collectors.md                Per-collector reference: data source, schema, limitations
WIP.md               Live status: done / in progress / next
```

## License

GPLv3 — see `LICENSE`.

## Contributing

See `CONTRIBUTING.md`, `ROADMAP.md` (phased plan), and `CHANGELOG.md`.
CI (`.github/workflows/ci.yml`) runs `cargo fmt`/`clippy`/`test` on
Windows (the real target), a fast Linux sanity check for the
OS-agnostic crates, `cargo-deny` supply-chain checks, and a
`rules-check` lint of the bundled detection rules. Note: CI is
expected to fail on the Windows job right now specifically because of
`etw_collector.rs` (see `WIP.md`) — that's known and tracked, not a
sign something else is broken.
