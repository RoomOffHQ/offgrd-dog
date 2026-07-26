# OffGrd Dog

**Know Everything. Trust Nothing.**

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
  offgrd-common/   Shared Event schema + ProcessRef type (no OS deps)
  offgrd-core/     EventBus, Collector trait, SQLite-backed EventStore
  offgrd-rules/    Stateless YAML rule matching -> Alert
  offgrd-cli/      Binary: `offgrd ps|history|watch|alerts`
rules/             Bundled example detection rules (YAML)
docs/
  offgrd-dog-architecture.md   Full architecture & phased roadmap
WIP.md             Live status: done / in progress / next
```

## License

GPLv3 — see `LICENSE`.

## Contributing

See `CONTRIBUTING.md`. CI (`.github/workflows/ci.yml`) runs `cargo
fmt`/`clippy`/`test` on Windows (the real target) plus a fast Linux
sanity check for the OS-agnostic crates. Note: CI is expected to fail
on the Windows job right now specifically because of
`etw_collector.rs` (see `WIP.md`) — that's known and tracked, not a
sign something else is broken.
