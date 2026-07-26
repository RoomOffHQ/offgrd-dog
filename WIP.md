# OffGrd Dog — Work In Progress

Per your instruction, this round was built end-to-end **assuming
everything (including the still-unverified ETW collector) works,**
without waiting for a compile/test pass. That means the "Done" list
below is broader but less trustworthy than usual — treat all of it as
"written, not yet compiled," not just the items previously flagged
experimental. Real verification (yours) comes next; this file tells
you exactly where to expect problems.

---

## Done (written this round and previously — see caveat above)

- [x] Everything from previous rounds: `offgrd-common`, `offgrd-core`
  (bus + SQLite storage for events & alerts), `offgrd-rules`
  (YAML rule engine + `load_dir_report` linting), bundled `rules/`,
  `.github/` CI + governance scaffolding.
- [x] **Major refactor (NEW): `offgrd-collectors` crate.** Moved
  `ProcessSnapshotCollector`, `EtwProcessCollector`, and all the
  Win32/ETW `platform` code out of `offgrd-cli` into a new shared
  library crate, `crates/offgrd-collectors`. Reason: the GUI needs the
  exact same collectors the CLI uses, and duplicating Win32/ETW code
  between two binaries would be a maintenance trap and a correctness
  risk (two copies to keep in sync). `offgrd-cli` and the new GUI both
  depend on it now. **This is a real structural change, not just new
  code** — `offgrd-cli`'s `main.rs`/`monitor.rs` imports were updated
  accordingly, but this is exactly the kind of mechanical refactor
  that's easy to get subtly wrong (a missed `use`, a path typo)
  without a compiler checking it, so double-check this compiles first
  if things break.
- [x] **`gui/offgrd-gui`: a real Tauri desktop GUI (NEW).** Dark
  theme, sidebar nav (Dashboard / Processes / Alerts / Rules),
  sortable + filterable process table, color-coded severity badges,
  live dashboard stats. Rust backend (`src-tauri/src/main.rs`) exposes
  4 commands (`list_processes`, `run_alerts_scan`,
  `get_alert_history`, `get_dashboard_summary`), all thin wrappers
  around `offgrd-collectors`/`offgrd-core`/`offgrd-rules` — the GUI
  has no detection logic of its own, same principle as the CLI.
  Frontend is plain HTML/CSS/JS with **no npm/bundler step**
  (`withGlobalTauri: true` exposes `window.__TAURI__.invoke`
  directly) — this was a deliberate choice to minimize new build
  tooling/failure surface, at the cost of not having a component
  framework if the UI grows a lot more complex later.

## Known gaps / things that will need fixing, flagged in advance

- **Tauri version assumption**: backend uses Tauri v1's API shape
  (`tauri::Builder`, `tauri.conf.json` schema, `tauri-build`). This is
  the version I have the most confidence in from training data, but
  it's not verified against whatever's actually current/installable
  today — if `cargo install tauri-cli` pulls v2 by default now, the
  config schema and some API names differ and this will need
  adjusting. Pin explicitly if needed: `cargo install tauri-cli
  --version "^1"` (already in the README).
- **No app icons shipped.** `tauri.conf.json` references
  `icons/icon.ico`, which doesn't exist in this zip. `cargo tauri dev`
  may or may not tolerate that (uncertain); `cargo tauri build`
  (installer packaging) definitely needs real icons. Generate them
  before packaging: `cargo tauri icon path\to\a-1024x1024-icon.png`
  (standard Tauri workflow, not a bug — just an asset I can't produce
  offline).
- **GUI's `DEFAULT_DB_PATH`/`DEFAULT_RULES_DIR` are relative paths**
  (`"offgrd.db"`, `"rules"`), same simplification as the CLI — means
  the GUI needs to be launched from the repo root (or wherever those
  exist) to find them right now. A packaged installer needs a real
  per-user data directory; not addressed yet.
- **`offgrd-collectors`' Cargo.toml pulls in `ferrisetw` unconditionally
  on Windows** (needed for the still-unverified ETW collector) even
  though the GUI doesn't use `EtwProcessCollector` yet — meaning any
  `ferrisetw` compile error will block the GUI build too, not just
  `offgrd watch`. Worth knowing before you dig into an error there.
- **No live-updating GUI yet** — Processes/Alerts are "click Refresh /
  Scan now," not push-updated. A real live view needs a Tauri event
  channel from a running collector to the frontend (`app.emit` +
  `listen()` on the JS side), which is a reasonable next step but adds
  more surface — deliberately not attempted this round given how much
  is already unverified.

## Next (once you've compiled and reported back)

1. Fix whatever `cargo build --workspace` reports — expect issues
   concentrated in three places, roughly in order of how much I'd
   bet on them: (a) `offgrd-collectors`/`offgrd-cli` import paths from
   the refactor, (b) `etw_collector.rs`'s `ferrisetw` API guesses
   (unchanged risk from before), (c) the GUI's Tauri v1 API/config
   assumptions.
2. Real app icons + per-user data directory for the GUI.
3. Live-updating GUI views via Tauri events, once the above is solid.

## How to report back

Paste the exact `cargo build --workspace` output first (covers
common/core/rules/collectors/cli). Then, separately,
`cd gui\offgrd-gui\src-tauri && cargo build` (or `cargo tauri dev`)
output for the GUI specifically, since it's a separate
Cargo.toml/Cargo.lock from the main workspace. I'll patch based on
real errors and re-deliver a full, updated zip — never a partial diff.
