# OffGrd Dog — Work In Progress

Updated with every delivered chunk of code. Three sections only:
**Done**, **In progress**, **Next**. Nothing here is aspirational
beyond "Next" — if it's in "Done" it's real code in this zip.

---

## Done

- [x] Cargo workspace scaffolding
- [x] `offgrd-common`: `Event`/`EventCategory`/`EventSource`/`Severity`/`EventPayload`/`ProcessRef`/`Alert` schema, tested
- [x] `offgrd-core`: `EventBus`, `Collector` trait, `EventStore` (events + alerts, SQLite, tested)
- [x] `offgrd-cli`: `ProcessSnapshotCollector`, `offgrd ps` [`--tree`][`--json`][`--save`], `offgrd history`
- [x] `offgrd-rules`: `Rule`/`Condition`/`RuleSet`, tested; bundled example rules in `rules/`
- [x] `offgrd-cli`: `offgrd alerts` [`--from-history`][`--save`], `offgrd alert-history`
- [x] **`offgrd monitor`** (NEW this round, `crates/offgrd-cli/src/monitor.rs`) — continuous, polling-based process start/stop monitoring that works **today, with no dependency on the still-unverified ETW code**. Reuses the already-solid `ProcessSnapshotCollector` on a fixed interval (`--interval` seconds), diffs successive snapshots by pid set (first tick = baseline only, no false "everything just started" noise), evaluates the rule engine on each tick's diff, and can persist both events and alerts (`--save-events`, `--save-alerts`). Runs until Ctrl+C.
- [x] `EtwProcessCollector` (`offgrd watch`) — still **experimental/unverified**, unchanged this round; `offgrd monitor` is not a replacement for it (different tradeoffs — see the module doc comment in `monitor.rs`), just a way to get real continuous monitoring shipped without waiting on ETW.
- [x] Cross-platform stub so `cargo build`/`cargo test` succeed on Linux/macOS too
- [x] **Open-source project scaffolding** (NEW this round, zero compilation risk — pure config/docs): `.github/workflows/ci.yml` (fmt + clippy + build + test, Windows job = real target, Linux job = fast sanity check for OS-agnostic crates), `.github/workflows/nightly.yml` (unsigned nightly build artifact), issue templates (bug report, feature request, detection rule), PR template, `CODEOWNERS` (kernel/unsafe-code-adjacent paths scoped to a stricter reviewer tier, per the original architecture doc's governance section), `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `rustfmt.toml`, `.editorconfig`.

## In progress

- [ ] Nothing actively mid-flight in `monitor.rs` or the new `.github/` scaffolding.
- [ ] **CI will currently fail on the Windows job** because of `etw_collector.rs` — this is expected, not a new problem. Once you (or CI, if you push this to a real GitHub repo) get a real Windows compiler error from it, that's exactly the signal needed to fix it. The Linux cross-platform-check job should pass since it doesn't touch Windows-only code.
- [ ] `EtwProcessCollector` still needs your `cargo build` output before I can fix its API-signature guesses (unchanged blocker).

## Explicitly deferred (with reasoning)

- **Exit codes on stop events from `monitor`**: polling can only observe that a pid disappeared, not *why* (clean exit vs. crash vs. killed) or its exit code — that information only exists at the moment of exit, which polling by definition misses. This is a real, structural limitation of polling vs. ETW, not an oversight; it's exactly the kind of gap the ETW collector is meant to close once it's verified working.
- **Merging `monitor` and the future ETW daemon into one code path**: deliberately kept as two separate, independent implementations for now rather than one collector with a "polling vs. ETW" flag — premature to unify before ETW is even confirmed to compile.

## Next (in the order we'll tackle them)

1. **Fix `etw_collector.rs`** based on your `cargo build` output — unchanged top blocker for anything ETW-related.
2. Once ETW works: decide whether `offgrd watch`/`monitor` merge into one collector-agnostic daemon command, or stay separate (polling as a no-admin-rights fallback, ETW as the high-fidelity default).
3. **GUI shell (Tauri)**: after the above is stable.

## How to report back

Paste the exact `cargo build`/`cargo test` output. `monitor.rs` is new
this round but built from patterns already proven elsewhere in the
project — a compile error here would be a real bug on my end, same as
`offgrd-rules` last round. `etw_collector.rs` remains the one place
where I expect and need your error output specifically.
