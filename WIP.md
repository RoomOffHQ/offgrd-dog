# OffGrd Dog — Work In Progress

Updated with every delivered chunk of code. Three sections only:
**Done**, **In progress**, **Next**. Nothing here is aspirational
beyond "Next" — if it's in "Done" it's real code in this zip.

---

## Done

- [x] Cargo workspace scaffolding (`Cargo.toml`, `rust-toolchain.toml`, `.gitignore`)
- [x] `offgrd-common`: `Event` / `EventCategory` / `EventSource` / `Severity` / `EventPayload` / `ProcessRef` schema, with a passing JSON round-trip unit test
- [x] `offgrd-core`: `EventBus` (wraps `tokio::sync::broadcast`) + `Collector` async trait, with unit tests
- [x] `offgrd-core`: `EventStore` — SQLite-backed persistence (`rusqlite`, bundled), tested (in-memory + on-disk)
- [x] `offgrd-cli`: `ProcessSnapshotCollector` — Win32 Toolhelp32 process listing as a real `Collector`
- [x] `offgrd-cli`: `offgrd ps` [`--tree`] [`--json`] [`--save`] — one-shot snapshot through the bus
- [x] `offgrd-cli`: `offgrd history [--limit N]` — reads back stored events
- [x] Cross-platform stub so `cargo build`/`cargo test` succeed on Linux/macOS too

## In progress — THIS DELIVERY, marked experimental on purpose

- [ ] **`EtwProcessCollector`** (`crates/offgrd-cli/src/etw_collector.rs`) — live process start/stop via the `Microsoft-Windows-Kernel-Process` ETW provider, using the `ferrisetw` crate. **This is the riskiest code shipped so far and is explicitly NOT verified to compile.** Specific things that may need fixing once you build it:
  - `ferrisetw` 1.x's exact API names (`Provider::by_guid`, `UserTrace::new().enable(...).start_and_process()`, `Parser::try_parse::<T>`) are written from recollection, not checked against the crate's current docs/version.
  - Whether the provider needs specific keywords/level enabled to emit event IDs 1 (start) and 2 (stop) with the `ProcessID`/`ParentProcessID`/`ImageName`/`CommandLine` properties I'm assuming exist — may need adjusting field names or enabling flags.
  - `offgrd watch` currently has **no graceful stop for the ETW session itself**: `tokio::select!` cancels the `collector.run()` future on Ctrl+C/timeout, but the underlying OS thread running `start_and_process()` (which blocks) is not joined or told to stop — it will keep running detached until the whole process exits. Fine for "run the CLI, Ctrl+C the whole thing," not fine for embedding this in a long-lived service later. A real `stop()` handle (probably via `ferrisetw`'s trace `.stop()` if it exists, or a control GUID/event) is needed before this collector is used anywhere but a short-lived CLI invocation.
  - New CLI command: `offgrd watch [--seconds N] [--save] [--json]`.

## Explicitly deferred (with reasoning)

- Nothing newly deferred this round — see prior notes on command-line-via-PEB (now superseded: ETW gives us `CommandLine` directly, assuming the property name above is correct).

## Next (in the order we'll tackle them)

1. **Fix whatever `cargo build`/`cargo test` reports for `etw_collector.rs`** — this is the expected next step before anything else, given how experimental this piece is.
2. **Give `EtwProcessCollector` a real stop mechanism** once it compiles and the thread-leak issue above needs addressing.
3. **Basic `offgrd-rules` crate**: stateless rule matching over the event stream, feeding `offgrd alerts`.
4. **GUI shell (Tauri)**: after the above is stable.

## How to report back

Paste the exact `cargo build`/`cargo test` output. For this delivery
specifically, compiler errors in `etw_collector.rs` are expected and
useful — that's exactly the feedback loop needed to get `ferrisetw`'s
real API signatures right. I'll patch and re-deliver a full, updated
zip — never a partial diff.
