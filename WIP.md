# OffGrd Dog — Work In Progress

**Start here: run `.\verify.ps1` from the repo root** (see README) and
paste back its full output. A LOT has been written across many rounds
without a single real compile pass — this script runs every check
(fmt, build, test, clippy, rules-check, GUI build) in one command so
you don't have to hunt through this file for individual commands.

Built end-to-end assuming everything works, without waiting for a
compile/test pass (per your instruction). Treat all of "Done" as
"written, not yet compiled." This file tells you exactly where to
expect problems, in rough order of how much I'd bet on each.

---

## Done (written, not yet compiled/tested)

- [x] Everything from previous rounds: `offgrd-common`, `offgrd-core`,
  `offgrd-rules`, bundled `rules/`, `.github/` scaffolding,
  `offgrd-collectors` refactor, the Tauri GUI shell + live updates +
  per-user data directory.
- [x] **De-duplicated the polling-diff logic** (previous round):
  `crates/offgrd-collectors/src/poll_diff.rs` — `PollDiffer`/`PollTick`,
  extracted from what used to be two independent, hand-copied
  implementations (`offgrd-cli`'s `monitor.rs` and
  `offgrd-gui`'s `live.rs`). Both now call the exact same
  `PollDiffer::tick()`; each still owns its own interval loop,
  storage, and display/emit logic (stdout vs. Tauri events), since
  those genuinely differ and forcing them into one shared abstraction
  would be premature. 2 unit tests in `poll_diff.rs` (first tick
  is always a baseline, second tick is a diff).
- [x] **GUI UX pass (NEW this round):**
  - `offgrd-rules::RuleSet::rules()` — read-only accessor exposing
    loaded rules (previously only `len()`/`is_empty()` were public).
  - New Tauri command `list_rules` + `RuleDto` — the Rules page now
    shows real rule cards (title, severity badge, description, a
    human-readable condition summary, MITRE ATT&CK ID) instead of
    static placeholder text.
  - Processes page: **Tree view toggle** — mirrors `offgrd ps --tree`'s
    parent→child indented tree logic, reimplemented in `app.js`
    (`renderProcessTree`) since the GUI works from `ProcessDto` JSON,
    not the CLI's Rust `ProcessRef` directly. Same roots/visited-set-
    guard logic as the CLI version.
  - Real generated app icons (blue gradient "OD" mark, all sizes
    Tauri expects) — `cargo tauri build` shouldn't fail on missing
    icon files anymore.
  - **JSON/CSV export (NEW this round)** for both Processes and
    Alerts, via Tauri's native `dialog.save` + `fs.writeFile` (not a
    browser `<a download>` trick, which is unreliable inside a
    webview and doesn't let the user choose a save location — matters
    for a security tool's forensic exports per the architecture doc's
    Exports module). Requires new `allowlist` entries in
    `tauri.conf.json` (`dialog.save`, `fs.writeFile` scoped to
    `$APPDATA`/`$DOWNLOAD`/`$DOCUMENT`/`$HOME`) — this is new,
    unverified Tauri config surface, flagged below.
- [x] **CLI integration tests** (previous round):
  `crates/offgrd-cli/tests/cli_integration.rs` — 9 tests that run the
  actual compiled `offgrd` binary (via Cargo's built-in
  `CARGO_BIN_EXE_offgrd`, no `assert_cmd` dependency needed) rather
  than just unit-testing the library crates: `--help`/`--version`
  exit cleanly and mention every subcommand; `history`/`alert-history`
  against a fresh empty database are graceful, not errors;
  `rules-check` correctly reports success/failure/zero-rules for
  missing dir / one bad file / one good file; no-subcommand exits
  non-zero; and platform-specific behavior for `ps` (succeeds and
  returns data on Windows, fails with a clear Windows-only message
  everywhere else).
- [x] **Remaining open-source ecosystem pieces (NEW this round)**:
  `ROADMAP.md` (phased plan, referenced by README/CONTRIBUTING but
  previously missing), `CHANGELOG.md` (Keep a Changelog format),
  `deny.toml` (cargo-deny supply-chain policy — license allowlist,
  advisory/yanked-crate checks, per the architecture doc's Security
  section), `.github/dependabot.yml` (weekly PRs for both the main
  workspace and the separate GUI Cargo.toml), `.github/workflows/release.yml`
  (tag-triggered build + SHA256 checksum + CycloneDX SBOM + draft
  GitHub Release — explicitly NOT code-signed yet, needs real
  certs/secrets this repo doesn't have), plus two new CI jobs:
  `security-checks` (cargo-deny) and `lint-rules` (builds the CLI and
  runs `rules-check` against the bundled `rules/` directory as an
  actual CI gate).
- [x] **Network Monitor** (previous round) — `offgrd-common::EventPayload::NetworkConnectionObserved`,
  `offgrd-collectors::NetworkSnapshotCollector` (Win32's
  `GetExtendedTcpTable`, IPv4 TCP only), `offgrd net [--save] [--json]`.
- [x] **Autoruns/Persistence Monitor (NEW this round)** — another
  Tier-1 module. `offgrd-common::EventPayload::AutorunEntryObserved`
  (hive, key path, value name/data). `offgrd-collectors::AutorunsCollector`
  reads the well-known registry Run/RunOnce keys (HKLM + HKCU, plus
  the WOW6432Node 32-bit view on 64-bit Windows — a real, documented
  gotcha this collector accounts for) via `RegOpenKeyExW`/`RegEnumValueW`.
  Missing keys (e.g. no WOW6432Node on a machine that's never
  installed 32-bit software) are logged and skipped, not treated as a
  scan failure. New CLI command: `offgrd autoruns [--save] [--json]`.
  Scheduled tasks, services, startup-folder shortcuts, and WMI
  persistence are the same conceptual mechanism but different data
  sources — deliberately not attempted together with this.
- [x] **Rule engine extended: `value_data_contains` condition** —
  `offgrd-rules::Condition` gained a field for matching
  `AutorunEntryObserved`'s `value_data`, following the exact same
  pattern as `image_path_contains`/`command_line_contains`
  (independent, type-gated checks — a rule using this field only ever
  matches autorun events, never process events, and vice versa). New
  bundled rule: `rules/autorun-from-temp-or-appdata.yaml` (flags
  autoruns pointing into `%AppData%` — a real, if noisy, persistence
  heuristic). 1 new unit test covering both the positive match and
  the "wrong event shape never matches" guarantee.
- [x] **`offgrd export` (NEW this round)** — the architecture doc's
  Exports module, CLI side: `--kind events|alerts --format
  json|csv|html|markdown --output FILE [--limit N]`. Pure Rust, no
  OS APIs, no `unsafe` — reads from the already-built `EventStore`
  and writes a file, same lowest-risk category as `offgrd-rules`.
  HTML export is a real standalone styled document (dark theme,
  matching the GUI's look), not a bare table. 5 unit tests
  (`crates/offgrd-cli/src/export.rs`) covering CSV/HTML/Markdown
  shape and CSV-escaping edge cases. XML/PDF/encrypted-archive
  (also listed in the architecture doc) deliberately not attempted —
  real, separate follow-ups.
- [x] **Service Manager (NEW this round)** — another Tier-1 module.
  `offgrd-common::EventPayload::ServiceObserved` (name, display name,
  decoded state/type strings; `start_type`/`binary_path` deliberately
  `None` for now — see module doc in `services.rs` for why: those need
  a second `QueryServiceConfigW` two-call dance per service, kept out
  of this pass rather than stacking two independent variable-buffer
  patterns at once). `offgrd-collectors::ServicesCollector` via
  `OpenSCManagerW`/`EnumServicesStatusExW` (enumerate-only rights, no
  admin needed). New CLI command: `offgrd services [--save] [--json]`.
  `export.rs`'s event-summary match updated for the new payload
  variant (Rust's exhaustive-match checking catches this kind of
  thing at compile time, which is exactly the safety net this pattern
  of "add a payload variant, then find every match site" relies on).
- [x] **Certificate Inspector (installed-cert variant, NEW this
  round)** — a Tier-2 module from the architecture doc. New
  `EventCategory::Certificates` (required updating `storage.rs`'s
  category label/parse match pairs — again caught by Rust's
  exhaustiveness checking). `offgrd-common::EventPayload::CertificateObserved`
  (store name, subject, issuer, thumbprint, validity dates).
  `offgrd-collectors::CertificatesCollector` via
  `CertOpenSystemStoreW`/`CertEnumCertificatesInStore` over
  ROOT/CA/MY. Thumbprint uses a small hand-rolled SHA-1 (2 unit tests
  against known test vectors) rather than a crypto dependency, since
  it's a display/lookup identifier only, never a trust decision. New
  CLI command: `offgrd certs [--save] [--json]`. This is "what's
  installed in the trust store," not live TLS chain inspection of an
  active connection — a real, separate, harder capability.
- [x] **GUI parity for the 4 newer collectors (NEW this round)** — the
  GUI previously only exposed `ProcessSnapshotCollector`; it now has
  Network/Autoruns/Services/Certificates views too, each following
  the exact same fetch/filter/render table pattern as Processes.
  4 new Tauri commands (`list_network`, `list_autoruns`,
  `list_services`, `list_certificates`), all built on a new shared
  `collect_and_extract` helper (same bus/subscribe/run/drain pattern
  `list_processes` already used, factored out instead of copy-pasted
  four more times). Frontend: one generic `simpleViews` config object
  + `refreshSimpleView`/`renderSimpleView` drives all four tables,
  rather than four near-identical JS functions. Lower incremental
  risk than the collectors themselves, since it's only wiring
  already-written Rust collectors into already-proven GUI patterns —
  no new `unsafe` code in this round.
- [x] **`docs/collectors.md` (NEW this round)** — a consolidated
  per-collector reference (data source, exact payload schema,
  privilege requirements, known limitations, "how to add a new one"
  checklist), pulling together what was previously scattered across
  each collector's module doc comment. Pure documentation, no code
  changes — consolidation, not expansion, per the note above about
  pausing feature growth.

## Known gaps / things that will need fixing, flagged in advance

**`CertificatesCollector`'s `unsafe` code is the newest addition,
check it first if certs-related code fails.** It dereferences a raw
`*const CERT_CONTEXT` pointer returned by `CertEnumCertificatesInStore`
(the API's documented enumeration contract says NOT to free it
ourselves between calls — only the guard drops the *store*, never an
individual cert context), reads a DER byte slice via
`pbCertEncoded`/`cbCertEncoded`, and does manual `FILETIME`-to-Unix-
timestamp math. Three genuinely different `unsafe` patterns in one
collector, more than any previous one — worth extra scrutiny.

Also worth double-checking: `CertGetNameStringW`'s buffer-length
convention (character count including NUL, not byte count) — a subtly
different convention than the byte-count conventions used elsewhere
in this project's registry/network code.

**Pausing new-feature expansion here.** Five collectors (process, ETW,
network, autoruns, services) plus the GUI plus the rule engine plus
storage is a lot of surface accumulated without a single real compile
pass. Adding a sixth collector or another GUI feature right now has
worse odds of being useful than spending that effort on your actual
`.\verify.ps1` output once you have it. Next round should be fixes,
not more additions — unless you tell me otherwise.

- **`ServicesCollector`'s `unsafe` code (NEW this round)** — the
  `EnumServicesStatusExW` two-call size-query pattern mirrors
  `NetworkSnapshotCollector`'s approach, but this one also reads two
  embedded `PWSTR` pointers per entry (`lpServiceName`/`lpDisplayName`)
  that point *into* the same buffer rather than being separately
  allocated — worth specific scrutiny that the pointer-to-string
  conversion doesn't read past the buffer if a service name happens to
  sit at the very end of it.
- **`AutorunsCollector`'s registry `unsafe` code** — `RegEnumValueW`'s buffer-size out-parameters
  (`name_len`, `data_len`) are passed as both in (capacity) and out
  (actual size) — a subtlety of this specific API that's easy to get
  backwards. Also double check `wide_bytes_to_string`'s manual
  byte-pair-to-u16 reconstruction (registry `REG_SZ` data comes back
  as raw bytes, not already as `u16`s, unlike the Toolhelp32/ETW code
  paths) — this is a different decoding step than anything in the
  previously-shipped collectors, so it's unverified in a way that
  isn't just "the same pattern as before."
- **`NetworkSnapshotCollector` is new `unsafe` surface** — it does raw pointer arithmetic over
  a `GetExtendedTcpTable` buffer (casting to `MIB_TCPTABLE_OWNER_PID`
  and reading a variable-length row array via `dwNumEntries`). This is
  a well-documented, standard pattern for this specific Win32 API (not
  a guess the way `ferrisetw`'s API surface was), but it's still raw
  pointer work I can't compile-check here — this is the single
  highest-risk piece of `unsafe` code in this delivery, more so than
  the existing Toolhelp32 code, and worth extra scrutiny/testing
  before trusting its output. Also double-check the IPv4
  byte-order handling in `ipv4_to_string`/`port_from_network_order` —
  address bytes and port bytes have different, easy-to-mix-up
  endianness conventions in this API.
- This refactor touches three files that all need to agree with each
  other's new shapes: `offgrd-collectors/src/lib.rs` (new exports),
  `offgrd-cli/src/monitor.rs` (rewritten to use `PollDiffer`), and
  `gui/offgrd-gui/src-tauri/src/live.rs` (rewritten to use
  `PollDiffer`). If something doesn't compile, check these three
  first — a mismatched import or a forgotten `pub use` is the most
  likely failure mode for a mechanical refactor like this.
- Previously flagged, still unresolved: `etw_collector.rs`'s
  `ferrisetw` API guesses; Tauri v1 API/version assumptions in the
  GUI.
- **`list_rules` command + `RuleDto`**: straightforward, low risk —
  same pattern as the other commands. The JS-side `renderProcessTree`
  reimplementation of the CLI's tree logic (pure JS, no compile risk)
  is worth eyeballing in the running app against your machine's real
  process tree, not just trusting it in theory.
- **Also new and unverified**: the `tauri.conf.json` allowlist changes
  for export (`dialog.save`, `fs.writeFile` + scope globs). Tauri's
  fs scope syntax (`$APPDATA/**` etc.) is written from recollection of
  Tauri v1's path-scoping conventions — if exports fail with a
  "path not allowed"/scope error rather than a compile error, that's
  the first place to check, not a sign the whole export feature is
  broken.
- **New this round, config-only (no Rust compile risk, but untested
  against a real GitHub Actions run)**: `release.yml`'s use of
  `cargo-cyclonedx` and `softprops/action-gh-release@v2`, and
  `ci.yml`'s new `security-checks` (`EmbarkStudios/cargo-deny-action`)
  and `lint-rules` jobs. `deny.toml`'s license allowlist is a
  starting guess, not audited against the project's actual current
  dependency tree — expect to need to add a license or two once
  `cargo deny check` actually runs against it.
  matches the current `main.rs` messages exactly (e.g. "no events
  stored", the rules-check summary format). If you've been running
  with a slightly different build than what's in this zip, or if a
  future wording tweak isn't mirrored in the test, that's a test
  fixture going stale, not a real regression — worth a glance before
  assuming a genuine bug if these specific assertions fail.
- ~~No shipped app icons~~ — **fixed this round**: real (generated
  placeholder, blue-gradient "OD" mark) PNG/ICO icons now ship in
  `gui/offgrd-gui/src-tauri/icons/` at the sizes Tauri expects
  (32/128/128@2x/512 PNG + multi-size ICO), so `cargo tauri build`
  shouldn't fail on missing icon files anymore. Swap for real branding
  later via `cargo tauri icon`.

## Next (once you've compiled and reported back)

1. `cargo build --workspace` (CLI side) — should now also exercise
   `offgrd-collectors`' new `poll_diff` module and its tests.
2. `cd gui\offgrd-gui\src-tauri && cargo build` (GUI side) — confirms
   `live.rs`'s simplified version still works end-to-end with the
   shared `PollDiffer`.
3. Once both compile: real icons, and reconsidering whether the ETW
   collector should feed the GUI's live view too (higher fidelity,
   same tradeoffs as before) — now easier to reason about since the
   diffing logic is unified.

## How to report back

Paste `cargo build --workspace` output first, then separately the GUI
build output. I'll patch based on real errors and re-deliver a full,
updated zip — never a partial diff.
