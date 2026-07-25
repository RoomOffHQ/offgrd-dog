# OffGrd Dog — Architecture & Implementation Roadmap

**Tagline:** Know Everything. Trust Nothing.
**License:** GPLv3
**Category:** Windows system-transparency / counter-surveillance observability platform (Sysmon + Process Explorer + Autoruns + OSQuery + Zeek, unified)

This document is a founding architecture and roadmap for the project — the level of detail a team would use to start building and to structure the GitHub org. It is not a finished codebase (that's a multi-year, many-contributor effort), but it's structured so each section maps directly to an implementable milestone.

---

## 1. Guiding Constraints

- **Observability only.** No blocking, no "cleaning," no auto-quarantine in v1. Detection surfaces facts; the user (or a later, opt-in policy engine) decides. This keeps the project legally and ethically unambiguous and avoids AV-style false-positive liability.
- **Local-first.** No telemetry, no cloud calls, no phone-home update checks without explicit opt-in. GeoIP/threat-intel databases ship as offline, versioned data files.
- **Two-process model.** A minimal, auditable **kernel-mode driver** (signed, WHQL-eligible) does only what user-mode cannot: ETW kernel provider consumption, minifilter for filesystem/registry hooks where ETW is insufficient, and image-load callbacks. Everything else — correlation, UI, storage, rules — lives in **user-mode Rust**, which is where 95% of the attack surface and 95% of contributions will live.
- **Memory safety by default.** `#![forbid(unsafe_code)]` in every crate except the driver shim and a small, isolated `ffi` crate; unsafe blocks require a `// SAFETY:` comment and a named reviewer in CODEOWNERS.

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        offgrd-gui (Tauri)                    │
│   Dashboards · Timeline · Explorers · Alert Center · Search  │
└───────────────────────────┬───────────────────────────────────┘
                             │ local IPC (named pipe / gRPC over UDS)
┌───────────────────────────┴───────────────────────────────────┐
│                     offgrd-core (Rust service)                │
│  ┌───────────┐ ┌────────────┐ ┌───────────────┐ ┌──────────┐  │
│  │ Collectors│ │ Correlation │ │ Rule Engine   │ │ Storage  │  │
│  │ (ETW, WMI,│ │ Engine      │ │ (Sigma-like)  │ │ (sqlite/ │  │
│  │ Registry, │ │ (graph +    │ │               │ │ duckdb)  │  │
│  │ Net, FS…) │ │ sliding-win)│ │               │ │          │  │
│  └───────────┘ └────────────┘ └───────────────┘ └──────────┘  │
│  ┌───────────┐ ┌────────────┐ ┌───────────────┐                │
│  │ Plugin Mgr│ │ REST API   │ │ Export Engine │                │
│  │ (WASM     │ │ (localhost │ │ (JSON/CSV/PDF)│                │
│  │ sandboxed)│ │ only)      │ │               │                │
│  └───────────┘ └────────────┘ └───────────────┘                │
└───────────────────────────┬───────────────────────────────────┘
                             │ IOCTL / shared ring buffer
┌───────────────────────────┴───────────────────────────────────┐
│                offgrd-driver (kernel, Rust/C, signed)          │
│  ETW kernel session consumer · Minifilter (FS/Registry)        │
│  Image-load & thread-creation callbacks · Object callbacks      │
└─────────────────────────────────────────────────────────────────┘
```

**Why this split:** the driver is small and stable (rarely changes → easier WHQL/signing cadence); almost all detection logic, rules, and UI ship as user-mode updates that don't require kernel re-certification.

---

## 3. Data Flow

1. **Collectors** subscribe to ETW providers (`Microsoft-Windows-Kernel-Process`, `-Kernel-Registry`, `-Kernel-File`, `-Kernel-Network`, `-PowerShell`, `-WMI-Activity`, `-DotNETRuntime`, Sysmon-equivalent custom provider if the driver installs one) plus WMI event subscriptions, registry change notifications, and the minifilter's ring buffer.
2. Each raw event is normalized into a common `Event` envelope (see §6) and pushed onto an in-process **event bus** (`tokio::sync::broadcast` or a lock-free MPMC ring buffer for high-volume topics like file I/O).
3. The **Correlation Engine** consumes the bus, maintains a rolling **process/behavior graph** (nodes = processes/threads/handles, edges = causal relationships: spawned, injected-into, wrote-to, connected-to), and evaluates **Rule Engine** rules against both individual events and graph patterns (multi-hop chains, e.g. Office → PowerShell → encoded cmd → network → injection).
4. Matches become **Alerts**, written to storage, pushed to the GUI over IPC, and available via REST/CLI.
5. **Storage**: append-only event log (Parquet or SQLite WAL) for forensics + a queryable index (SQLite/DuckDB) for the timeline/search UI. Snapshots (registry/autoruns/service/driver state) are periodic full-state captures, diffable.

---

## 4. Module Breakdown (v1 scope vs. later)

### Tier 1 — MVP (drives whether the project is even usable)
| Module | Data source | Notes |
|---|---|---|
| System Overview / Dashboard | aggregated | CPU, RAM, network, active alerts |
| Process Explorer | ETW Kernel-Process, NtQuerySystemInformation | tree view, signer, hash, command line, parent spoof detection |
| Network Monitor / Socket Explorer | ETW Kernel-Network, `GetExtendedTcpTable` | per-process connections, DNS resolution join |
| DNS Monitor | ETW `Microsoft-Windows-DNS-Client` | query/response pairing |
| Autoruns / Persistence Monitor | registry run keys, services, scheduled tasks, WMI subscriptions, startup folders | static scan + change monitoring |
| Registry Monitor | minifilter or `RegNotifyChangeKey` + ETW Kernel-Registry | filterable live feed |
| Filesystem Monitor | minifilter | create/write/delete/rename with process attribution |
| Event Timeline | all of the above | the unifying UI |
| Alert Center + basic Rule Engine | correlation engine | Sigma-subset rule format |
| Snapshot & Diff (registry, autoruns, services, drivers) | periodic scan | forensic baseline comparison |
| CLI (`offgrd-cli`) | REST API | scriptable, JSON output |

### Tier 2 — Depth
DLL/Driver Explorer, Handle Explorer, Thread Explorer, Memory Explorer (RWX/entropy scanning via `MiniDumpWriteDump`-style read-only inspection), USB Monitor, Firewall Inspector (WFP log), TLS/Certificate Inspector (SNI + cert chain from ETW Schannel provider), WMI/PowerShell/COM/RPC/Named-pipe monitors, Clipboard Monitor, Camera/Mic/Screen-capture-handle detection (via device handle + session enumeration, **not** interception).

### Tier 3 — Advanced detection & ecosystem
Injection technique detectors (reflective DLL, process hollowing, APC, thread hijack, manual map — via image-load + memory-protection + thread-start-address heuristics), kernel callback/SSDT integrity checks, ETW-tampering detection (session count/consumer anomalies), Plugin SDK + WASM sandbox, REST/OpenAPI, encrypted forensic export, Bluetooth/WiFi monitors, GPU activity.

Building Tier 1 first and shipping it is far more valuable than a shallow implementation of everything — this is how Sysmon, OpenSnitch, and Zeek all grew.

---

## 5. Repository Structure

```
offgrd-dog/
├── crates/
│   ├── offgrd-driver/          # kernel driver (KMDF, Rust where possible, C shims where required)
│   ├── offgrd-driver-ffi/      # unsafe boundary, IOCTL contracts, shared with user-mode
│   ├── offgrd-collectors/      # ETW/WMI/registry/net/fs collectors → normalized Event
│   ├── offgrd-core/            # event bus, correlation engine, storage
│   ├── offgrd-rules/           # rule engine + Sigma-subset parser
│   ├── offgrd-plugins/         # WASM plugin host + SDK types
│   ├── offgrd-api/             # local REST/OpenAPI server
│   ├── offgrd-cli/             # command-line client
│   └── offgrd-common/          # shared types, Event schema, error types
├── gui/
│   └── offgrd-gui/             # Tauri + React or egui frontend
├── docs/
│   ├── architecture/
│   ├── rfcs/
│   ├── sdk/
│   └── user-guide/
├── rules/                      # bundled detection rules (YAML)
├── geoip-db/                   # offline GeoIP data + update tooling
├── .github/
│   ├── workflows/              # ci.yml, release.yml, nightly.yml, codeql.yml, sbom.yml
│   ├── ISSUE_TEMPLATE/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── CODEOWNERS
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── GOVERNANCE.md
├── ROADMAP.md
├── CHANGELOG.md (conventional commits → auto-generated)
└── LICENSE (GPLv3)
```

---

## 6. Core Event Schema (illustrative)

```rust
// offgrd-common/src/event.rs
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Event {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,        // Etw, Wmi, Minifilter, Registry, Synthetic
    pub category: EventCategory,    // Process, Network, Registry, File, Dns, ...
    pub process: Option<ProcessRef>,// pid, image path, hash, signer, integrity level
    pub payload: EventPayload,      // enum, one variant per category
    pub severity_hint: Option<Severity>,
    pub tags: Vec<String>,
}
```

All collectors normalize into this envelope so the correlation engine, storage, and rule engine never need source-specific logic — new collectors are additive, not invasive.

---

## 7. Rule Engine

- Rule format: YAML, deliberately close to **Sigma** so the community's existing detection-rule corpus is portable with a converter tool (`offgrd-cli rules import-sigma`).
- Two evaluation modes:
  1. **Stateless** — single-event pattern match (field equals/regex/in-list).
  2. **Stateful/graph** — sliding-window sequence match over the process graph (the "Word → PowerShell → network → injection" chain example), expressed as an ordered list of stateless rules joined by `causal_edge` constraints (`spawned_by`, `injected_by`, `same_process_within(Xs)`).
- Rules carry `severity`, `mitre_attack_id` (ATT&CK mapping), `references`, and `false_positive_notes` — mirroring Sigma metadata conventions for interoperability.

---

## 8. Security & Supply Chain

- `cargo-deny` + `cargo-audit` in CI on every PR.
- SBOM (CycloneDX) generated per release via `cargo-sbom`.
- Reproducible builds: pinned toolchain (`rust-toolchain.toml`), `Cargo.lock` committed, `cargo vendor` for release builds, build provenance via SLSA-style attestation in GitHub Actions.
- Driver and installer signing via EV cert + Windows Hardware Dev Center attestation signing (Sysmon's model).
- Fuzzing: `cargo-fuzz` targets for every parser touching untrusted input (ETW payload parsing, PE header parsing, rule YAML parsing).
- `SECURITY.md` with coordinated disclosure policy and PGP contact.

---

## 9. Plugin SDK (sketch)

- Plugins are **WASM modules** (via `wasmtime`), sandboxed, capability-scoped (a plugin declares which event categories and API endpoints it needs; host enforces it).
- SDK crate (`offgrd-plugin-sdk`) exposes a stable `trait Plugin { fn on_event(&mut self, ev: &Event) -> Vec<Alert>; }` plus a manifest (`plugin.toml`) with semver-checked API compatibility.
- Signed plugin manifests (detached sig) checked by the Plugin Manager before load; unsigned plugins load only with an explicit `--allow-unsigned-plugins` flag and a UI warning banner.

---

## 10. Testing & CI/CD

- Unit tests per crate; integration tests spin up a test VM snapshot (via `packer` + Hyper-V) for driver/collector tests since these need a real Windows kernel.
- UI tests via Tauri's webdriver support.
- CI: `ci.yml` (fmt, clippy -D warnings, test, deny, audit) on every PR; `nightly.yml` builds signed nightly installers; `release.yml` on tag push builds, signs, generates SBOM, publishes to GitHub Releases with checksums + Sigstore/cosign attestation.
- Semantic versioning; Conventional Commits enforced via commit-lint bot; CHANGELOG auto-generated.

---

## 11. Governance & Community Scaffolding

- BDFL-lite for v1 (founding maintainer + 2–3 core reviewers), transitioning to a technical steering committee once there are ~5 regular external contributors — mirrors the path OpenSnitch and Zeek took.
- `CODEOWNERS` maps `crates/offgrd-driver/*` to a smaller, higher-trust reviewer set than `gui/*` or `rules/*`, since kernel code has outsized blast radius.
- RFC process (`docs/rfcs/NNNN-title.md`) required for: new kernel-mode capabilities, storage schema changes, plugin API changes.

---

## 12. Suggested Phased Roadmap

| Phase | Duration (indicative) | Deliverable |
|---|---|---|
| 0 — Foundation | 4–6 wks | Repo scaffolding, CI, Event schema, IPC contract, driver skeleton that just loads/unloads safely |
| 1 — MVP | 3–4 mo | Tier 1 modules, basic timeline UI, CLI, SQLite storage |
| 2 — Detection depth | 3–4 mo | Rule engine + Sigma import, correlation engine, Tier 2 modules |
| 3 — Advanced/Ecosystem | ongoing | Tier 3 detectors, Plugin SDK, REST API, plugin marketplace, i18n, ARM64 |
| 3+ | ongoing | WHQL driver certification, third-party security audit, CVE program |

---

## Next steps I can help with directly

Pick any single piece and I'll build it out in real, runnable code rather than spec form — for example:
- The `Event` schema + a working ETW collector for process-creation events
- The Tauri GUI shell with a live process tree
- The Sigma-subset rule parser
- The GitHub Actions CI pipeline and issue/PR templates

Which one do you want to start with?
