# Roadmap

See `WIP.md` for the live, granular "done / in progress / next" status.
This file is the higher-level picture — the phases from
`docs/offgrd-dog-architecture.md`, kept short on purpose.

## Phase 0 — Foundation ✅ (in progress → mostly done, unverified)
Cargo workspace, `Event`/`Alert` schema, `EventBus`, SQLite storage,
CI scaffolding, governance docs.

## Phase 1 — MVP (in progress)
- [x] Process snapshot collector (Win32 Toolhelp32)
- [x] Polling-based continuous monitor (no ETW needed)
- [x] Stateless YAML rule engine + bundled example rules
- [x] Desktop GUI shell (dashboard, processes, alerts, rules) with
      live updates and export
- [ ] ETW-based live process collector (`offgrd watch`) — written,
      **not yet verified to compile**, see `WIP.md`
- [ ] Network Monitor / Socket Explorer
- [ ] DNS Monitor
- [ ] Autoruns / Persistence Monitor
- [ ] Registry Monitor
- [ ] Filesystem Monitor (minifilter)
- [ ] Snapshot & diff (registry, autoruns, services, drivers)

## Phase 2 — Detection depth
- [ ] Stateful/graph correlation engine (multi-event chains — the
      "Word → PowerShell → network → injection" example from the
      architecture doc)
- [ ] Sigma rule import (`offgrd rules import-sigma`)
- [ ] DLL/Driver/Handle/Thread/Memory Explorers
- [ ] USB Monitor, Firewall Inspector, TLS/Certificate Inspector
- [ ] WMI/PowerShell/COM/RPC/Named-pipe monitors
- [ ] Clipboard Monitor, Camera/Mic/Screen-capture-handle detection

## Phase 3 — Advanced / ecosystem
- [ ] Injection-technique detectors (reflective DLL, process
      hollowing, APC, thread hijack, manual map)
- [ ] Kernel callback/SSDT integrity checks, ETW-tampering detection
- [ ] Plugin SDK (WASM-sandboxed)
- [ ] REST/OpenAPI local API
- [ ] Encrypted forensic export
- [ ] Bluetooth/WiFi monitors, GPU activity
- [ ] Kernel-mode driver (minifilter + ETW kernel session consumer),
      WHQL certification path
- [ ] Third-party security audit, CVE program

## Not on the roadmap (by design)

OffGrd Dog is an observability tool, not an antivirus. It will never:
- Block, quarantine, or auto-remediate anything
- Phone home, collect telemetry, or require a cloud account
- Make decisions on the user's behalf without surfacing the facts first
