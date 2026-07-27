# 20 Additional Surveillance Features — Ranked by "Wow", Implementation Status

Brainstormed per your request, ranked roughly by visual/security impact
("wow factor") tempered by implementation risk. **13 of 20 are now
implemented** (7 in the first pass, 6 more in a second pass covering
everything that didn't need COM/WMI/a new complex API family). The
remaining 7 (Scheduled Tasks, TPM/BitLocker, Event Log, WiFi, USB live,
browser extensions, Bluetooth) genuinely need either COM interop or a
new API family each and are queued for their own dedicated passes
rather than being rushed in alongside everything else.

| # | Feature | Wow | Status | Why / API |
|---|---|---|---|---|
| 1 | **Loaded DLLs per process** | ★★★★★ | ✅ Implemented | Injection/hijacking detection precursor — reuses the exact Toolhelp32 pattern already in the project (`Module32First`/`Module32Next`), so it's low-risk despite being high-value. |
| 2 | **RDP / Remote Desktop sessions** | ★★★★★ | ✅ Implemented | "Is someone else logged into my machine right now" is viscerally alarming to see — `WTSEnumerateSessionsW`, a small, well-documented API. |
| 3 | **Hosts file tampering monitor** | ★★★★★ | ✅ Implemented | Classic, very real malware technique (redirect `windowsupdate.com` to localhost); trivial to read/parse, huge "trust nothing" narrative payoff. |
| 4 | **Startup folder monitor** | ★★★★☆ | ✅ Implemented | Completes the Autoruns picture (registry Run keys were already covered) — a shortcut quietly dropped in `shell:startup` is a common persistence technique the registry-only view misses entirely. |
| 5 | **Named pipes enumeration** | ★★★★☆ | ✅ Implemented | `\\.\pipe\*` — reveals IPC channels, some services/malware use recognizably-named pipes; simple `FindFirstFileW`/`FindNextFileW` walk. |
| 6 | **Installed programs (Add/Remove Programs)** | ★★★☆☆ | ✅ Implemented | Less flashy but genuinely useful baseline inventory — registry `Uninstall` keys, same pattern as Autoruns. |
| 7 | **Clipboard snapshot** | ★★★★☆ | ✅ Implemented | Immediately relatable ("wait, it can see my clipboard?!") — `GetClipboardData`/`OpenClipboard`, text formats only for this pass. |
| 8 | Scheduled Tasks Monitor | ★★★★★ | 🔜 Queued | Huge persistence-monitor value (architecture doc's own module), but needs COM (`ITaskService`/`ITaskFolder`) — real interop complexity, deserves its own pass. |
| 9 | TPM / Secure Boot / BitLocker status | ★★★★☆ | 🔜 Queued | Straight from the architecture doc's System Integrity section; needs WMI (`Win32_Tpm`, `Win32_EncryptableVolume`) — COM-based, non-trivial. |
| 10 | Windows Event Log tail (Security channel) | ★★★★★ | 🔜 Queued | Extremely high value (logon events, privilege use) but the `EvtQuery`/`EvtNext` API is a bigger lift than anything implemented so far. |
| 11 | WiFi networks (visible + connected SSIDs) | ★★★★☆ | 🔜 Queued | Very visual/relatable, needs the WLAN API (`WlanOpenHandle`/`WlanGetNetworkBssList`) — a new API family. |
| 12 | USB device insertion/removal (live) | ★★★★☆ | 🔜 Queued | Needs either `WM_DEVICECHANGE` window-message plumbing or SetupAPI device notifications — a different collector shape (event-driven, not snapshot-poll). |
| 13 | Local user accounts & groups | ★★★☆☆ | ✅ Implemented | `NetUserEnum`/`NetLocalGroupEnum` — moderate new API surface, good security value (hidden accounts, group membership changes). |
| 14 | Browser extensions inspector | ★★★☆☆ | 🔜 Queued | High privacy relevance, but needs per-browser JSON/SQLite parsing (Chrome/Edge/Firefox each differ) — more parsing work than API work. |
| 15 | Network shares (`NetShareEnum`) | ★★★☆☆ | ✅ Implemented | Reveals unexpected file sharing; moderate new API. |
| 16 | Foreground/active window tracker | ★★★☆☆ | ✅ Implemented | Simple API (`GetForegroundWindow`) but raises "is this basically a keylogger-adjacent feature" UX/ethics questions worth thinking through in the design, not just the code. |
| 17 | Environment variables inspector (PATH hijacking) | ★★☆☆☆ | ✅ Implemented | Easy (`GetEnvironmentStringsW`) but narrower attack surface than most items above. |
| 18 | DNS cache viewer | ★★★☆☆ | ✅ Implemented | The real API (`DnsGetCacheDataTable`) is undocumented/fragile; pragmatic fallback is shelling out to `ipconfig /displaydns` and parsing text — noted as a deliberate compromise if implemented. |
| 19 | Bluetooth paired/nearby devices | ★★☆☆☆ | 🔜 Queued | Real but niche; Windows Bluetooth API is more involved than WiFi's. |
| 20 | Idle time / screen lock state | ★★☆☆☆ | ✅ Implemented | `GetLastInputInfo` — trivial API, lowest security relevance of the 20. |

See `docs/collectors.md` for the same "how to add a collector" checklist
these 7 new ones followed, and `WIP.md` for the usual honesty caveats
about what's verified vs. not.
