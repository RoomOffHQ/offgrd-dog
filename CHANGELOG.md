# Changelog

All notable changes to this project are documented here. Format
loosely follows [Keep a Changelog](https://keepachangelog.com/), and
entries are meant to be generatable from
[Conventional Commits](https://www.conventionalcommits.org/) history
once there's real commit history to generate from (see
`CONTRIBUTING.md`) — this initial entry was written by hand since the
project doesn't have a commit history yet.

## [Unreleased]

### Added
- Initial workspace scaffolding: `offgrd-common`, `offgrd-core`,
  `offgrd-rules`, `offgrd-collectors`, `offgrd-cli`.
- `offgrd-cli`: `ps`, `history`, `watch` (ETW, experimental/unverified),
  `monitor` (polling-based, no ETW needed), `alerts`, `alert-history`,
  `rules-check`.
- SQLite-backed event and alert storage (`offgrd-core::EventStore`).
- YAML-based detection rule engine (`offgrd-rules`) with bundled
  example rules.
- Desktop GUI (`gui/offgrd-gui`, Tauri): dashboard, processes (table +
  tree view), alerts, rules views; live updates via a background
  polling monitor; JSON/CSV export.
- CI (`.github/workflows/ci.yml`, `nightly.yml`), issue/PR templates,
  `CODEOWNERS`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`.
- Full architecture document (`docs/offgrd-dog-architecture.md`).

### Known issues
See `WIP.md` for the current, detailed list of what's verified vs.
unverified/experimental at any given point — this changelog tracks
what was *added*, not what's *confirmed working*, until the project
has its first tagged release.

[Unreleased]: https://github.com/offgrd-dog/offgrd-dog/commits/main
