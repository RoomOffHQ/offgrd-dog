# Contributing to OffGrd Dog

Thanks for considering contributing. This project follows the same
principle as the software itself: **be transparent about what's
verified vs. experimental.**

## Before you start

Read `WIP.md` — it tells you exactly what's solid, what's in progress,
and what's explicitly deferred (and why). Please don't build on top of
something marked experimental without flagging that your PR depends on
an unverified piece.

## Development setup

```powershell
git clone <this repo>
cd offgrd-dog
cargo build --workspace
cargo test --workspace
```

Requires an MSVC toolchain (for `rusqlite`'s `bundled` feature and the
`windows` crate) — the same Visual Studio Build Tools most native
Rust-on-Windows projects need.

## Code standards

- `cargo fmt --all` before committing.
- `cargo clippy --workspace --all-targets -- -D warnings` must pass.
- `#![forbid(unsafe_code)]` at the crate root everywhere except code
  that genuinely needs to call raw Win32/ETW APIs
  (`crates/offgrd-cli/src/platform/windows.rs`,
  `crates/offgrd-cli/src/etw_collector.rs` currently). Every `unsafe`
  block needs a `// SAFETY:` comment explaining specifically why it's
  sound — not just "this is safe because X" restated, but the actual
  invariant being relied on (buffer size, handle validity, lifetime).
- New dependencies need a reason in the PR description. This project
  intentionally keeps its dependency tree small and auditable.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`. Used to
auto-generate the changelog.

## Adding a detection rule

Rules live in `rules/*.yaml`. See `crates/offgrd-rules/src/rule.rs`
for the schema and `rules/powershell-execution.yaml` for a commented
example. Use the "New detection rule" issue template if you want
feedback before writing the YAML.

## Adding a collector

Every collector implements `offgrd_core::Collector`
(`fn name()`, `async fn run(&self, bus: &EventBus)`). Look at
`ProcessSnapshotCollector` (`crates/offgrd-cli/src/collector.rs`) for
the reference "one-shot" pattern, or `EtwProcessCollector`
(`crates/offgrd-cli/src/etw_collector.rs`) for the "long-running,
background thread" pattern — though flag in your PR if you're copying
the latter, since it's not yet verified to compile/work correctly
itself.

## Reporting security issues

Do not open a public issue for a security vulnerability — see
`SECURITY.md`.
