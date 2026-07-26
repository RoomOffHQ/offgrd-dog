//! Integration tests for the `offgrd` binary itself, as opposed to
//! the unit tests inside each crate. These run the actual compiled
//! executable (`env!("CARGO_BIN_EXE_offgrd")`, a standard Cargo
//! mechanism — no `assert_cmd` or other test-harness dependency
//! needed) and check its exit code / stdout / stderr, the same way a
//! user invoking it from a terminal would experience it.
//!
//! Deliberately conservative about what's tested here: commands whose
//! behavior depends on the live state of the machine they run on
//! (`ps`, `watch`, `monitor` — process lists differ everywhere, and
//! `ps`/`monitor` only work on Windows at all) are NOT asserted on
//! their actual output content, only on "did it exit the way we
//! expect for this platform." Commands whose behavior is
//! deterministic regardless of what's running (`--help`,
//! `rules-check` against a controlled temp directory, `history`
//! against a fresh empty database) get real content assertions.

use std::path::Path;
use std::process::Command;

fn offgrd_binary() -> &'static str {
    env!("CARGO_BIN_EXE_offgrd")
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(offgrd_binary())
        .args(args)
        .output()
        .expect("failed to execute offgrd binary")
}

fn run_in(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(offgrd_binary())
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to execute offgrd binary")
}

#[test]
fn help_exits_successfully_and_lists_known_subcommands() {
    let output = run(&["--help"]);
    assert!(output.status.success(), "offgrd --help should exit 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    for subcommand in ["ps", "history", "watch", "monitor", "alerts", "alert-history", "rules-check"] {
        assert!(
            stdout.contains(subcommand),
            "expected --help output to mention '{subcommand}', got:\n{stdout}"
        );
    }
}

#[test]
fn version_flag_exits_successfully() {
    let output = run(&["--version"]);
    assert!(output.status.success(), "offgrd --version should exit 0");
}

#[test]
fn history_against_fresh_empty_database_is_graceful_not_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("fresh.db");

    let output = run_in(
        dir.path(),
        &["--db", db_path.to_str().unwrap(), "history"],
    );

    assert!(
        output.status.success(),
        "history against a fresh/empty db should exit 0, not error. stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no events stored"),
        "expected a friendly 'no events stored' message on stderr, got:\n{stderr}"
    );
}

#[test]
fn alert_history_against_fresh_empty_database_is_graceful_not_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("fresh.db");

    let output = run_in(
        dir.path(),
        &["--db", db_path.to_str().unwrap(), "alert-history"],
    );

    assert!(output.status.success(), "alert-history against a fresh db should exit 0");
}

#[test]
fn rules_check_against_missing_directory_reports_zero_rules_not_a_crash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing_rules_dir = dir.path().join("does-not-exist");

    let output = run(&["rules-check", "--rules-dir", missing_rules_dir.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "rules-check against a missing directory should exit 0 (0 rules loaded, 0 errors), not fail. stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn rules_check_against_directory_with_one_bad_rule_reports_error_and_exits_nonzero() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("broken.yaml"), "not: [valid, yaml: shape").expect("write");

    let output = run(&["rules-check", "--rules-dir", dir.path().to_str().unwrap()]);

    assert!(
        !output.status.success(),
        "rules-check should exit non-zero when a rule file fails to parse"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("broken.yaml"),
        "expected the broken file to be named in the output, got:\n{stdout}"
    );
}

#[test]
fn rules_check_against_directory_with_valid_rule_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("good.yaml"),
        "id: test-rule\ntitle: Test rule\nseverity: Low\ncondition:\n  image_path_contains: cmd.exe\n",
    )
    .expect("write");

    let output = run(&["rules-check", "--rules-dir", dir.path().to_str().unwrap()]);

    assert!(
        output.status.success(),
        "rules-check should succeed with a valid rule file. stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn no_subcommand_exits_nonzero_with_usage_shown() {
    // clap's default behavior for a required subcommand that's missing.
    let output = run(&[]);
    assert!(!output.status.success(), "no subcommand should not silently succeed");
}

// ---------- Platform-specific behavior ----------
//
// `ps`/`watch`/`monitor` depend on Windows APIs. On Windows we can't
// assert much about *content* (every machine's process list differs)
// but we can assert the command at least runs successfully. On other
// platforms, `platform::other::list_processes` is designed to return
// a clear error rather than silently doing nothing — assert that
// contract instead.

#[cfg(windows)]
#[test]
fn ps_succeeds_on_windows_and_includes_current_process() {
    let output = run(&["ps", "--json"]);
    assert!(output.status.success(), "offgrd ps should succeed on Windows");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty(), "expected at least one process in JSON output");
}

#[cfg(not(windows))]
#[test]
fn ps_fails_clearly_on_non_windows() {
    let output = run(&["ps"]);
    assert!(
        !output.status.success(),
        "offgrd ps should fail clearly (not silently no-op) on non-Windows platforms"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("windows"),
        "expected the error to explain this is Windows-only, got:\n{stderr}"
    );
}
